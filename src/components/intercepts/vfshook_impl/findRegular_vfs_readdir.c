/*
 * findRegular_vfs_readdir.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2019 Sophos Limited, Oxford, England.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License Version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if not,
 * write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <linux/kernel.h>
#include <linux/version.h>

#ifdef TALPA_VFSREADDIR

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unistd.h>

#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
#include <linux/syscalls.h>
#endif
#include <linux/namei.h>
#include <linux/moduleparam.h>
#endif
#ifdef TALPA_HAS_SMBFS
#include <linux/smb_fs.h>
#endif

#ifdef TALPA_HOOK_D_OPS
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#include <linux/uaccess.h>
# endif
#endif

#include "platforms/linux/alloc.h"
#include "platforms/linux/glue.h"
#include "platforms/linux/vfs_mount.h"
#include "platforms/linux/locking.h"
#include "platforms/linux/log.h"
#include "platforms/linux/list.h"

#include "findRegular.h"
#include "getPath.h"

#ifdef TALPA_SCAN_ON_MOUNT

#ifndef LOOKUP_NO_AUTOMOUNT
# define LOOKUP_NO_AUTOMOUNT 0
#endif

/* Structure which holds info on one entry as we scan the directory tree */
struct dentryContext
{
    struct file*    dir;
    char*           dirent;
    size_t          bufsize;
    bool            overflow;
    bool            fill;
    bool            skip;
    char*           root;
    size_t          rootsize;
    unsigned int    rootlen;
};


/* Callback we supply to vfs_readdir in order to get dentry info */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19) || defined TALPA_HAS_BACKPORTED_FILLDIR
static int fillDentry(void * __buf, const char * name, int namlen, loff_t offset, u64 ino, unsigned int d_type)
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,4,8)
static int fillDentry(void * __buf, const char * name, int namlen, loff_t offset, ino_t ino, unsigned int d_type)
#else
static int fillDentry(void * __buf, const char * name, int namlen, off_t offset, ino_t ino, unsigned int d_type)
#endif
{
    struct dentryContext *dc = (struct dentryContext *)__buf;


    /* Skip current and parent directory inodes.
       Also skip zero-length names which smbfs can provide in some cases. */
    if ( (namlen == 0) || (name == NULL) || (*name == 0) ||
        ((namlen == 1) && !strncmp(name, ".", 1)) ||
        ((namlen == 2) && !strncmp(name, "..", 2)) )
    {
        return 0;
    }
    /* Skip this dentry if requested so */
    else if ( dc->skip )
    {
        dc->skip = false;
        return 0;
    }

    /* Check if we have enough space in dirent to copy the whole path in */
    if ( dc->bufsize < (strlen(dc->root) + 1 + namlen + 1) )
    {
        dc->overflow = true;
        dbg("pathname too long, skipping");
        return 0;
    }

    /* We have a potentially interesting dentry */
    dc->fill = true;

    strcpy(dc->dirent, dc->root);
    if ( dc->root[dc->rootlen - 1] != '/' )
    {
        strcat(dc->dirent, "/");
    }
    strncat(dc->dirent, name, namlen);

    return -EBFONT;
}

static void stripLastPathElement(char* path)
{
    char* p;


    /* Position ourselves at the last character */
    p = path + strlen(path) - 1;

    /* Skip trailing slash */
    if ( (*p != '/') && (p > path) )
        *p-- = 0;

    /* Find previous slash */
    while ( (*p != '/') && (p > path) )
        p--;

    /* Null terminate at the slash, or at one after if this is a root directory */
    if ( p > path )
    {
        *p = 0;
    }
    else
    {
        *++p = 0;
    }
}

struct openDirectory
{
    talpa_list_head head;
    unsigned int    level;
    char*           name;
    struct file*    dir;
};

struct directories
{
    talpa_list_head list;
    unsigned int    dmax;
    unsigned int    cmax;
    unsigned int    count;
};

static void initDirectories(struct directories* dirs)
{
    TALPA_INIT_LIST_HEAD(&dirs->list);
    dirs->dmax = 0;
    dirs->cmax = 0;
    dirs->count = 0;
}

static char* namedup(char *name)
{
    char *tmp;
    size_t len = strlen(name) + 1;


    tmp = talpa_alloc(len);
    if ( tmp )
    {
        memcpy(tmp, name, len);
    }

    return tmp;
}

static void purgeDirectories(struct directories* dirs, unsigned int depth)
{
    struct openDirectory* tmp;
    struct openDirectory* dir = NULL;


    talpa_list_for_each_entry_safe(dir, tmp, &dirs->list, head)
    {
        if ( dir->level == depth )
        {
            --dirs->count;
            talpa_list_del(&dir->head);
            dbg("deleting handle for %s at %u", dir->name, dir->level);
            filp_close(dir->dir, current->files);
            talpa_free(dir->name);
            talpa_free(dir);
        }
    }
}

static void cleanupDirectories(struct directories* dirs)
{
    struct openDirectory* tmp;
    struct openDirectory* dir = NULL;


    dbg("max depth was %u and max count %u", dirs->dmax, dirs->cmax);

    talpa_list_for_each_entry_safe(dir, tmp, &dirs->list, head)
    {
        talpa_list_del(&dir->head);
        dbg("deleting handle for %s at %u", dir->name, dir->level);
        filp_close(dir->dir, current->files);
        talpa_free(dir->name);
        talpa_free(dir);
    }
}

static struct file* openDirectory(struct directories* dirs, unsigned int depth, char* name, bool* newdir)
{
    struct openDirectory* tmp;
    struct openDirectory* dir = NULL;
    int ret = -ENOMEM;


    talpa_list_for_each_entry(tmp, &dirs->list, head)
    {
        if ( (tmp->level == depth) && !strcmp(tmp->name, name) )
        {
            dir = tmp;
            break;
        }

    }

    if ( dir )
    {
        dbg("found open handle for %s at %u", dir->name, dir->level);
        *newdir = false;
        return dir->dir;
    }
    else
    {
        dir = talpa_alloc(sizeof(struct openDirectory));

        if ( dir )
        {
            dir->level = depth;
            dir->name = namedup(name);
            if ( dir->name )
            {
                dir->dir = filp_open(dir->name, O_RDONLY | O_DIRECTORY, 0);
                if ( !IS_ERR(dir->dir) )
                {
                    if ( dir->level > dirs->dmax )
                    {
                        dirs->dmax = dir->level;
                    }
                    dirs->count++;
                    if ( dirs->count > dirs->cmax )
                    {
                        dirs->cmax = dirs->count;
                    }
                    *newdir = true;
                    purgeDirectories(dirs, depth);
                    talpa_list_add(&dir->head, &dirs->list);
                    dbg("added handle for %s at %u", dir->name, dir->level);

                    return dir->dir;
                }
                else
                {
                    ret = PTR_ERR(dir->dir);
                    dbg("open directory for %s failed (%d)", dir->name, ret);
                }
                talpa_free(dir->name);
            }
            talpa_free(dir);
        }
    }

    return ERR_PTR(ret);
}

static struct dentry *scanDirectory(const char* dirname, char* rootbuf, size_t rootsize, char* buf, size_t bufsize, bool* overflow)
{
    struct dentry *reg = NULL;
    struct dentryContext* dc;
#ifdef TALPA_HAVE_PATH_LOOKUP
    struct nameidata nd;
#else
    struct path p;
#endif
    int err;
    bool newdir = false;
    struct directories dirs;
    unsigned int depth = 0;
    struct vfsmount *mnt;
    struct dentry *dentry;


    initDirectories(&dirs);
    /* Allocate structures and memory */
    dc = talpa_alloc(sizeof(struct dentryContext));

    if ( !dc )
    {
        goto out;
    }

    dc->rootsize = rootsize;
    dc->root = rootbuf;
    dc->bufsize = bufsize;
    dc->dirent = buf;

    dc->rootlen = strlen(dirname);
    if ( dc->rootlen >= dc->rootsize )
    {
        dbg("dirname of length %u longer than root buffer of size %lu", dc->rootlen, (long unsigned int)dc->rootsize);
        *overflow = true;
        goto out;
    }
    strcpy(dc->root, dirname);

    dbg("root at %s, max path %lu bytes", dc->root, (long unsigned int)dc->bufsize);
rescan:
    dc->dir = openDirectory(&dirs, depth, dc->root, &newdir);

    /* Back-out if we failed to open, abort if we are at given root */
    if ( IS_ERR(dc->dir) )
    {
        if ( !strcmp(dirname, dc->root) )
        {
            dbg("backed out to root (err %ld)", PTR_ERR(dc->dir));
            goto out;
        }

        stripLastPathElement(dc->root);
        purgeDirectories(&dirs, depth);
        --depth;
        dbg("backing out to %s (%ld) [%u]", dc->root, PTR_ERR(dc->dir), depth);
        dc->rootlen = strlen(dc->root);
        goto rescan;
    }

    dc->skip = false;

    do
    {
        /* Fill flag will be set in fillDentry if an
           interesting dentry is found. */
        dc->fill = false;
        /* Overflow signals that the dirent buffer was
           to small for at least one path in this scan. */
        dc->overflow = false;
        /* Skip first entry if we are continuing to
           read an open directory.  */
        if ( !newdir )
        {
            dc->skip = true;
        }
        err = vfs_readdir(dc->dir, fillDentry, dc);
        newdir = false;
        *overflow |= dc->overflow;

        /* Back-out if at end-of-directory or if error occured */
        if ( ((err < 0) && (err != -EBFONT)) || !dc->fill )
        {
            if ( !strcmp(dirname, dc->root) )
            {
                dbg("eod");
                goto out;
            }

            stripLastPathElement(dc->root);
            purgeDirectories(&dirs, depth);
            --depth;
            dbg("backing out to %s (%d)", dc->root, err);
            dc->rootlen = strlen(dc->root);
            goto rescan;
        }

        /* Try to lookup it... */
#ifdef TALPA_HAVE_PATH_LOOKUP
        err = talpa_path_lookup(dc->dirent, 0, &nd);
#else
        dbg("kern_path on %s", dc->dirent);
        err = kern_path(dc->dirent, LOOKUP_NO_AUTOMOUNT, &p);
#endif

        if ( err == 0 )
        {
#ifdef TALPA_HAVE_PATH_LOOKUP
            mnt = talpa_nd_mnt(&nd);
            dentry = talpa_nd_dentry(&nd);
#else
            mnt = p.mnt;
            dentry = p.dentry;
#endif

            /* If dentry resolves to regular file we're done! */
            if ( S_ISREG(dentry->d_inode->i_mode) )
            {
                dbg("regular %s", dc->dirent);
                reg = dget(dentry);
            }
            /* If it is a directory and not a root of a mounted filesystem, enter into it.
               But only if we have enough space in the buffer to copy that path. */
            else if ( S_ISDIR(dentry->d_inode->i_mode) && (dentry != mnt->mnt_root) && (dc->rootsize > strlen(dc->dirent)) )
            {
                dbg("entering %s", dc->dirent);
                depth++;
#ifdef TALPA_HAVE_PATH_LOOKUP
                talpa_path_release(&nd);
#else
                path_put(&p);
#endif
                strcpy(dc->root, dc->dirent);
                dc->rootlen = strlen(dc->root);
                goto rescan;
            }
            else
            {
                dbg("  skipping %s", dc->dirent);
            }
            /* Can release the path, as we have done dget, if we want to keep it */
#ifdef TALPA_HAVE_PATH_LOOKUP
            talpa_path_release(&nd);
#else
            path_put(&p);
#endif
        }
    } while ( !reg ); /* !reg = search finished, we have a regular file */

out:
    talpa_free(dc);
    cleanupDirectories(&dirs);

    return reg;
}


/* Find a regular file on a given vfsmount. dgets it's dentry. */
struct dentry *findRegular(struct vfsmount* root)
{
    struct dentry *reg = NULL;
    struct dentry *droot;
    struct vfsmount *mntroot;
    char *path, *name;
    size_t path_size = 0;
    bool overflow;
    char *rootbuf = NULL;
    char *buf = NULL;
    size_t root_size = 0;
    unsigned int dir_order;
    unsigned int mnt_order;


    /* Allocate storage and build mount point path */
    droot = dget(root->mnt_root);
    mntroot = mntget(root);

    name = getPath(root, &path, &mnt_order, &root_size);
    if ( IS_ERR(name) )
    {
        goto exit1;
    }

    /* Now scan the mount point path */
    for (dir_order = mnt_order; dir_order <= TALPA_MAX_ORDER; dir_order++)
    {
        rootbuf = talpa_alloc_path_order(dir_order, &root_size);
        buf = talpa_alloc_path_order(dir_order, &path_size);
        if ( !rootbuf || !buf )
        {
            dbg("failed to allocate order %u", dir_order);
            break;
        }
        overflow = false;
        reg = scanDirectory(name, rootbuf, root_size, buf, path_size, &overflow);
        if ( !reg && overflow )
        {
            /* Try with a larger buffer */
            dbg("order %u is insufficient", dir_order);
            talpa_free_path_order(rootbuf, dir_order);
            rootbuf = NULL;
            talpa_free_path_order(buf, dir_order);
            buf = NULL;
            continue;
        }
        if (reg)
        {
            dbg("found regular dentry 0x%p", reg);
        }
        break;
    }

    talpa_free_path_order(rootbuf, dir_order);
    talpa_free_path_order(buf, dir_order);
    talpa_free_path_order(path, mnt_order);
exit1:
    mntput(mntroot);
    dput(droot);

    return reg;
}
#endif /* TALPA_SCAN_ON_MOUNT */

#endif /* TALPA_VFSREADDIR */
