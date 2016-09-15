/*
 * findRegular_iterate_dir.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2016 Sophos Limited, Oxford, England.
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)

#include "findRegular.h"

#ifdef TALPA_SCAN_ON_MOUNT

#define __NO_VERSION__
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/sched.h>

#include "platforms/linux/alloc.h"
#include "platforms/linux/log.h"
#include "platforms/linux/glue.h"

#include "getPath.h"

#ifndef LOOKUP_NO_AUTOMOUNT
# define LOOKUP_NO_AUTOMOUNT 0
#endif

#define DEBUG_err dbg

struct TalpaFindRegularContext
{
    struct TalpaFindRegularContext* parent;
    struct file* dir;
    char * dirname;
    u64 ino;
    size_t bufsize; /* length of dirname buffer */
    int dirlength; /* Length of the directory we are iterating */
    unsigned int d_type;
    int count;
    int skip;
    bool* overflow;
    bool fill;
};

struct IterateCallback
{
    struct dir_context ctx; /* Must be first, so that cast works below */
    struct TalpaFindRegularContext* talpaContext;
};

static int appendBasename(struct TalpaFindRegularContext* buf, const char * name, int namlen)
{
    int parentlen = buf->dirlength;

    if ( buf->dirname[parentlen - 1] != '/' )
    {
        if (parentlen == buf->bufsize)
        {
            *(buf->overflow) = true;
            return -EOVERFLOW;
        }

        strcat(buf->dirname+parentlen, "/");
        parentlen += 1;
    }

    if (parentlen + namlen > buf->bufsize)
    {
        *(buf->overflow) = true;
        return -EOVERFLOW;
    }

    strncat(buf->dirname+parentlen,name,namlen);
    buf->dirname[parentlen+namlen] = 0;
    return 0;
}

/* Callback we supply to vfs_readdir in order to get dentry info */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
static int fillonedir(struct dir_context * __buf, const char * name, int namlen, loff_t offset,
            u64 ino, unsigned int d_type)
#else
static int fillonedir(void * __buf, const char * name, int namlen, loff_t offset,
            u64 ino, unsigned int d_type)
#endif
{
    struct IterateCallback *ctx = (struct IterateCallback *) __buf;
    struct TalpaFindRegularContext* buf = ctx->talpaContext;
    int error;

/*
    err("fillonedir name=%s namlen=%d, offset=%ld, ino=%ld, d_type=%d, count=%d, skip=%d",
        name,namlen, offset, ino, d_type,buf->count, buf->skip);
        */

    /* Skip current and parent directory inodes.
       Also skip zero-length names which smbfs can provide in some cases. */
    if ( (namlen == 0) || (name == NULL) || (*name == 0) ||
        ((namlen == 1) && !strncmp(name, ".", 1)) ||
        ((namlen == 2) && !strncmp(name, "..", 2)) )
    {
        return 0;
    }

    if (d_type != DT_DIR && d_type != DT_REG)
    {
        /* Skip non-file non-directory items */
        return 0;
    }

    if (buf->count < buf->skip)
    {
        buf->count += 1;
        return 0;
    }

    error = appendBasename(buf, name, namlen);
    if (error == -EOVERFLOW)
    {
        return 0;
    }

    buf->fill = true;
    buf->ino = ino;
    buf->d_type = d_type;
    return -EBFONT;
}

/**
 * Open a directory.
 *
 * NB: The basename has already been appended to parent->dirname (shared buffer)
 */
static struct TalpaFindRegularContext* openDirectory(struct TalpaFindRegularContext* parent)
{
    struct TalpaFindRegularContext* dir = NULL;
    struct file* dirFilp;


    dirFilp = filp_open(parent->dirname, O_RDONLY | O_DIRECTORY, 0);
    if ( IS_ERR(dirFilp) )
    {
        err("Failed to open directory: %ld",PTR_ERR(dirFilp));
        return (struct TalpaFindRegularContext*)dirFilp; /* Error */
    }

    if (kdev_t_to_nr(inode_dev(dirFilp->f_dentry->d_inode)) !=
        kdev_t_to_nr(inode_dev(parent->dir->f_dentry->d_inode)))
    {
        /* Changed devices
        DEBUG_err("openDirectory dev=%d != parent %d for %s - not on same filesystem",
            kdev_t_to_nr(inode_dev(dirFilp->f_dentry->d_inode)),
            kdev_t_to_nr(inode_dev(parent->dir->f_dentry->d_inode)),
            parent->dirname);
            */

        filp_close(dirFilp, current->files);
        return parent;
    }

    dir = talpa_alloc(sizeof(struct TalpaFindRegularContext));
    if (dir)
    {
        dir->parent = parent;
        dir->dirname = parent->dirname;
        dir->dirlength = strlen(dir->dirname);
        dir->bufsize = parent->bufsize;
        dir->dir = dirFilp;
        dir->skip = 0;
        dir->d_type = DT_UNKNOWN;
        dir->overflow = parent->overflow;
    }
    else
    {
        filp_close(dirFilp, current->files);
    }

    return dir;
}

static struct TalpaFindRegularContext* initialOpenDirectory(const char* dirname, bool* overflow, char* buf, size_t bufsize)
{
    struct TalpaFindRegularContext* dir;
    struct file* dirFilp;


    dirFilp = filp_open(dirname, O_RDONLY | O_DIRECTORY, 0);
    if ( IS_ERR(dirFilp) )
    {
        err("Failed to open initial directory: %ld",PTR_ERR(dirFilp));
        return (struct TalpaFindRegularContext*)dirFilp; /* Error */
    }

    dir = talpa_alloc(sizeof(struct TalpaFindRegularContext));
    if (dir)
    {
        buf[0] = 0;
        strncpy(buf, dirname, bufsize);

        dir->parent = NULL;
        dir->dirname = buf;
        dir->dirlength = strlen(buf);
        dir->bufsize = bufsize;
        dir->dir = dirFilp;
        dir->skip = 0;
        dir->d_type = DT_UNKNOWN;
        dir->overflow = overflow;
    }
    else
    {
        filp_close(dirFilp, current->files);
    }

    return dir;
}

static struct TalpaFindRegularContext* closeDirAndReturnParent(struct TalpaFindRegularContext* ctx)
{
    struct TalpaFindRegularContext* parent;


    if (ctx == NULL)
    {
        return NULL;
    }
    parent = ctx->parent;

    filp_close(ctx->dir, current->files);
    talpa_free(ctx);

    return parent;
}

static void closeAllDirectories(struct TalpaFindRegularContext* ctx)
{
    struct TalpaFindRegularContext* parent = ctx;

    while (parent != NULL)
    {
        parent = closeDirAndReturnParent(parent);
    }
}

static struct dentry *scanDirectory(const char* dirname, char* buf, size_t bufsize, bool* overflow)
{
    struct TalpaFindRegularContext *context;
    int error;
    struct IterateCallback ctx = {
        .ctx.actor = fillonedir
    };

    context = initialOpenDirectory(dirname, overflow, buf, bufsize);
    if (IS_ERR(context))
    {
        err("Failed to open initial directory %s: %ld",dirname,PTR_ERR(context));
        return NULL;
    }

    while (true)
    {
        ctx.talpaContext = context;
        context->fill = false;
        context->count = 0;
        context->dirname[context->dirlength] = 0;

        error = iterate_dir(context->dir, &(ctx.ctx));
        if (error != 0 && error != -EBFONT)
        {
            err("iterate_dir produced error %d while iterating directory %s",error,dirname);
            context = closeDirAndReturnParent(context);
            if (context == NULL)
            {
                return NULL; /* no file found */
            }
        }
        else if (!context->fill)
        {
            context = closeDirAndReturnParent(context);
            if (context == NULL)
            {
                dbg("Found no files on this filesystem");
                return NULL; /* no file found */
            }
        }
        else if (context->d_type == DT_DIR)
        {
            struct TalpaFindRegularContext *parent = context;

            context = openDirectory(parent);
            if (IS_ERR(context))
            {
                dbg("Failed to open directory: %ld",PTR_ERR(context));
                closeAllDirectories(parent);
                return NULL;
            }
            else if (context == parent)
            {
                dbg("Failed to open directory overflow=%d",*overflow);
            }
            parent->skip += 1;
        }
        else if (context->d_type == DT_REG)
        {
            struct path p;
            /* Get dentry from file path - already appended to buf */
            error = kern_path(buf, LOOKUP_NO_AUTOMOUNT, &p);

            if (error == 0)
            {
                struct dentry* reg = dget(p.dentry);

                path_put(&p);

                closeAllDirectories(context);
                return reg;
            }
            err("Failed to kern_path for regular file %d",error);
            context->skip += 1;
        }
        else
        {
            err("skipping other entry %s",buf);
            context->skip += 1;
        }
    }
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
    char *buf;
    size_t root_size = 0;
    unsigned int dir_order;
    unsigned int mnt_order;


    /* Allocate storage and build mount point path */
    droot = dget(root->mnt_root);
    mntroot = mntget(root);

    name = getPath(root, &path, &mnt_order, &root_size);
    if ( IS_ERR(name) )
    {
        err("getPath failed");
        goto exit1;
    }

    /* Now scan the mount point path */
    for (dir_order = 0; dir_order <= TALPA_MAX_ORDER; dir_order++)
    {
        buf = talpa_alloc_path_order(dir_order, &path_size);
        if ( !buf )
        {
            dbg("failed to allocate order %u", dir_order);
            break;
        }
        buf[0] = 0;
        overflow = false;
        reg = scanDirectory(name, buf, path_size, &overflow);


        if ( !reg && overflow )
        {
            /* Try with a larger buffer */
            err("order %u is insufficient", dir_order);
            talpa_free_path_order(buf, dir_order);
            continue;
        }
        if (reg && !IS_ERR(reg))
        {
            DEBUG_err("found regular dentry 0x%p basename=%s",reg,reg->d_name.name);
        }
        break;
    }

    talpa_free_path_order(buf, dir_order);
    talpa_free_path_order(path, mnt_order);
exit1:
    mntput(mntroot);
    dput(droot);

    return reg;
}

#endif /* TALPA_SCAN_ON_MOUNT */

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0) */
