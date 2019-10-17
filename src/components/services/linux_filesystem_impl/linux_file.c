
/*
* linux_file.c
*
* TALPA Filesystem Interceptor
*
* Copyright (C) 2004-2018 Sophos Limited, Oxford, England.
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
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/quotaops.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/fcntl.h>
#include <linux/stat.h>
#endif

/* Header goes away in 2.6.39, but we don't use it on 2.6 anyway */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#include <linux/smp_lock.h>
#endif

#if defined TALPA_INODE_USES_INODE_LOCK
#include <linux/fs.h>
#endif

#if defined TALPA_INODE_USES_MUTEXES
#include <linux/mutex.h>
#endif

#ifdef TALPA_INODE_USES_SEMAPHORES
#include <asm/semaphore.h>
#endif

#ifdef CONFIG_IMA
#include <linux/ima.h>
#endif

#include "common/talpa.h"
#include "linux_file.h"
#include "platforms/linux/glue.h"
#include "platforms/linux/alloc.h"
#include "platforms/linux/uaccess.h"


/*
* Forward declare implementation methods.
*/
static void    get          (void* self);
static int     open         (void* self, const char* filename, unsigned int flags, bool check_permissions);
static int     openDentry   (void* self, void* object1, void* object2, unsigned int flags, bool check_permissions);
static int     openExec     (void* self, const char* filename);
static bool    isOpen       (const void* self);
static bool    isWritable   (const void* self);
static int     close        (void* self);
static loff_t  length       (const void* self);
static loff_t  seek         (void* self, loff_t offset, int whence);
static ssize_t read         (void* self, void __user * data, size_t count);
static ssize_t write        (void* self, const void __user * data, size_t count);
static int     unlink       (void* self);
static int     truncate     (void* self, loff_t length);

static void deleteLinuxFile(struct tag_LinuxFile* object);

/*
* Template Object.
*/
static LinuxFile template_LinuxFile =
    {
        {
            get,
            open,
            openDentry,
            openExec,
            isOpen,
            isWritable,
            close,
            length,
            seek,
            read,
            write,
            unlink,
            truncate,
            NULL,
            (void (*)(void*))deleteLinuxFile
        },
        deleteLinuxFile,
        ATOMIC_INIT(1),
        Dentry,
        false,
        NULL,
        0
    };
#define this    ((LinuxFile*)self)


/*
* Object creation/destruction.
*/
LinuxFile* newLinuxFile(void)
{
    LinuxFile* object;


    object = talpa_alloc(sizeof(template_LinuxFile));
    if ( likely(object != NULL) )
    {
        memcpy(object, &template_LinuxFile, sizeof(template_LinuxFile));
        object->i_IFile.object = object;
    }
    return object;
}

static inline bool verifyFile(struct file* file)
{
    if ( file->f_dentry && file->f_dentry->d_inode && S_ISREG(file->f_dentry->d_inode->i_mode) )
    {
        return true;
    }

    return false;
}

LinuxFile* cloneLinuxFile(struct file* fobject)
{
    LinuxFile* object;
    loff_t offset;


    if ( !verifyFile(fobject) )
    {
        return NULL;
    }

    object = talpa_alloc(sizeof(template_LinuxFile));
    if ( likely(object != NULL) )
    {
        memcpy(object, &template_LinuxFile, sizeof(template_LinuxFile));
        object->i_IFile.object = object;

        object->mOpenType = Cloned;

        get_file(fobject);

        if ( fobject->f_flags & (O_WRONLY | O_RDWR) )
        {
            object->mWritable = true;
        }

        object->mFile = fobject;

        offset = seek(object, 0, 1);
        if ( unlikely(offset < 0) )
        {
            talpa_free(object);
            return NULL;
        }

        object->mOffset = offset;
    }
    return object;
}

static void deleteLinuxFile(struct tag_LinuxFile* object)
{
    if ( atomic_dec_and_test(&object->mRefCnt) )
    {
        close(object);
        talpa_free(object);
    }

    return;
}

/*
* IFile.
*/

static void get(void* self)
{
    atomic_inc(&this->mRefCnt);
    return;
}

static int openExec(void* self, const char* filename)
{
    struct file* file;


    if ( unlikely(this->mFile != NULL) )
    {
        return -EBUSY;
    }

    file = open_exec(filename);

    if ( unlikely(IS_ERR(file)) )
    {
        return PTR_ERR(file);
    }

    this->mOpenType = Exec;
    this->mFile = file;
    this->mOffset = 0;

    return 0;
}

#ifndef ACC_MODE
  #define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])
#endif

static int openDentry(void* self, void* object1, void* object2, unsigned int flags, bool check_permissions)
{
    struct file *file;
    struct dentry *dentry = (struct dentry *)object1;
    struct inode *inode;
    struct vfsmount *mnt = (struct vfsmount *)object2;
    int error;
    int namei_flags;
    int acc_mode;


    if ( unlikely(this->mFile != NULL) )
    {
        return -EBUSY;
    }

    if ( unlikely((dentry == NULL) || (mnt == NULL)) )
    {
        return -EINVAL;
    }

    namei_flags = flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
    if ( (namei_flags+1) & O_ACCMODE )
    {
        namei_flags++;
    }
#endif

    acc_mode = ACC_MODE(namei_flags);

    if ( namei_flags & O_TRUNC )
    {
        acc_mode |= MAY_WRITE;
    }
#ifdef MAY_APPEND
    if ( namei_flags & O_APPEND )
    {
        acc_mode |= MAY_APPEND;
    }
#endif
    if ( acc_mode & MAY_WRITE )
    {
        this->mWritable = true;
    }

    if ( !dentry->d_inode )
    {
        return -ENOENT;
    }

    inode = dentry->d_inode;

    if ( S_ISLNK(inode->i_mode) )
    {
        return -ELOOP;
    }

    if ( S_ISDIR(inode->i_mode) && (namei_flags & FMODE_WRITE) )
    {
        return -EISDIR;
    }

    /* Always do permission checking if we are requesting write access or
       or also if caller has requested it and we do not own the file.
       Not doing permission checking for a read-only open when we own the
       file works around a problem with scanning a file created by user without
       permissions. And requesting no permission checking makes sense when
       opening a file for scanning when we know it has already been open (on close). */
    if ( (acc_mode&MAY_WRITE) ||
            (
                check_permissions &&
                (
                    __talpa_kuid_val(inode->i_uid) != __talpa_kuid_val(current_fsuid())
                )
            )
        )
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
        error = inode_permission(inode, acc_mode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        error = permission(inode, acc_mode, NULL);
#else
        error = permission(inode, acc_mode);
#endif
        if ( unlikely( error != 0 ) )
        {
            return error;
        }
    }

#ifdef CONFIG_IMA
  #ifdef TALPA_IMA_HAS_PATH_CHECK
    {
        struct path path = {mnt, dentry};


        error = ima_path_check(&path, acc_mode ?
                               acc_mode & (MAY_READ | MAY_WRITE | MAY_EXEC) :
                               ACC_MODE(flags) & (MAY_READ | MAY_WRITE),
                               IMA_COUNT_UPDATE);
        if ( unlikely( error != 0 ) )
        {
            return error;
        }
    }
  #endif
#endif

#ifdef current_cred /* Introduced in 2.6.29. */
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    {
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
       struct path path = { .mnt=mnt, .dentry=dentry };
#  else
       struct path path = { mnt, dentry };
#  endif
       path_get(&path);
       file = dentry_open (&path,flags,current_cred());
       path_put(&path);
    }
 #else
    file = dentry_open(dget(dentry), mntget(mnt), flags, current_cred());
 #endif
#else
    file = dentry_open(dget(dentry), mntget(mnt), flags);
#endif
    if ( unlikely(IS_ERR(file)) )
    {
        return PTR_ERR(file);
    }

    if ( !verifyFile(file) )
    {
        fput(file);
        return -EBADF;
    }

    this->mOpenType = Dentry;
    this->mFile = file;
    this->mOffset = 0;

    return 0;
}


static int open(void* self, const char* filename, unsigned int flags, bool check_permissions)
{
    int ret;
    struct vfsmount *mnt;
    struct dentry *dentry;
    struct file *file;
#ifdef TALPA_HAVE_PATH_LOOKUP
    struct nameidata nd;
#else
    struct path p;
#endif

    if ( unlikely(this->mFile != NULL) )
    {
        return -EBUSY;
    }

    if ( unlikely(filename == NULL) )
    {
        return -EINVAL;
    }

#ifdef TALPA_HAVE_PATH_LOOKUP
    ret = talpa_path_lookup(filename, TALPA_LOOKUP, &nd);
#else
    ret = kern_path(filename, TALPA_LOOKUP, &p);
#endif

    if ( unlikely(ret != 0) )
    {
        return ret;
    }

#ifdef TALPA_HAVE_PATH_LOOKUP
    mnt = talpa_nd_mnt(&nd);
    dentry = talpa_nd_dentry(&nd);
#else
    mnt = p.mnt;
    dentry = p.dentry;
#endif
    ret = openDentry(self, dentry, mnt, flags, check_permissions);

    // NFSv4 doesn't implement openDentry, so we need to go up a level
    // and use filp_do_open
    if (ret == -ENOTDIR)
    {
        dbg("NFSv4 backup route - -ENOTDIR -> filp_open\n");
        file = filp_open(filename, flags, 0);
        if (IS_ERR(file))
        {
            ret = PTR_ERR(file);
            err("NFSv4 backup route failure %d\n",ret);
        }
        else
        {
            dbg("NFSv4 backup route success\n");
            this->mOpenType = Dentry;
            this->mFile = file;
            this->mOffset = 0;
            ret = 0;
        }
    }
 #ifdef TALPA_HAVE_PATH_LOOKUP
    talpa_path_release(&nd);
#else
    path_put(&p);
#endif

    return ret;
}

static bool isOpen(const void* self)
{
    if ( this->mFile )
    {
        return true;
    }

    return false;
}

static bool isWritable(const void* self)
{
    return this->mWritable;
}

static int close(void* self)
{
    int retval = 0;


    if ( unlikely(!this->mFile) )
    {
        return -EBADF;
    }

    if ( this->mOpenType == Exec )
    {
        allow_write_access(this->mFile);
    }
    else if ( this->mOpenType == Cloned )
    {
        retval = seek(this, this->mOffset, 0);
    }

    fput(this->mFile);

    this->mFile = NULL;
    this->mOffset = 0;
    this->mWritable = false;

    return retval;
}

static loff_t length(const void* self)
{
    int error;
    struct kstat stat;

    if ( unlikely(!this->mFile) )
    {
        return -EBADF;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    error = vfs_getattr(&this->mFile->f_path, &stat,
            STATX_BASIC_STATS, AT_STATX_DONT_SYNC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
    error = vfs_getattr(&this->mFile->f_path, &stat);
#else
    error = vfs_getattr(this->mFile->f_vfsmnt, this->mFile->f_dentry, &stat);
#endif
    if ( likely(error == 0) )
        return stat.size;

    // fallback - works for most filesystems, but not overlayfs
    return this->mFile->f_dentry->d_inode->i_size;
}

static loff_t seek(void* self, loff_t offset, int whence)
{
    struct file* file = this->mFile;
    mm_segment_t oldfs;
    loff_t res;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
    loff_t (*fn)(struct file *, loff_t, int);
#endif

    if ( unlikely(!file) )
    {
        return -EBADF;
    }

    res = -EINVAL;

    if ( whence > 2 )
    {
        return res;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fn = default_llseek;
    if (file->f_op && file->f_op->llseek)
        fn = file->f_op->llseek;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    lock_kernel();
    res = fn(file, offset, whence);
    unlock_kernel();
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
    fn = default_llseek;
    if (file->f_op && file->f_op->llseek)
        fn = file->f_op->llseek;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    res = fn(file, offset, whence);
#else
    oldfs = get_fs(); set_fs(KERNEL_DS);
    res = vfs_llseek(file, offset, whence);
#endif
    set_fs(oldfs);

    return res;
}

static ssize_t read(void* self, void __user * data, size_t count)
{
    struct file* file = this->mFile;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    mm_segment_t oldfs;
#endif
    ssize_t retval;


    if ( unlikely(!file) )
    {
        return -EBADF;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    /* kernel_read is valid for both user and kernel pointers, due to use of set_fs() */
    retval = kernel_read(file, (__force void *) data, count, &file->f_pos);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    oldfs = get_fs(); set_fs(KERNEL_DS);
    retval = vfs_read(file, data, count, &file->f_pos);
    set_fs(oldfs);
#else
    if ( !file->f_op || !file->f_op->read )
    {
        return -EINVAL;
    }

    oldfs = get_fs(); set_fs(KERNEL_DS);
    retval = file->f_op->read(file, data, count, &file->f_pos);
    set_fs(oldfs);
#endif

    return retval;
}

static ssize_t write(void* self, const void __user * data, size_t count)
{
    struct file* file = this->mFile;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    mm_segment_t oldfs;
#endif
    ssize_t retval;


    if ( unlikely(!file) )
    {
        return -EBADF;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    /* kernel_write is valid for both user and kernel pointers, due to use of set_fs() */
    retval = kernel_write(file, (__force void *) data, count, &file->f_pos);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    oldfs = get_fs(); set_fs(KERNEL_DS);
    retval = vfs_write(file, data, count, &file->f_pos);
    set_fs(oldfs);
#else
    if ( !file->f_op || !file->f_op->write )
    {
        return -EINVAL;
    }

    oldfs = get_fs(); set_fs(KERNEL_DS);
    retval = file->f_op->write(file, data, count, &file->f_pos);
    set_fs(oldfs);
#endif

    return retval;
}

static void talpa_inode_lock(struct inode* i)
{
#ifdef TALPA_INODE_USES_INODE_LOCK
    inode_lock_nested(i, I_MUTEX_PARENT);
#elif defined TALPA_INODE_USES_MUTEXES
  #if defined TALPA_HAS_NESTED_MUTEX
    mutex_lock_nested(&i->i_mutex, I_MUTEX_PARENT);
  #else
    mutex_lock(&i->i_mutex);
  #endif
#else
    down(&i->i_sem);
#endif
}

static void talpa_inode_unlock(struct inode* i)
{
#ifdef TALPA_INODE_USES_INODE_LOCK
    inode_unlock(i);
#elif defined TALPA_INODE_USES_MUTEXES
    mutex_unlock(&i->i_mutex);
#else
    up(&i->i_sem);
#endif
}

static int unlink(void* self)
{
    int error;
    struct dentry* parentd;
    struct inode* parenti;
    struct dentry* filed;


    if ( unlikely(!this->mFile) )
    {
        return -EBADF;
    }

    filed = dget(this->mFile->f_dentry);

    if ( S_ISDIR(filed->d_inode->i_mode) )
    {
        return -EISDIR;
    }

    parentd = dget(filed->d_parent);

    if ( !parentd )
    {
        dput(filed);
        return -ENOTDIR;
    }

    parenti = parentd->d_inode;

    if ( !parenti )
    {
        dput(parentd);
        dput(filed);
        return -ENOENT;
    }

    talpa_inode_lock(parenti);

    atomic_inc(&parenti->i_count);

#if defined TALPA_VFSUNLINK_SUSE103
    error = vfs_unlink(parenti, filed, mntget(this->mFile->f_vfsmnt));
    mntput(this->mFile->f_vfsmnt);
#elif defined TALPA_VFSUNLINK_VSERVER
    error = vfs_unlink(parenti, filed, NULL);
#elif defined TALPA_VFSUNLINK_DELEGATE
    error = vfs_unlink(parenti, filed, NULL);
#else
    error = vfs_unlink(parenti, filed);
#endif

    talpa_inode_unlock(parenti);

    iput(parenti);
    dput(parentd);
    dput(filed);

    return error;
}

static int truncate(void* self, loff_t length)
{
    /*
     * Following code is taken from kernel sources and modified.
     */

    struct inode * inode;
    struct file * file;
    int error;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,13)
    int small = 1;
#endif

    error = -EINVAL;
    if (length < 0)
        goto out;
    error = -EBADF;
    file = this->mFile;
    if (!file)
        goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,13)
    /* explicitly opened as large or we are on 64-bit box */
    if (file->f_flags & O_LARGEFILE)
        small = 0;
#endif

    inode = file->f_dentry->d_inode;

    error = -EISDIR;
    if (S_ISDIR(inode->i_mode))
        goto out;

    error = -EINVAL;
    if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
        goto out;

    error = -EROFS;
    if (IS_RDONLY(inode))
        goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,13)
    error = -EINVAL;
    /* Cannot ftruncate over 2^31 bytes without large file support */
    if (small && length > MAX_NON_LFS)
        goto out;

    error = -EPERM;
    if (IS_APPEND(inode))
        goto out;
#else
    error = -EPERM;
    if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
        goto out;
#endif

    error = get_write_access(inode);
    if (error)
        goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
    error = break_lease(inode, O_WRONLY);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    error = break_lease(inode, FMODE_WRITE);
#else
    error = get_lease(inode, FMODE_WRITE);
#endif
    if (error)
        goto put_and_out;

    error = locks_verify_truncate(inode, file, length);
    if (!error) {
        /* Not pretty: "inode->i_size" shouldn't really be signed. But it is. */
        if (length < 0)
            error = -EINVAL;
        else {
#if defined TALPA_DOTRUNCATE_1
            typedef int (*dotruncatefunc)(struct dentry *dentry, loff_t length);
#elif defined TALPA_DOTRUNCATE_2
            typedef int (*dotruncatefunc)(struct dentry *dentry, loff_t length, struct file *filp);
#elif defined TALPA_DOTRUNCATE_3
            typedef int (*dotruncatefunc)(struct dentry *dentry, loff_t length, unsigned int time_attrs, struct file *filp);
#elif defined TALPA_DOTRUNCATE_RH4
            typedef int (*dotruncatefunc)(struct dentry *dentry, loff_t length, unsigned int time_attrs);
#elif defined TALPA_DOTRUNCATE_SUSE103
            typedef int (*dotruncatefunc)(struct dentry *dentry, struct vfsmount *mnt, loff_t length, unsigned int time_attrs, struct file *filp);
#else
  #error "Truncate type not defined!"
#endif
            dotruncatefunc talpa_do_truncate = (dotruncatefunc)talpa_get_symbol("do_truncate", (void *)TALPA_DOTRUNCATE_ADDR);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
            vfs_dq_init(inode);
  #endif
#else
            DQUOT_INIT(inode);
#endif
#if defined TALPA_DOTRUNCATE_1
            error = talpa_do_truncate(file->f_dentry, length);
#elif defined TALPA_DOTRUNCATE_2
            error = talpa_do_truncate(file->f_dentry, length, file);
#elif defined TALPA_DOTRUNCATE_3
            error = talpa_do_truncate(file->f_dentry, length, 0, file);
#elif defined TALPA_DOTRUNCATE_RH4
            error = talpa_do_truncate(file->f_dentry, length, 0);
#elif defined TALPA_DOTRUNCATE_SUSE103
            error = talpa_do_truncate(file->f_dentry, file->f_vfsmnt, length, 0, file);
#endif
        }
    }

put_and_out:
    put_write_access(inode);
out:
    return error;
}

/*
* End of linux_file.c
*/
