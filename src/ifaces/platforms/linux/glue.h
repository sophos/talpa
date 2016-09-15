/*
 * linux_glue.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
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
#ifndef H_LINUXGLUE
#define H_LINUXGLUE

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <asm/param.h>
#include <linux/types.h>
#include <asm/page.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/kdev_t.h>
#define TALPA_LOOKUP (LOOKUP_FOLLOW)
#define inode_dev(i) ((i)->i_sb->s_dev)
#define kdev_t_to_nr old_encode_dev
#else
#define TALPA_LOOKUP (LOOKUP_FOLLOW|LOOKUP_POSITIVE)
#define inode_dev(i) ((i)->i_dev)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#include <linux/path.h>
#endif

#ifdef HAVE_LINUXUIDGID
#include <linux/uidgid.h>
#endif

#include "platforms/linux/bool.h"
#include "platform/compiler.h"



#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#define try_module_get(m) \
({ \
    __MOD_INC_USE_COUNT(m); \
    1; \
})

#define module_put(m) \
({ \
    __MOD_DEC_USE_COUNT(m); \
    1; \
})

#endif

#ifndef MODULE_LICENSE
#define MODULE_LICENSE(x) const char module_license[] = x
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) || defined TALPA_HAS_NEW_PARENT
#define processParentPID(task) task->parent->pid
#else
#define processParentPID(task) task->p_pptr->pid
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10) && !defined TALPA_HAS_SNPRINTF
#define snprintf(string, len, arg...) sprintf(string, ## arg)
#endif

char * talpa__d_path( struct dentry *dentry, struct vfsmount *vfsmnt,
            struct dentry *root, struct vfsmount *rootmnt,
            char *buffer, int buflen);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)

#define talpa_nd_dentry(nd) ((nd)->path.dentry)
#define talpa_nd_mnt(nd) ((nd)->path.mnt)
#define talpa_path_release(nd) (path_put(&(nd)->path))
#define talpa_task_root_dentry(t) ((t)->fs->root.dentry)
#define talpa_task_root_mnt(t) ((t)->fs->root.mnt)
#define talpa_fs_mnt(f) ((f)->root.mnt)

static inline char *talpa_d_path(struct dentry *dentry, struct vfsmount *mnt, char *buf, int len)
{
    struct path path;


    path.dentry = dentry;
    path.mnt = mnt;

    return d_path(&path, buf, len);
}
#else /* <2.6.25 */

#define talpa_nd_dentry(nd) ((nd)->dentry)
#define talpa_nd_mnt(nd) ((nd)->mnt)
#define talpa_d_path d_path
#define talpa_path_release(nd) (path_release(nd))
#define talpa_task_root_dentry(t) ((t)->fs->root)
#define talpa_task_root_mnt(t) ((t)->fs->rootmnt)
#define talpa_fs_mnt(f) ((f)->rootmnt)

#endif /* 2.6.25 */

#if  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)

/* No path_lookup */
#undef TALPA_HAVE_PATH_LOOKUP

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,4,25) && !defined TALPA_HAS_PATH_LOOKUP
#define TALPA_HAVE_PATH_LOOKUP 1
static inline int talpa_path_lookup(const char *path, unsigned flags, struct nameidata *nd)
{
        int error = 0;
        if (path_init(path, flags, nd))
                error = path_walk(path, nd);
        return error;
}
#else
#define talpa_path_lookup path_lookup
#define TALPA_HAVE_PATH_LOOKUP 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#ifdef _LINUX_HZ_H

/*
 * Thanks to SuSE 'smart' kernel hack we need these to be a run-time calculation
 */

static inline unsigned long msecs_to_jiffies(unsigned long ms)
{
    return ms*HZ/1000;
}

static inline unsigned long jiffies_to_msecs(unsigned long jiffies)
{
    return jiffies*1000/HZ;
}

#else
# if HZ == 1000
#  define jiffies_to_msecs(x)    (x)
#  define msecs_to_jiffies(x)    (x)
# elif HZ == 100
#  define jiffies_to_msecs(x)    ((x) * 10)
#  define msecs_to_jiffies(x)    ((x) / 10)
# else
#  define jiffies_to_msecs(x)    ((x) * 1000 / HZ)
#  define msecs_to_jiffies(x)    ((x) * HZ / 1000)
# endif
#endif

#else /* version >= 2.6.0 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)) && !TALPA_HAS_BACKPORTED_JIFFIES

static inline unsigned long msecs_to_jiffies(const unsigned int m)
{
#if HZ <= 1000 && !(1000 % HZ)
        return (m + (1000 / HZ) - 1) / (1000 / HZ);
#elif HZ > 1000 && !(HZ % 1000)
        return m * (HZ / 1000);
#else
        return (m * HZ + 999) / 1000;
#endif
}

#endif /* version < 2.6.7 */

#endif /* version < 2.6.0 */

/*
 * tasklist_lock un-export handling
 */
#ifdef TALPA_NO_TASKLIST_LOCK
void talpa_tasklist_lock(void);
void talpa_tasklist_unlock(void);
#else
static inline void talpa_tasklist_lock(void)
{
    read_lock(&tasklist_lock);
}

static inline void talpa_tasklist_unlock(void)
{
    read_unlock(&tasklist_lock);
}
#endif

/*
 * hidden vfsmnt_lock handling
 */
void talpa_vfsmount_lock(unsigned* m_seq);
bool talpa_vfsmount_unlock(unsigned* m_seq);

/* various helpers */
#define flags_to_writable(f)   ((f)&(O_WRONLY|O_RDWR|O_APPEND|O_CREAT|O_TRUNC)?true:false)

/* Task credentials */
#define talpa_current(xxx)  \
({                          \
        current->xxx;       \
})

#ifndef current_uid
#define current_uid() talpa_current(uid)
#endif

#ifndef current_euid
#define current_euid() talpa_current(euid)
#endif

#ifndef current_gid
#define current_gid() talpa_current(gid)
#endif

#ifndef current_egid
#define current_egid() talpa_current(egid)
#endif

#ifndef current_fsuid
#define current_fsuid() talpa_current(fsuid)
#endif



static inline struct task_struct *talpa_find_task_by_pid(pid_t pid)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
        return pid_task(find_pid_ns(1, &init_pid_ns), PIDTYPE_PID);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
        return find_task_by_vpid(1);
#else
        return find_task_by_pid(1);
#endif
}

/*
 * Relocatable hidden kernel symbol support.
 */
#ifndef CONFIG_RELOCATABLE
static __inline const void* talpa_get_symbol(const char* name, const void* ptr)
{
    (void)name;


    return ptr;
}
#else
static __inline const void* talpa_get_symbol(const char* name, const void* ptr)
{
    long offset = (unsigned long)&printk - TALPA_PRINTK_ADDR;


    (void)name;

    return (void *)ptr + offset;
}
#endif

#ifdef TALPA_HAS_STRUCT_FILENAME
#define TALPA_FILENAME_T struct filename
static __inline const char* getCStr(const TALPA_FILENAME_T* filenameObj)
{
    return filenameObj->name;
}
#else /* ! TALPA_HAS_STRUCT_FILENAME */
#define TALPA_FILENAME_T char
static __inline const char* getCStr(const TALPA_FILENAME_T* filenameObj)
{
    return filenameObj;
}
#endif /* TALPA_HAS_STRUCT_FILENAME */


#ifndef TALPA_PUTNAME_EXPORTED
void talpa_putname(TALPA_FILENAME_T* filename);
#else
# define talpa_putname putname
#endif

#ifndef TALPA_GETNAME_EXPORTED
TALPA_FILENAME_T * talpa_getname(const char * filename);
#else
# define talpa_getname getname
#endif
/**
 * Implement our own copy, since kernel 3.12 gets rid of this exported function
 */

#if  LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
# define TALPA_SYSTEM_GET_FS_ROOT_AND_PWD
#endif

#ifdef TALPA_SYSTEM_GET_FS_ROOT_AND_PWD
# define talpa_get_fs_root_and_pwd get_fs_root_and_pwd
#else
void talpa_get_fs_root_and_pwd(struct fs_struct *fs, struct path *root, struct path *pwd);
#endif

#ifdef HAVE_LINUXUIDGID

typedef kuid_t talpa_kuid_t;
typedef kgid_t talpa_kgid_t;

#define TALPA_KUIDT_INIT(value) KUIDT_INIT(value)
#define TALPA_KGIDT_INIT(value) KGIDT_INIT(value)

#define __talpa_kuid_val __kuid_val
#define __talpa_kgid_val __kgid_val

#else /* ! HAVE_LINUXUIDGID */

typedef uid_t talpa_kuid_t;
typedef gid_t talpa_kgid_t;

static inline uid_t __talpa_kuid_val(talpa_kuid_t uid)
{
        return uid;
}

static inline gid_t __talpa_kgid_val(talpa_kgid_t gid)
{
        return gid;
}

#define TALPA_KUIDT_INIT(value) ((talpa_kuid_t) value )
#define TALPA_KGIDT_INIT(value) ((talpa_kgid_t) value )

#endif /* ! HAVE_LINUXUIDGID */

#ifndef TALPA_FDENTRY_DEFINED
#define f_dentry f_path.dentry
#endif /* TALPA_FDENTRY_DEFINED */

#endif /* H_LINUXGLUE */
/*
 * End of linux_glue.h
 */
