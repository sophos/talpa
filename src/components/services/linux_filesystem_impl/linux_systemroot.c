/*
 * linux_systemroot.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2017 Sophos Limited, Oxford, England.
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
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <asm/page.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
# include <linux/sched/task.h>
#endif

#include "common/talpa.h"
#include "platforms/linux/glue.h"
#include "platforms/linux/vfs_mount.h"
#include "platforms/linux/alloc.h"
#include "linux_systemroot.h"



/*
 * Forward declare implementation methods.
 */
static void* directoryEntry(const void* self);
static void* mountPoint(const void* self);
static void* utsNamespace(const void* self);
static void deleteLinuxSystemRoot(struct tag_LinuxSystemRoot* object);


/*
 * Template Object.
 */
static LinuxSystemRoot template_LinuxSystemRoot =
    {
        {
            directoryEntry,
            mountPoint,
            utsNamespace,
            NULL,
            (void (*)(void*))deleteLinuxSystemRoot
        },
        deleteLinuxSystemRoot,
        NULL,
        NULL,
        NULL /* mUtsNamespace */
};
#define this    ((LinuxSystemRoot*)self)

/*
 * Object creation/destruction.
 */
LinuxSystemRoot* newLinuxSystemRoot(void)
{
    LinuxSystemRoot* object;
    unsigned m_seq = 0;


    object = talpa_alloc(sizeof(template_LinuxSystemRoot));
    if ( object )
    {
        struct task_struct* inittask;


        memcpy(object, &template_LinuxSystemRoot, sizeof(template_LinuxSystemRoot));
        object->i_ISystemRoot.object = object;

        talpa_tasklist_lock();
        inittask = talpa_find_task_by_pid(1);
        talpa_tasklist_unlock();

        if ( inittask )
        {
            struct fs_struct *init_fs;
            struct vfsmount *rootmnt;

            task_lock(inittask);
            init_fs = inittask->fs;
            if ( init_fs )
            {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
                spin_lock(&init_fs->lock);
  #else
                write_lock(&init_fs->lock);
  #endif
                init_fs->users++;
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
                spin_unlock(&init_fs->lock);
  #else
                write_unlock(&init_fs->lock);
  #endif
#else
                atomic_inc(&init_fs->count);
#endif
            }
            object->mUtsNamespace = getUtsNamespace(inittask);
            task_unlock(inittask);

            if ( init_fs )
            {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
                spin_lock(&init_fs->lock);
#else
                write_lock(&init_fs->lock);
#endif


restart_mnt:
                talpa_vfsmount_lock(&m_seq); // locks dcache_lock on 2.4
                for (rootmnt = talpa_fs_mnt(init_fs); rootmnt != getParent(rootmnt); rootmnt = getParent(rootmnt));
                object->mMnt = mntget(rootmnt);
                object->mDentry = dget(rootmnt->mnt_root);
                if (talpa_vfsmount_unlock(&m_seq)) // unlocks dcache_lock on 2.4
                {
                    goto restart_mnt;
                }
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
                init_fs->users--;
  #else
                atomic_dec(&init_fs->count);
  #endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
                spin_unlock(&init_fs->lock);
#else
                write_unlock(&init_fs->lock);
#endif
            }
        }

        if ( !object->mMnt || !object->mDentry )
        {
            if ( object->mMnt )
            {
                mntput(object->mMnt);
            }

            if ( object->mDentry )
            {
                dput(object->mDentry);
            }

            talpa_free(object);

            return NULL;
        }

    }

    return object;
}

static void deleteLinuxSystemRoot(struct tag_LinuxSystemRoot* object)
{
    dput(object->mDentry);
    mntput(object->mMnt);

    talpa_free(object);
    return;
}

/*
 * ISystemRoot.
 */
static void* directoryEntry(const void* self)
{
    return this->mDentry;
}

static void* mountPoint(const void* self)
{
    return this->mMnt;
}

static void* utsNamespace(const void* self)
{
    return this->mUtsNamespace;
}

/*
 * End of linux_systemroot.c
 */

