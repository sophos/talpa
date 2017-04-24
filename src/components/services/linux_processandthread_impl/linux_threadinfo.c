/*
* linux_threadinfo.c
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

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tty.h>
#include <linux/fs_struct.h>

#ifdef TALPA_HAS_PROBE_KERNEL_READ
# include <linux/uaccess.h>
#endif

#include <asm/uaccess.h>

#include "common/talpa.h"
#include "app_ctrl/iportability_app_ctrl.h"
#include "platforms/linux/glue.h"
#include "platforms/linux/locking.h"
#include "platforms/linux/alloc.h"

#include "linux_threadinfo.h"

/*
* Forward declare implementation methods.
*/
static void get(const void* self);
static pid_t processId(const void* self);
static pid_t threadId(const void* self);
static unsigned long environmentSize(const void* self);
static const unsigned char* environment(const void* self);
static unsigned long controllingTTY(const void* self);
static const char* rootDir(const void* self);
static void* utsNamespace(const void* self);
static void deleteLinuxThreadInfo(struct tag_LinuxThreadInfo* object);


/*
* Template Object.
*/
static LinuxThreadInfo template_LinuxThreadInfo =
    {
        {
            get,
            processId,
            threadId,
            environmentSize,
            environment,
            controllingTTY,
            rootDir,
            utsNamespace,
            NULL,
            (void (*)(const void*))deleteLinuxThreadInfo
        },
        deleteLinuxThreadInfo,
        ATOMIC_INIT(1),
        0,
        0,
        0,
        NULL,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL  /* mUtsNamespace */
    };
#define this    ((LinuxThreadInfo*)self)


/*
* Object creation/destruction.
*/
LinuxThreadInfo* newLinuxThreadInfo(void)
{
    LinuxThreadInfo* object;


    object = talpa_alloc(sizeof(template_LinuxThreadInfo));
    if ( likely(object != NULL) )
    {
        struct task_struct* proc;
        struct mm_struct* mm;


        memcpy(object, &template_LinuxThreadInfo, sizeof(template_LinuxThreadInfo));
        object->i_IThreadInfo.object = object;
        proc = current;
        if( unlikely( proc == NULL ) )
        {
            critical("proc is NULL");
            talpa_free(object);
            return NULL;
        }

        object->mPID = proc->tgid;
        object->mTID = proc->pid;

        task_lock(proc);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        if (proc->tty)
        {
            object->mTTY = kdev_t_to_nr(proc->tty->device);
        }
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,6)) && !defined TALPA_HAS_TASK_NEW_TTY
        if (proc->tty)
        {
            object->mTTY = kdev_t_to_nr(tty_devnum(proc->tty));
        }
#else
        if (proc->signal)
        {
            if (proc->signal->tty)
            {
                object->mTTY = kdev_t_to_nr(tty_devnum(proc->signal->tty));
            }
        }
#endif

        object->mUtsNamespace = getUtsNamespace(proc);

        mm = proc->mm;

        if ( likely(mm != NULL) )
            atomic_inc(&mm->mm_users);


        if( unlikely(proc->fs == NULL) )
        {
            dbg("proc->fs is NULL for PID=%d",object->mPID);
            object->mRootMount = NULL;
            object->mRootDentry = NULL;
        }
        else
        {
            talpa_proc_fs_lock(&proc->fs->lock);
            object->mRootMount = mntget(talpa_task_root_mnt(proc));
            object->mRootDentry = dget(talpa_task_root_dentry(proc));
            talpa_proc_fs_unlock(&proc->fs->lock);
        }

        task_unlock(proc);

        if ( likely(mm != NULL) )
        {
            object->mEnvSize = mm->env_end - mm->env_start;
            object->mEnv = talpa_alloc(object->mEnvSize);
            if ( likely(object->mEnv != NULL) )
            {
#ifdef TALPA_HAS_PROBE_KERNEL_READ
                if ( probe_kernel_read(object->mEnv, (void *)mm->env_start, object->mEnvSize) )
                {
                    err("Can't copy environment for %s[%d/%d] (%lu)!", current->comm, current->tgid, current->pid, object->mEnvSize);
                    talpa_free(object->mEnv);
                    object->mEnv = NULL;
                    object->mEnvSize = 0;
                }
#else
                /* Don't have probe_kernel_read (2.6.32+) */
                if ( likely (down_write_trylock(&mm->mmap_sem) ) )
                {
                    /* We are not within munmap which holds the write lock */
                    up_write(&mm->mmap_sem); /* We don't actually need or want the lock while calling copy_from_user */
                    if ( copy_from_user(object->mEnv, (void *)mm->env_start, object->mEnvSize) )
                    {
                        err("Can't copy environment for %s[%d/%d] (%lu)!", current->comm, current->tgid, current->pid, object->mEnvSize);
                        talpa_free(object->mEnv);
                        object->mEnv = NULL;
                        object->mEnvSize = 0;
                    }
                }
#endif
            }
            else
            {
                object->mEnvSize = 0;
            }
            atomic_dec(&mm->mm_users);
        }

    }

    return object;
}

static void deleteLinuxThreadInfo(struct tag_LinuxThreadInfo* object)
{
    if ( atomic_dec_and_test(&object->mRefCnt) )
    {
        talpa_free(object->mEnv);
        talpa_free_path(object->mPath);

        if (object->mRootDentry)
            dput(object->mRootDentry);

        if (object->mRootMount)
            mntput(object->mRootMount);

        talpa_free(object);
    }
    return;
}

/*
* IThreadInfo.
*/

static void get(const void* self)
{
    atomic_inc(&this->mRefCnt);
    return;
}

static pid_t processId(const void* self)
{
    return this->mPID;
}

static pid_t threadId(const void* self)
{
    return this->mTID;
}

static unsigned long environmentSize(const void* self)
{
    return this->mEnvSize;
}

static const unsigned char* environment(const void* self)
{
    return this->mEnv;
}

static unsigned long controllingTTY(const void* self)
{
    return this->mTTY;
}

static const char* rootDir(const void* self)
{
    size_t path_size = 0;


    if ( this->mRootDir )
    {
        return this->mRootDir;
    }

    this->mPath = talpa_alloc_path(&path_size);
    if ( likely(this->mPath != NULL) )
    {
        if (this->mRootDentry == NULL || this->mRootMount == NULL)
        {
            strcpy(this->mPath, "/");
        }
        else
        {
            ISystemRoot* root = TALPA_Portability()->systemRoot();

            this->mRootDir =
                talpa__d_namespace_path(this->mRootDentry, this->mRootMount,
                    root->directoryEntry(root->object), root->mountPoint(root->object),
                    this->mPath, path_size, NULL, NULL);
            if (unlikely(this->mRootDir == NULL))
            {
                critical("threadInfo:rootDir: talpa__d_namespace_path returned NULL");
            }
        }

        /* Immediately delete the dentry and mount, since we aren't going to need them again */
        if (this->mRootDentry)
        {
            dput(this->mRootDentry); this->mRootDentry = NULL;
        }

        if (this->mRootMount)
        {
            mntput(this->mRootMount); this->mRootMount = NULL;
        }

    }
    else
    {
        warn("Not getting a single free page!");
    }

    return this->mRootDir;
}

static void* utsNamespace(const void* self)
{
    return this->mUtsNamespace;
}

/*
* End of linux_threadinfo.c
*/

