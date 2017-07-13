/*
 * tlp-personality.c
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/errno.h>

#include "tlp-test.h"


#include "common/bool.h"
#define TALPA_SUBSYS "threadinfotest"
#include "common/talpa.h"

#include "components/services/linux_processandthread_impl/linux_threadinfo.h"
#include "components/services/linux_filesystem_impl/linux_systemroot.h"
#include "app_ctrl/iportability_app_ctrl.h"

static ISystemRoot* systemRoot(void);
static LinuxSystemRoot* mSystemRoot;

/*
 * Singleton Object.
 */
static IPortabilityApplicationControl GL_talpa_linux =
    {
        NULL,
        systemRoot,
        NULL,
        NULL,
        NULL
    };

const IPortabilityApplicationControl* TALPA_Portability(void)
{
    return &GL_talpa_linux;
}

static ISystemRoot* systemRoot(void)
{
    return &mSystemRoot->i_ISystemRoot;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
long talpa_ioctl(struct file *file, unsigned int cmd, unsigned long parm)
#else
int talpa_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long parm)
#endif
{
    int ret = -ENOTTY;

    struct talpa_thread thread;
    LinuxThreadInfo *ti;

    switch ( cmd )
    {
        case TALPA_TEST_THREADINFO:
            ret = copy_from_user(&thread, (void *)parm, sizeof(struct talpa_thread));
            if ( !ret )
            {
                ti = newLinuxThreadInfo();
                if ( ti )
                {
                    thread.pid = ti->i_IThreadInfo.processId(ti);
                    thread.tid = ti->i_IThreadInfo.threadId(ti);
                    thread.tty = ti->i_IThreadInfo.controllingTTY(ti);
                    thread.envsize = ti->i_IThreadInfo.environmentSize(ti);
                    ret = copy_to_user((void *)thread.env, ti->i_IThreadInfo.environment(ti), thread.envsize);
                    if ( !ret )
                    {
                        ret = copy_to_user((void *)parm,&thread,sizeof(struct talpa_thread));
                        if ( ret )
                        {
                            err("copy_to_user!");
                        }
                    }
                    else
                    {
                        err("env copy error!");
                    }

                    ti->delete(ti);
                }
                else
                {
                    err("Failed to create LinuxThreadInfo!");
                    ret = -EINVAL;
                }
            }
            else
            {
                err("copy_from_user!");
            }
            break;
    }

    return ret;
}

struct file_operations talpa_fops =
{
    owner:  THIS_MODULE,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
    unlocked_ioctl:  talpa_ioctl
#else
    ioctl:  talpa_ioctl
#endif
};

static int __init talpa_test_init(void)
{
    int ret;

    mSystemRoot = newLinuxSystemRoot();
    if (mSystemRoot == 0)
    {
        err("Failed to create system root");
        return -ENOMEM;
    }

    ret = register_chrdev(TALPA_MAJOR, TALPA_DEVICE, &talpa_fops);

    if ( ret )
    {
        err("Failed to register TALPA Test character device!");
        mSystemRoot->delete(mSystemRoot);
        return ret;
    }

    return 0;
}

static void __exit talpa_test_exit(void)
{
    int ret;

    mSystemRoot->delete(mSystemRoot);

    ret = talpa_unregister_chrdev(TALPA_MAJOR, TALPA_DEVICE);

    if ( ret )
    {
        err("Hmmmmmm... very strange things are happening!");
    }
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Limited");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Test Module");
MODULE_LICENSE("GPL");

module_init(talpa_test_init);
module_exit(talpa_test_exit);

