/*
 * tlp-fileinfo.c
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
#include <asm/errno.h>

#include "tlp-test.h"

#include "platform/uaccess.h"

#include "common/bool.h"
#define TALPA_SUBSYS "fileinfotest"
#include "common/talpa.h"

#include "components/services/linux_filesystem_impl/linux_fileinfo.h"
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

    struct talpa_file tf;
    LinuxFileInfo *fi;

    switch ( cmd )
    {
        case TALPA_TEST_FILEINFO:
            ret = copy_from_user(&tf, (void *)parm, sizeof(struct talpa_file));
            if ( !ret )
            {
                fi = newLinuxFileInfo(tf.operation, tf.name, 0, 0);
                if ( fi )
                {
                    tf.operation = fi->i_IFileInfo.operation(fi);
                    strncpy(tf.name,fi->i_IFileInfo.filename(fi),sizeof(tf.name));
                    tf.major = fi->i_IFileInfo.deviceMajor(fi);
                    tf.minor = fi->i_IFileInfo.deviceMinor(fi);
                    ret = copy_to_user((void *)parm,&tf,sizeof(struct talpa_file));
                    if ( ret )
                    {
                        err("copy_to_user!");
                    }
                    fi->delete(fi);
                }
                else
                {
                    err("Failed to create IFileInfo!");
                    ret = -EINVAL;
                }
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_FILEINFOFD:
            ret = copy_from_user(&tf, (void *)parm, sizeof(struct talpa_file));
            if ( !ret )
            {
                fi = newLinuxFileInfoFromFd(tf.operation, tf.fd);
                if ( fi )
                {
                    tf.operation = fi->i_IFileInfo.operation(fi);
                    strncpy(tf.name,fi->i_IFileInfo.filename(fi),sizeof(tf.name));
                    tf.major = fi->i_IFileInfo.deviceMajor(fi);
                    tf.minor = fi->i_IFileInfo.deviceMinor(fi);
                    ret = copy_to_user((void *)parm,&tf,sizeof(struct talpa_file));
                    if ( ret )
                    {
                        err("copy_to_user!");
                    }
                    fi->delete(fi);
                }
                else
                {
                    err("Failed to create IFileInfo!");
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
        mSystemRoot->delete(mSystemRoot);
        err("Failed to register TALPA Test character device!");
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

