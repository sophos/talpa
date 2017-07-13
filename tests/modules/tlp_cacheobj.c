/*
 * tlp-cache.c
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
#include <linux/limits.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/errno.h>

#include "tlp-test.h"


#include "common/bool.h"
#define TALPA_SUBSYS "cachetest"
#include "common/talpa.h"

#include "components/services/linux_personality_impl/linux_personality.h"
#include "components/services/linux_filesystem_impl/linux_fileinfo.h"
#include "components/services/linux_filesystem_impl/linux_filesysteminfo.h"
#include "components/core/cache_impl/cache.h"
#include "components/services/configurator_impl/procfs_configurator.h"
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

static Cache *cache;
static ProcfsConfigurator*  mConfig;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
long talpa_ioctl(struct file *file, unsigned int cmd, unsigned long parm)
#else
int talpa_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long parm)
#endif
{
    int ret = -ENOTTY;

    char string[256];
    struct talpa_cacheobj co;

    switch ( cmd )
    {
        case TALPA_TEST_CACHE_FIND:
            ret = copy_from_user(&co, (void *)parm, sizeof(struct talpa_cacheobj));
            if ( !ret )
            {
                ret = cache->i_ICache.find(cache, co.keyH, co.keyL);
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_CACHE_ADD:
            ret = copy_from_user(&co, (void *)parm, sizeof(struct talpa_cacheobj));
            if ( !ret )
            {
                cache->i_ICache.add(cache, co.class, co.keyH, co.keyL);
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_CACHE_CLEAR:
            ret = copy_from_user(&co, (void *)parm, sizeof(struct talpa_cacheobj));
            if ( !ret )
            {
                cache->i_ICache.clear(cache, co.keyH, co.keyL);
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_CACHE_CONFIG:
            ret = strncpy_from_user(string, (void *)parm, sizeof(string));
            if ( ret >= 0 )
            {
                cache->i_IConfigurable.set(cache, "fstypes", string);
            }
            else
            {
                err("strncpy_from_user!");
            }
            break;
        case TALPA_TEST_CACHE_PURGE:
            cache->i_IConfigurable.set(cache, "status", "disable");
            cache->i_IConfigurable.set(cache, "status", "enable");
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

    mConfig = newProcfsConfigurator();
    if ( !mConfig )
    {
        err("Failed to allocate configurator");
        mSystemRoot->delete(mSystemRoot);
        return -ENOMEM;
    }

    cache = newCache();

    if ( !cache )
    {
        mConfig->delete(mConfig);
        mSystemRoot->delete(mSystemRoot);
        err("Failed to create cache!");
        return 1;
    }

    cache->i_IConfigurable.set(cache, "status", "enable");

    ret = mConfig->i_IConfigurator.attach(mConfig, ECG_InterceptFilter, &cache->i_IConfigurable);

    if ( ret )
    {
        err("Failed to attach configuration!");
        cache->delete(cache);
        mConfig->delete(mConfig);
        mSystemRoot->delete(mSystemRoot);
        return ret;
    }

    ret = register_chrdev(TALPA_MAJOR, TALPA_DEVICE, &talpa_fops);

    if ( ret )
    {
        err("Failed to register TALPA Test character device!");
        mConfig->i_IConfigurator.detach(mConfig, &cache->i_IConfigurable);
        cache->delete(cache);
        mConfig->delete(mConfig);
        mSystemRoot->delete(mSystemRoot);
        return ret;
    }

    return 0;
}

static void __exit talpa_test_exit(void)
{
    int ret;

    mConfig->i_IConfigurator.detach(mConfig, &cache->i_IConfigurable);
    cache->delete(cache);
    mConfig->delete(mConfig);
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

