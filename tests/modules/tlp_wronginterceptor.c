/*
 * tlp_wronginterceptor.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2008-2019 Sophos Limited, Oxford, England.
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



#define TALPA_SUBSYS "wronginterceptor"
#include "common/talpa.h"

#include "platforms/linux/talpa_syscallhook.h"


static long talpaDummyOpen(unsigned int fd)
{
    return 0;
}

static void talpaDummyClose(unsigned int fd)
{
    return;
}

static long talpaDummyUselib(const char __user * library)
{
    return 0;
}


static long talpaDummyPreMount(char __user * dev_name, char __user * dir_name, char __user * type, unsigned long flags, void __user * data)
{
    return 0;
}

static long talpaDummyPostMount(int err, char __user * dev_name, char __user * dir_name, char __user * type, unsigned long flags, void __user * data)
{
    return 0;
}

static void talpaDummyPreUmount(char __user * name, int flags, void** ctx)
{
    return;
}

static void talpaDummyPostUmount(int err, char __user * name, int flags, void* ctx)
{
    return;
}

static struct talpa_syscall_operations ops = {
    .open_post = talpaDummyOpen,
    .close_pre = talpaDummyClose,
    .execve_pre = NULL,
    .uselib_pre = talpaDummyUselib,
    .mount_pre = talpaDummyPreMount,
    .mount_post = talpaDummyPostMount,
    .umount_pre = talpaDummyPreUmount,
    .umount_post = talpaDummyPostUmount,
};


int (*syscallhook_register)(unsigned int version, struct talpa_syscall_operations* ops);
void (*syscallhook_unregister)(struct talpa_syscall_operations* ops);

static int __init talpa_test_init(void)
{
	int err = -EFAULT;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    syscallhook_register = (int (*)(unsigned int, struct talpa_syscall_operations* ops))inter_module_get("__talpa_syscallhook_register");
    syscallhook_unregister = (void (*)(struct talpa_syscall_operations* ops))inter_module_get("talpa_syscallhook_unregister");
#else
    syscallhook_register = symbol_get(__talpa_syscallhook_register);
    syscallhook_unregister = symbol_get(talpa_syscallhook_unregister);
#endif

    if ( syscallhook_register && syscallhook_unregister )
    {
        err = syscallhook_register(0, &ops);
        if ( err )
        {
            err("Failed to register with talpa-syscallhook! (%d)", err);
            goto error;
        }

        info("Enabled");

        return 0;
    }
    else
    {
            err("Failed to register with talpa-syscallhook!");
            goto error;
    }

error:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        if ( syscallhook_register )
        {
            inter_module_put("__talpa_syscallhook_register");
        }
        if ( syscallhook_unregister )
        {
            inter_module_put("talpa_syscallhook_unregister");
        }
#else
        if ( syscallhook_register )
        {
            symbol_put(__talpa_syscallhook_register);
        }
        if ( syscallhook_unregister )
        {
            symbol_put(talpa_syscallhook_unregister);
        }
#endif

    return err;
}

static void __exit talpa_test_exit(void)
{
    if ( syscallhook_register && syscallhook_unregister )
    {
        syscallhook_unregister(&ops);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        inter_module_put("__talpa_syscallhook_register");
        inter_module_put("talpa_syscallhook_unregister");
#else
        symbol_put(__talpa_syscallhook_register);
        symbol_put(talpa_syscallhook_unregister);
#endif
        info("Disabled");
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
