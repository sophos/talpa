/*
 * tlp_wronginterceptor.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2008-2018 Sophos Limited, Oxford, England.
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

static int __init talpa_test_init(void)
{
    return __talpa_syscallhook_register(0, &ops);
}

static void __exit talpa_test_exit(void)
{
    talpa_syscallhook_unregister(&ops);
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
