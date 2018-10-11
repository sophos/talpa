/*
 * talpa_syscallhook.h
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
#ifndef H_TALPASYSCALLHOOK
#define H_TALPASYSCALLHOOK

#include "platforms/linux/glue.h"

#define TALPA_SYSCALLHOOK_IFACE_VERSION (2)
#define TALPA_SYSCALLHOOK_IFACE_VERSION_STR "2"

/*
 * All strings are in userspace except for execve.
 */

struct talpa_syscall_operations
{
    long    (*open_post)    (unsigned int fd);
    void    (*close_pre)    (unsigned int fd);
    long    (*uselib_pre)   (const char __user * library);
    int     (*execve_pre)   (const TALPA_FILENAME_T* name);
    long    (*mount_pre)    (char __user * dev_name, char __user * dir_name, char __user * type, unsigned long flags, void __user * data);
    long    (*mount_post)   (int err, char __user * dev_name, char __user * dir_name, char __user * type, unsigned long flags, void __user * data);
    void    (*umount_pre)   (char __user * name, int flags, void** ctx);
    void    (*umount_post)  (int err, char __user * name, int flags, void* ctx);
};

/*
 * Returns non-zero if the module is unloadable at the time of call.
 */
unsigned int talpa_syscallhook_can_unload(void);

/*
 * Register yourself if you want talpa_syscallhook to call you.
 * You must define all the hooks which are enabled at run time
 * because talpa_syscallhook does no checking!
 */
#define talpa_syscallhook_register(ops) __talpa_syscallhook_register(TALPA_SYSCALLHOOK_IFACE_VERSION, ops)
int __talpa_syscallhook_register(unsigned int version, struct talpa_syscall_operations* ops);

/*
 * Unregister may sleep until the last caller exits.
 */
void talpa_syscallhook_unregister(struct talpa_syscall_operations* ops);

/*
 * Call when you want to write to potentialy read-only kernel
 * memory. modify_finish must be called after modifications are
 * done. Calls cannot be nested.
 * Returns non-zero on error which means modification cannot be
 * made following the call and talpa_syscallhook_modify_finish
 * should not be called.
 */
int talpa_syscallhook_modify_start(void);

/*
 * Call when you are done writing to potentialy read-only kernel
 * memory.
 */
void talpa_syscallhook_modify_finish(void);

/*
 * Use to modify pointers in potentialy read-only memory.
 * Returns address written to.
 */
void *talpa_syscallhook_poke(void *addr, void *val);

#endif

/*
 * End of talpa_syscallhook.h
 */
