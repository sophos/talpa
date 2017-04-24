/*
 * linux_locking.h
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
#ifndef H_LINUXLOCKING
#define H_LINUXLOCKING

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/rcupdate.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4)
#include <linux/rwsem.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16) || defined TALPA_HAS_MUTEXES
#include <linux/mutex.h>
#else
#include <asm/semaphore.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#include <linux/rwlock_types.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#include <linux/spinlock_types.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#include <linux/smp_lock.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16) || defined TALPA_HAS_MUTEXES

typedef struct mutex talpa_mutex_t;

#define TALPA_DEFINE_MUTEX      DEFINE_MUTEX
#define TALPA_MUTEX_INIT        { }
#define TALPA_STATIC_MUTEX(x)   __MUTEX_INITIALIZER(x)
#define talpa_mutex_init        mutex_init
#define talpa_mutex_lock        mutex_lock
#define talpa_mutex_unlock      mutex_unlock

#else

/* Starting with 2.6.15, this macro is no longer present */
#ifndef __MUTEX_INITIALIZER
#define __MUTEX_INITIALIZER(name) \
        __SEMAPHORE_INITIALIZER(name,1)
#endif

typedef struct semaphore talpa_mutex_t;

#define TALPA_DEFINE_MUTEX      DECLARE_MUTEX
#define TALPA_MUTEX_INIT        { }
#define TALPA_STATIC_MUTEX(x)   __MUTEX_INITIALIZER(x)
#define talpa_mutex_init        init_MUTEX
#define talpa_mutex_lock        down
#define talpa_mutex_unlock      up

#endif

typedef spinlock_t talpa_simple_lock_t;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define TALPA_SIMPLE_UNLOCKED(lockname)   __SPIN_LOCK_UNLOCKED(lockname)
#else
#define TALPA_SIMPLE_UNLOCKED(lockname)   SPIN_LOCK_UNLOCKED
#endif

#define talpa_simple_init       spin_lock_init
#define talpa_simple_lock       spin_lock
#define talpa_simple_unlock     spin_unlock

typedef rwlock_t talpa_rw_lock_t;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#define TALPA_RW_UNLOCKED(lockname)   __RW_LOCK_UNLOCKED(lockname)
#else
#define TALPA_RW_UNLOCKED(lockname)   RW_LOCK_UNLOCKED
#endif

#define talpa_rw_init       rwlock_init
#define talpa_read_lock     read_lock
#define talpa_read_unlock   read_unlock
#define talpa_write_lock    write_lock
#define talpa_write_unlock  write_unlock

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

typedef spinlock_t talpa_rcu_lock_t;

#define TALPA_RCU_UNLOCKED(lockname)      TALPA_SIMPLE_UNLOCKED(lockname)
#define talpa_rcu_lock_init         spin_lock_init
#define talpa_rcu_read_lock(l)      rcu_read_lock()
#define talpa_rcu_read_unlock(l)    rcu_read_unlock()
#define talpa_rcu_write_lock(l)     spin_lock(l)
#define talpa_rcu_write_unlock(l)   spin_unlock(l)

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) */

typedef rwlock_t talpa_rcu_lock_t;

#define TALPA_RCU_UNLOCKED(lockname)      TALPA_RW_UNLOCKED(lockname)
#define talpa_rcu_lock_init     rwlock_init
#define talpa_rcu_read_lock     read_lock
#define talpa_rcu_read_unlock   read_unlock
#define talpa_rcu_write_lock    write_lock
#define talpa_rcu_write_unlock  write_unlock

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) */

/* BKL wrapper */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define talpa_lock_kernel       lock_kernel
#define talpa_unlock_kernel     unlock_kernel
#else
/* No more BKL, so the best we can do is put in a memory barrier and hope */
#define talpa_lock_kernel       smp_mb
#define talpa_unlock_kernel     smp_mb
#endif

/**
 * What sort of lock is required for proc->fs->lock ?
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
#define talpa_proc_fs_lock   spin_lock
#define talpa_proc_fs_unlock spin_unlock
#else
#define talpa_proc_fs_lock   read_lock
#define talpa_proc_fs_unlock read_unlock
#endif

#endif

/*
 * End of linux_locking.h
 */
