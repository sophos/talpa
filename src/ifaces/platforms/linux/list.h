/*
 * linux_list.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2019 Sophos Limited, Oxford, England.
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
#ifndef H_LINUXLIST
#define H_LINUXLIST

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/rcupdate.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,10) || defined TALPA_BACKPORTED_PREFETCH
#include <linux/prefetch.h>
#else
static inline void prefetch(const void *x) {;}
#endif


#ifndef list_for_each_safe
/**
 * list_for_each_safe   -   iterate over a list safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop counter.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
        pos = n, n = pos->next)
#endif

#ifndef list_for_each_entry
/**
 * list_for_each_entry  -   iterate over list of given type
 * @pos:    the type * to use as a loop counter.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)              \
    for (pos = list_entry((head)->next, typeof(*pos), member),  \
             prefetch(pos->member.next);            \
         &pos->member != (head);                    \
         pos = list_entry(pos->member.next, typeof(*pos), member),  \
             prefetch(pos->member.next))
#endif


#ifndef list_for_each_entry_safe
/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:    the type * to use as a loop counter.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)          \
    for (pos = list_entry((head)->next, typeof(*pos), member),  \
        n = list_entry(pos->member.next, typeof(*pos), member); \
         &pos->member != (head);                    \
         pos = n, n = list_entry(n->member.next, typeof(*n), member))
#endif


typedef struct list_head talpa_list_head;

#define TALPA_INIT_LIST_HEAD    INIT_LIST_HEAD
#define TALPA_LIST_HEAD_INIT    LIST_HEAD_INIT

#define talpa_list_add          list_add
#define talpa_list_add_tail     list_add_tail
#define talpa_list_del          list_del
#define talpa_list_move         list_move

#define talpa_list_for_each             list_for_each
#define talpa_list_for_each_safe        list_for_each_safe
#define talpa_list_for_each_entry       list_for_each_entry
#define talpa_list_for_each_entry_safe  list_for_each_entry_safe

#define talpa_list_empty    list_empty
#define talpa_list_entry    list_entry

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#define talpa_list_add_rcu        list_add_rcu
#define talpa_list_add_tail_rcu   list_add_tail_rcu
#define talpa_list_del_rcu        list_del_rcu

#define talpa_list_for_each_rcu           list_for_each_rcu
#define talpa_list_for_each_safe_rcu      list_for_each_safe_rcu
#define talpa_list_for_each_entry_rcu     list_for_each_entry_rcu
#define talpa_list_for_each_continue_rcu  list_for_each_continue_rcu

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) */

#define talpa_list_add_rcu        list_add
#define talpa_list_add_tail_rcu   list_add_tail
#define talpa_list_del_rcu        list_del

#define talpa_list_for_each_rcu           list_for_each
#define talpa_list_for_each_safe_rcu      list_for_each_safe
#define talpa_list_for_each_entry_rcu     list_for_each_entry
#define talpa_list_for_each_continue_rcu  list_for_each_continue


#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

/**
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({          \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

typedef struct rcu_head talpa_rcu_head;

#define TALPA_RCU_INIT              RCU_HEAD_INIT
#define talpa_rcu_init(x)           INIT_RCU_HEAD(x)
#define talpa_rcu_call(head, func)  call_rcu(head, func)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32))
#define talpa_rcu_synchronize       synchronize_rcu
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)) || defined TALPA_HAS_BACKPORTED_RCU
#define talpa_rcu_synchronize       synchronize_sched
#else
#define talpa_rcu_synchronize       synchronize_kernel
#endif

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) */

typedef  unsigned int talpa_rcu_head;

#define TALPA_RCU_INIT              (0)
#define talpa_rcu_init(x)           do { } while(0)
#define talpa_rcu_call(head, func)  func(head)
#define talpa_rcu_synchronize       schedule

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) */



#endif

/*
 * End of list.h
 */
