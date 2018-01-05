/*
 * linux_quirks.h
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
#ifndef H_LINUXQUIRKS
#define H_LINUXQUIRKS

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16) || defined TALPA_HAS_HRTIMERS
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#else
#include <linux/timer.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
# include <linux/sched/signal.h>
#endif

#include "common/bool.h"
#include "platform/log.h"
#include "platform/glue.h"

#ifdef TALPA_HAS_HRTIMERS
  #ifdef TALPA_HAS_HRTIMERS_V21
    #define TALPA_HRTIMER_REL HRTIMER_MODE_REL
  #else
    #define TALPA_HRTIMER_REL HRTIMER_REL
  #endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
  #define TALPA_HRTIMER_REL HRTIMER_MODE_REL
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
  #define TALPA_HRTIMER_REL HRTIMER_REL
#endif

#ifdef TALPA_HAS_XHACK
static inline void talpa_quirk_vc_sleep_init(bool* status)
{
    /* Nasty hack to workaround X not obeying open(2) failing
       with -EINTR caused by smart scheduler in recent versions.
       This is also Linux specific code. */
    if ( *status )
    {
        struct task_struct *cur = current;
        const char xfree[] = "X";
        const char xorg[] = "Xorg";
        __u16 *p16 = (__u16 *)xfree;
        __u16 *comm16 = (__u16 *)cur->comm;
        __u32 *p32 = (__u32 *)xorg;
        __u32 *comm32 = (__u32 *)cur->comm;

        if ( likely( (*p16 != *comm16) && (*p32 != *comm32) ) )
        {
            *status = false;
        }
    }
}

static inline void talpa_quirk_vc_pre_sleep(bool* status, unsigned int timeout_ms)
{
    if ( unlikely( *status == true ) )
    {
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16) || defined TALPA_HAS_HRTIMERS
        *status = (hrtimer_cancel(&current->signal->real_timer)==1)?true:false;
  #elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)) || defined TALPA_HAS_BACKPORTED_SIGNAL
        *status = mod_timer(&current->signal->real_timer, jiffies + msecs_to_jiffies(1+timeout_ms*2));
  #else
        *status = mod_timer(&current->real_timer, jiffies + msecs_to_jiffies(1+timeout_ms*2));
  #endif

        if ( !*status )
        {
            /* Remove the timer since we have just activated an inactive one */
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16) || defined TALPA_HAS_HRTIMERS
            /* No-op */
  #elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)) || defined TALPA_HAS_BACKPORTED_SIGNAL
            del_timer(&current->signal->real_timer);
  #else
            del_timer(&current->real_timer);
  #endif
        }
        else
        {
            dbg("X workaround activated!");
        }
    }
}

static inline void talpa_quirk_vc_post_sleep(bool* status)
{
    if ( unlikely( *status == true ) )
    {
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16) || defined TALPA_HAS_HRTIMERS
        hrtimer_start(&current->signal->real_timer, current->signal->it_real_incr, TALPA_HRTIMER_REL);
  #elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)) || defined TALPA_HAS_BACKPORTED_SIGNAL
        mod_timer(&current->signal->real_timer, jiffies + current->signal->it_real_incr);

  #else
        mod_timer(&current->real_timer, jiffies + current->it_real_incr);

  #endif
    }
}

#else

static inline void talpa_quirk_vc_sleep_init(bool* status) { };
static inline void talpa_quirk_vc_pre_sleep(bool* status, unsigned int timeout_ms) { };
static inline void talpa_quirk_vc_post_sleep(bool* status) { };

#endif /* XHACK */


#endif
/*
 * End of linux_quirks.h
 */
