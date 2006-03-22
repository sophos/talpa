/*
 * linux_quirks.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004 Sophos Plc, Oxford, England.
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#else
#include <linux/timer.h>
#endif


#include "common/bool.h"
#include "platform/log.h"
#include "platform/glue.h"



#ifdef TALPA_HAS_XHACK

static inline void talpa_quirk_vc_sleep_init(bool* status)
{
    /* Nasty hack to workaround X not obeying open(2) failing
       with -EINTR caused by smart scheduler in recent versions.
       This is also Linux specific code. */
    if ( *status )
    {
        char c1 = current->comm[0];
        char c2 = current->comm[1];
        if ( likely( (c1 != 'X') || (c2 != 0 ) ) )
        {
            *status = false;
        }
    }
}

static inline void talpa_quirk_vc_pre_sleep(bool* status, unsigned int timeout_ms)
{
    if ( unlikely( *status == true ) )
    {
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
        ktime_t tout = ktime_set(timeout_ms/1000, 0); /* This would be the real nanoseconds calculation
                                                                but we don't care: (timeout_ms%1000)*1000) */

        *status = (hrtimer_forward(&current->signal->real_timer, tout)>0)?true:false;
  #elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)) || defined TALPA_HAS_BACKPORTED_SIGNAL
        *status = mod_timer(&current->signal->real_timer, jiffies + msecs_to_jiffies(1+timeout_ms*2));
  #else
        *status = mod_timer(&current->real_timer, jiffies + msecs_to_jiffies(1+timeout_ms*2));
  #endif
        if ( !*status )
        {
            /* Remove the timer since we have just activated an inactive one */
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
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

  #endif
}

static inline void talpa_quirk_vc_post_sleep(bool* status)
{
    if ( unlikely( *status == true ) )
    {
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
        hrtimer_forward(&current->signal->real_timer, current->signal->it_real_incr);
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

/*
 * End of linux_quirks.h
 */