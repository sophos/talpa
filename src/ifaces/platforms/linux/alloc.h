/*
 * alloc.h
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
#ifndef H_ALLOC
#define H_ALLOC

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include "platform/compiler.h"


static inline void *talpa_alloc(size_t bytes)
{
    return kmalloc(bytes, GFP_KERNEL);
}

static inline void *talpa_zalloc(size_t bytes)
{
    void *ptr;

    ptr =  talpa_alloc(bytes);

    if ( likely( ptr != NULL ) )
    {
        memset(ptr, 0, bytes);
    }

    return ptr;
}

static inline void talpa_free(void *ptr)
{
    kfree(ptr);
}

static inline void *talpa_large_alloc(size_t bytes)
{
    return vmalloc(bytes);
}

static inline void talpa_large_free(void *ptr)
{
    if ( unlikely(ptr == NULL) )
    {
        return;
    }

    vfree(ptr);
}

static inline char *talpa_alloc_path_order(unsigned int order, size_t *size)
{
    unsigned int mask = GFP_KERNEL;


    if ( unlikely(order > 0) )
    {
#ifdef __GFP_NOWARN
        mask |= __GFP_NOWARN;
#endif

#ifdef __GFP_NORETRY
        mask |= __GFP_NORETRY;
#endif
    }

    *size = PAGE_SIZE<<order;

    return (char *)__get_free_pages(mask, order);
}

static inline void talpa_free_path_order(char *buf, unsigned int order)
{
    if ( unlikely(buf == NULL) )
    {
        return;
    }

    free_pages((unsigned long)buf, order);
}

static inline char *talpa_alloc_path(size_t *size)
{
    *size = PAGE_SIZE;

    return (char *)__get_free_pages(GFP_KERNEL, 0);
}

static inline char *talpa_alloc_path_atomic(size_t *size)
{
    *size = PAGE_SIZE;

    return (char *)__get_free_pages(GFP_ATOMIC, 0);
}

static inline void talpa_free_path(char *buf)
{
    if ( likely(buf != NULL) )
    {
        free_pages((unsigned long)buf, 0);
    }
}

#endif
/*
 * End of alloc.h
 */
