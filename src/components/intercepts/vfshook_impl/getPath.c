/*
 * getPath.c
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

#include <linux/kernel.h>
#include <linux/version.h>

#include "getPath.h"

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unistd.h>

#include <linux/fs.h>

#include "platforms/linux/glue.h"
#include "platforms/linux/alloc.h"
#include "platforms/linux/vfs_mount.h"
#include "platforms/linux/locking.h"
#include "platforms/linux/log.h"

#if defined __GFP_NOWARN && defined __GFP_NORETRY
# define TALPA_MAX_ORDER 3
#else
# define TALPA_MAX_ORDER 0
#endif

char* getPath(struct vfsmount* root, char** pathPtr, int* mnt_orderPtr, size_t* path_size)
{
    unsigned int mnt_order;
    char *path, *name;
    *pathPtr = NULL;
    *mnt_orderPtr = 0;

    /* Allocate storage and build mount point path */
    for (mnt_order = 0; mnt_order <= TALPA_MAX_ORDER; mnt_order++)
    {
        path = talpa_alloc_path_order(mnt_order, path_size);
        /* Fail immediately if allocation failed since chances are low
           the higher order one will succeed. */
        if ( !path )
        {
            dbg("failed to allocate order %u", mnt_order);
            name = ERR_PTR(-ENOMEM);
            break;
        }
        else
        {
            *pathPtr = path; /* save path for freeing later */
        }
        name = talpa_d_path(root->mnt_root, root, path, *path_size);
        if ( IS_ERR(name) )
        {
            talpa_free_path_order(path, mnt_order); *pathPtr = NULL;

            if ( PTR_ERR(name) == -EOVERFLOW )
            {
                /* Try with a larger buffer if there was not enough room for a path */
                dbg("order %u is insufficient", mnt_order);
                continue;
            }
            else
            {
                /* Unexpected failure */
                dbg("unexpected failure %ld", PTR_ERR(name));
                return name;
            }
        }
        else
        {
            /* Success */
            dbg("mount point path %s (%u)", name, mnt_order);
            *mnt_orderPtr = mnt_order;
            return name;
        }
    }

    /* Failed to build mount point path? */
    if ( IS_ERR(name) && PTR_ERR(name) == -EOVERFLOW )
    {
        dbg("max order of %u was insufficient (%ld)", TALPA_MAX_ORDER, PTR_ERR(name));
    }
    return name;
}
