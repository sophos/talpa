/*
 * ifile.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
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
#ifndef H_IFILE
#define H_IFILE

#include <linux/types.h>

#include "common/bool.h"

typedef struct
{
    void    (*get)          (void* self);
    int     (*open)         (void* self, const char* filename, unsigned int flags, bool check_permissions);
    int     (*openDentry)   (void* self, void* object1, void* object2, unsigned int flags, bool check_permissions);
    int     (*openExec)     (void* self, const char* filename);
    bool    (*isOpen)       (const void* self);
    bool    (*isWritable)   (const void* self);
    int     (*close)        (void* self);
    loff_t  (*length)       (const void* self);
    loff_t  (*seek)         (void* self, loff_t offset, int whence);
    ssize_t (*read)         (void* self, void __user * data, size_t count);
    ssize_t (*write)        (void* self, const void __user * data, size_t count);
    int     (*unlink)       (void* self);
    int     (*truncate)     (void* self, loff_t);
    /*
     *  Object supporting this interface instance.
     */
    void*                 object;
    void                  (*delete)             (void* self);
} IFile;

#endif

/*
 * End of ifile.h
 */

