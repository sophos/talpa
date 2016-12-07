/*
 * ifile_info.h
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
#ifndef H_IFILEINFO
#define H_IFILEINFO

#include <linux/types.h>

#include "common/bool.h"

#include "efilesystem_operation.h"

typedef struct
{
    void                  (*get)                  (const void* self);
    EFilesystemOperation  (*operation)            (const void* self);
    const char*           (*filename)             (const void* self);
    unsigned int          (*flags)                (const void* self);
    unsigned int          (*mode)                 (const void* self);
    unsigned long         (*inode)                (const void* self);
    bool                  (*isWritable)           (const void* self);
    unsigned int          (*isWritableAnywhere)   (const void* self);
    uint64_t              (*device)               (const void* self);
    uint32_t              (*deviceMajor)          (const void* self);
    uint32_t              (*deviceMinor)          (const void* self);
    const char*           (*deviceName)           (const void* self);
    const char*           (*fsType)               (const void* self);
    bool                  (*fsObjects)            (const void* self, void** obj1, void** obj2);
    bool                  (*isDeleted)            (const void* self);
    bool                  (*isNonRootNamespace)   (const void* self);
    bool                  (*isInProcessNamespace) (const void* self);
    /*
     *  Object supporting this interface instance.
     */
    void*                 object;
    void                  (*delete)             (const void* self);
} IFileInfo;

#endif

/*
 * End of ifile_info.h
 */

