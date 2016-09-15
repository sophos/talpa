/*
 * linux_filesysteminfo.h
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
#ifndef H_LINUXFILESYSTEMINFO
#define H_LINUXFILESYSTEMINFO


#include <asm/atomic.h>

#include "filesystem/efilesystem_operation.h"
#include "filesystem/ifilesystem_info.h"

typedef struct tag_LinuxFilesystemInfo
{
    IFilesystemInfo             i_IFilesystemInfo;
    void                        (*delete)(struct tag_LinuxFilesystemInfo* object);
    atomic_t                    mRefCnt;
    EFilesystemOperation        mOperation;
    char*                       mDeviceName;
    char*                       mMountPoint;
    char*                       mType;
    uint64_t                    mDevice;
    uint32_t                    mDeviceMajor;
    uint32_t                    mDeviceMinor;
    int                         mPropagationCount;
} LinuxFilesystemInfo;

/*
 * Object Creators.
 */
LinuxFilesystemInfo* newLinuxFilesystemInfo(EFilesystemOperation operation, const char* dev_name, const char* dir_name, const char* type);

#endif

/*
 * End of linux_filesysteminfo.h
 */

