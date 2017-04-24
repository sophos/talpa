/*
 * linux_fileinfo.h
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
#ifndef H_LINUXFILEINFO
#define H_LINUXFILEINFO

#include <asm/atomic.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/unistd.h>


#include "filesystem/efilesystem_operation.h"
#include "filesystem/ifile_info.h"

typedef struct tag_LinuxFileInfo
{
    IFileInfo                   i_IFileInfo;
    void                        (*delete)(struct tag_LinuxFileInfo* object);
    atomic_t                    mRefCnt;
    EFilesystemOperation        mOperation;
    char*                       mFilename;
    int                         mFlags;
    int                         mMode;
    unsigned long               mIno;
    unsigned int                mWriteCount;
    struct inode*               mInode;
    struct dentry*              mDentry;
    struct vfsmount*            mVFSMount;
    uint64_t                    mDevice;
    uint32_t                    mDeviceMajor;
    uint32_t                    mDeviceMinor;
    char*                       mPath;
    char*                       mDeviceName;
    char*                       mFSType;
    bool                        mIsNonRootNamespace;
    bool                        mIsInProcessMntNamespace;
} LinuxFileInfo;

/*
 * Object Creators.
 */
extern LinuxFileInfo* newLinuxFileInfo(EFilesystemOperation operation, const char* filename, int flags, int mode);
extern LinuxFileInfo* newLinuxFileInfoFromFd(EFilesystemOperation operation, int fd);
extern LinuxFileInfo* newLinuxFileInfoFromFile(EFilesystemOperation operation, void* fileobj);
extern LinuxFileInfo* newLinuxFileInfoFromDirectoryEntry(EFilesystemOperation operation, void* dentryobj, void* mntobj, int flags, int mode);
extern LinuxFileInfo* newLinuxFileInfoFromInode(EFilesystemOperation operation, void* inode, int flags);

#endif

/*
 * End of linux_fileinfo.h
 */
