/*
 * linux_threadinfo.h
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
#ifndef H_LINUXTHREADINFO
#define H_LINUXTHREADINFO

#include <linux/types.h>
#include <asm/atomic.h>


#include "process_and_thread/ithreadinfo.h"

typedef struct tag_LinuxThreadInfo
{
    IThreadInfo                 i_IThreadInfo;
    void                        (*delete)(struct tag_LinuxThreadInfo* object);
    atomic_t                    mRefCnt;
    pid_t                       mPID;
    pid_t                       mTID;
    unsigned long               mEnvSize;
    unsigned char*              mEnv;
    unsigned long               mTTY;
    char*                       mPath;
    char*                       mRootDir;
    struct dentry*              mRootDentry;
    struct vfsmount*            mRootMount;
    void*                       mUtsNamespace;
} LinuxThreadInfo;

/*
 * Object Creators.
 */
extern LinuxThreadInfo* newLinuxThreadInfo(void);

#endif

/*
 * End of linux_threadinfo.h
 */

