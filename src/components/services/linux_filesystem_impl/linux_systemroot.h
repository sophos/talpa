/*
 * linux_systemroot.h
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
#ifndef H_LINUXSYSTEMROOT
#define H_LINUXSYSTEMROOT


#include "filesystem/isystemroot.h"

typedef struct tag_LinuxSystemRoot
{
    ISystemRoot         i_ISystemRoot;
    void                (*delete)(struct tag_LinuxSystemRoot* object);

    struct dentry*      mDentry;
    struct vfsmount*    mMnt;
    void*               mUtsNamespace;
} LinuxSystemRoot;

/*
 * Object Creators.
 */
LinuxSystemRoot* newLinuxSystemRoot(void);

#endif

/*
 * End of linux_systemroot.h
 */

