/*
 * vfs_mount.h
 *
 * TALPA Platform code
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

#ifndef H_VFS_MOUNT
#define H_VFS_MOUNT

#include <linux/kernel.h>
#include <linux/version.h>
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/mount.h>

#include "platforms/linux/bool.h"
#include "platforms/linux/alloc.h"
#include "platforms/linux/glue.h"
#include "platforms/linux/locking.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
 #define TALPA_REPLACE_MOUNT_STRUCT
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
 #define TALPA_MNT_NAMESPACE
#endif

int countPropagationPoints(struct vfsmount* mnt);

struct vfsmount* getParent(struct vfsmount* mnt);

int iterateFilesystems(struct vfsmount* root, int (*callback) (struct vfsmount* mnt, unsigned long flags, bool fromMount));

/**
 * @return borrowed reference to device name
 */
const char *getDeviceName(struct vfsmount* mnt);

#ifdef TALPA_MNT_NAMESPACE
struct mnt_namespace *getNamespaceInfo(struct vfsmount * mnt);
#endif

struct dentry *getVfsMountPoint(struct vfsmount* mnt);

#endif /* H_VFS_MOUNT */
