/*
 * linux_filesysteminfo.c
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
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <asm/uaccess.h>

#include "common/talpa.h"
#include "platforms/linux/alloc.h"
#include "platforms/linux/glue.h"
#include "platforms/linux/vfs_mount.h"
#include "linux_filesysteminfo.h"
#include "filesystem/isystemroot.h"
#include "app_ctrl/iportability_app_ctrl.h"



/*
 * Forward declare implementation methods.
 */
static void                  get                (const void* self);
static EFilesystemOperation  operation          (const void* self);
static const char*           deviceName         (const void* self);
static const char*           mountPoint         (const void* self);
static const char*           type               (const void* self);
static uint64_t              device             (const void* self);
static uint32_t              deviceMajor        (const void* self);
static uint32_t              deviceMinor        (const void* self);
static int                   propagationCount   (const void* self);
static void deleteLinuxFilesystemInfo(struct tag_LinuxFilesystemInfo* object);


/*
 * Template Object.
 */
static LinuxFilesystemInfo template_LinuxFilesystemInfo =
    {
        {
            get,
            operation,
            deviceName,
            mountPoint,
            type,
            device,
            deviceMajor,
            deviceMinor,
            propagationCount,
            NULL,
            (void (*)(const void*))deleteLinuxFilesystemInfo
        },
        deleteLinuxFilesystemInfo,
        ATOMIC_INIT(1),
        0,
        NULL,
        NULL,
        NULL,
        0,
        0,
        0,
        0
    };
#define this    ((LinuxFilesystemInfo*)self)

/* Makes an absolute path from nameidata, and allocates a string for it */
static char* absolutePath(struct dentry *dentry, struct vfsmount *mnt)
{
    char* path;
    size_t path_size = 0;
    char* absolute = NULL;
    ISystemRoot* root;
    char* apath;


    path = talpa_alloc_path(&path_size);

    if ( !path )
    {
        return NULL;
    }

    root = TALPA_Portability()->systemRoot();
    apath = talpa__d_path(dentry, mnt, root->directoryEntry(root->object), root->mountPoint(root->object), path, path_size);

    if (unlikely( apath == NULL ))
    {
        bool isDeleted = false;
        if ( dentry )
        {
            isDeleted = (!IS_ROOT(dentry) && d_unhashed(dentry));
        }
        critical("talpa__d_path failed for mnt=0x%p fstype=%s, dentry=0x%p deleted=%d",
            mnt,
            (const char *)mnt->mnt_sb->s_type->name,
            dentry,
            isDeleted);
    }
    else if (unlikely (IS_ERR(apath)))
    {
        apath = NULL;
    }
    else
    {
        absolute = talpa_alloc(strlen(apath) + 1);
        if ( absolute )
        {
            strcpy(absolute, apath);
        }
    }

    talpa_free_path(path);

    return absolute;
}

static char* copyString(const char* string)
{
    char* copy = NULL;

    if ( string )
    {
        int len = strlen(string) + 1;
        copy = talpa_alloc(len);
        if ( copy )
        {
            memcpy(copy, string, len);
        }
    }

    return copy;
}

/*
 * Object creation/destruction.
 */
LinuxFilesystemInfo* newLinuxFilesystemInfo(EFilesystemOperation operation, const char* dev_name, const char* dir_name, const char* type)
{
    LinuxFilesystemInfo* object;
#ifdef TALPA_HAVE_PATH_LOOKUP
    struct nameidata nd;
#else
    struct path p;
#endif
    struct vfsmount *mnt;
    struct dentry *dentry;
    int rc;

    object = talpa_alloc(sizeof(template_LinuxFilesystemInfo));
    if ( likely(object != NULL) )
    {
        memcpy(object, &template_LinuxFilesystemInfo, sizeof(template_LinuxFilesystemInfo));
        object->i_IFilesystemInfo.object = object;

        object->mOperation = operation;

        /* Two cases, mount and umount. On mount we are receiving all the strings and have very little
           extra work to do. On umount we are receiving just the mount point and will get the other data */

        if ( operation == EFS_Mount )
        {
            object->mType = copyString(type);

            mnt = 0;
            dentry = 0;
#ifdef TALPA_HAVE_PATH_LOOKUP
            rc = talpa_path_lookup(dev_name, TALPA_LOOKUP, &nd);
#else
            rc = kern_path(dev_name, TALPA_LOOKUP, &p);
#endif

            if ( rc == 0 )
            {
                struct inode *inode;
#ifdef TALPA_HAVE_PATH_LOOKUP
                mnt = talpa_nd_mnt(&nd);
                dentry = talpa_nd_dentry(&nd);
#else
                mnt = p.mnt;
                dentry = p.dentry;
#endif

                inode = dentry->d_inode;

                object->mDeviceName = absolutePath(dentry,mnt);

                if (S_ISBLK(inode->i_mode))
                {
                    object->mDevice = kdev_t_to_nr(inode->i_rdev);
                    object->mDeviceMajor = MAJOR(inode->i_rdev);
                    object->mDeviceMinor = MINOR(inode->i_rdev);
                }

#ifdef TALPA_HAVE_PATH_LOOKUP
                talpa_path_release(&nd);
#else
                path_put(&p);
#endif
            }

            if ( !object->mDeviceName )
            {
                dbg("DEBUG: EFS_Mount absolutePath deviceName failed: %s",dev_name);
                object->mDeviceName = copyString(dev_name);
                if ( !object->mDeviceName )
                {
                    goto error;
                }
            }

            if ( dir_name )
            {

                mnt = 0;
                dentry = 0;
#ifdef TALPA_HAVE_PATH_LOOKUP
                rc = talpa_path_lookup(dir_name, TALPA_LOOKUP, &nd);
#else
                rc = kern_path(dir_name, TALPA_LOOKUP, &p);
#endif

                if ( rc == 0 )
                {
#ifdef TALPA_HAVE_PATH_LOOKUP
                    mnt = talpa_nd_mnt(&nd);
                    dentry = talpa_nd_dentry(&nd);
#else
                    mnt = p.mnt;
                    dentry = p.dentry;
#endif

                    object->mMountPoint = absolutePath(dentry,mnt);

#ifdef TALPA_HAVE_PATH_LOOKUP
                    talpa_path_release(&nd);
#else
                    path_put(&p);
#endif
                }

                if ( object->mMountPoint == 0 )
                {
                    dbg("DEBUG: EFS_Mount absolutePath dir_name failed: %s",dir_name);
                    object->mMountPoint = copyString(dir_name);
                }
            }
        }
        else if ( (operation == EFS_Umount) && dir_name )
        {
            const char* mnt_devname;

#ifdef TALPA_HAVE_PATH_LOOKUP
            rc = talpa_path_lookup(dir_name, TALPA_LOOKUP, &nd);
#else
            rc = kern_path(dir_name, TALPA_LOOKUP, &p);
#endif
            if ( unlikely(rc != 0) )
            {
                dbg("DEBUG: EFS_Umount talpa_path_lookup/kern_path failed (%d)", rc);
                goto error;
            }
#ifdef TALPA_HAVE_PATH_LOOKUP
            mnt = talpa_nd_mnt(&nd);
            dentry = talpa_nd_dentry(&nd);
#else
            mnt = p.mnt;
            dentry = p.dentry;
#endif

            if ( dentry != mnt->mnt_root )
            {
                dbg("DEBUG: EFS_Umount dentry != mnt->mnt_root");
                goto error2;
            }

            object->mMountPoint = absolutePath(dentry,mnt);

            if ( object->mMountPoint == 0 )
            {
                dbg("DEBUG: EFS_Umount absolutePath dir_name failed");
                object->mMountPoint = copyString(dir_name);
                if ( !object->mMountPoint )
                {
                    goto error2;
                }
            }

            mnt_devname = getDeviceName(mnt);
            if ( mnt_devname )
            {
                if ( mnt->mnt_sb->s_bdev )
                {
#ifdef TALPA_HAVE_PATH_LOOKUP
                    struct nameidata dnd;
#else
                    struct path dp;
#endif
                    struct vfsmount *dmnt;
                    struct dentry *ddentry;

#ifdef TALPA_HAVE_PATH_LOOKUP
                    rc = talpa_path_lookup(mnt_devname, TALPA_LOOKUP, &dnd);
#else
                    rc = kern_path(mnt_devname, TALPA_LOOKUP, &dp);
#endif
                    if ( rc == 0 )
                    {
                        struct inode *inode;


#ifdef TALPA_HAVE_PATH_LOOKUP
                        dmnt = talpa_nd_mnt(&dnd);
                        ddentry = talpa_nd_dentry(&dnd);
#else
                        dmnt = dp.mnt;
                        ddentry = dp.dentry;
#endif
                        inode = ddentry->d_inode;
                        object->mDeviceName = absolutePath(ddentry,dmnt);

                        if (S_ISBLK(inode->i_mode))
                        {
                            object->mDevice = kdev_t_to_nr(inode->i_rdev);
                            object->mDeviceMajor = MAJOR(kdev_t_to_nr(inode->i_rdev));
                            object->mDeviceMinor = MINOR(kdev_t_to_nr(inode->i_rdev));
                        }

#ifdef TALPA_HAVE_PATH_LOOKUP
                        talpa_path_release(&dnd);
#else
                        path_put(&dp);
#endif
                    }
                }

                if ( !object->mDeviceName )
                {
                    dbg("DEBUG: EFS_Umount absolutePath mnt_devname failed");
                    object->mDeviceName = copyString(mnt_devname);
                    if ( !object->mDeviceName )
                    {
                        goto error2;
                    }
                }
            }

            if ( mnt->mnt_sb->s_type->name )
            {
                object->mType = copyString(mnt->mnt_sb->s_type->name);
            }

            if ( !object->mType )
            {
                object->mType = copyString(type);
            }

            dbg("Device %s resolved from mount point %s - %s", object->mDeviceName, object->mMountPoint, object->mType);

            object->mPropagationCount = countPropagationPoints(mnt);

#ifdef TALPA_HAVE_PATH_LOOKUP
            talpa_path_release(&nd);
#else
            path_put(&p);
#endif
        }
        else
        {
            dbg("DEBUG: unknown operation");
            goto error;
        }


        dbg("NAME:%s MAJOR:%u MINOR:%u",object->mDeviceName, object->mDeviceMajor, object->mDeviceMinor);
    }
    else
    {
        err("talpa_alloc() failed");
    }

    return object;

    error2:
#ifdef TALPA_HAVE_PATH_LOOKUP
    talpa_path_release(&nd);
#else
    path_put(&p);
#endif
    error:
    talpa_free(object->mDeviceName);
    talpa_free(object->mMountPoint);
    talpa_free(object->mType);
    talpa_free(object);

    return NULL;
}

static void deleteLinuxFilesystemInfo(struct tag_LinuxFilesystemInfo* object)
{
    if ( atomic_dec_and_test(&object->mRefCnt) )
    {
        talpa_free(object->mDeviceName);
        talpa_free(object->mMountPoint);
        talpa_free(object->mType);
        talpa_free(object);
    }
    return;
}

/*
 * IFilesystemInfo.
 */
static void get(const void* self)
{
    atomic_inc(&this->mRefCnt);
    return;
}

static EFilesystemOperation  operation(const void* self)
{
    return this->mOperation;
}

static const char* deviceName(const void* self)
{
    return this->mDeviceName;
}

static const char* mountPoint(const void* self)
{
    return this->mMountPoint;
}

static const char* type(const void* self)
{
    return this->mType;
}

static uint64_t device(const void* self)
{
    return this->mDevice;
}

static uint32_t deviceMajor(const void* self)
{
    return this->mDeviceMajor;
}

static uint32_t deviceMinor(const void* self)
{
    return this->mDeviceMinor;
}

static int propagationCount(const void* self)
{
    return this->mPropagationCount;
}

/*
 * End of linux_filesysteminfo.c
 */

