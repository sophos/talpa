/*
 * tlp-stdinterceptor.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2017 Sophos Limited, Oxford, England.
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/errno.h>

#include "tlp-test.h"

#include "platform/uaccess.h"

#include "common/bool.h"
#define TALPA_SUBSYS "stdinterceptor"
#include "common/talpa.h"

#include "components/core/intercept_processing_impl/std_intercept_processor.h"
#include "components/services/linux_personality_impl/linux_personality.h"
#include "components/services/linux_filesystem_impl/linux_systemroot.h"
#include "components/services/linux_filesystem_impl/linux_file.h"
#include "components/services/linux_filesystem_impl/linux_fileinfo.h"
#include "components/services/linux_filesystem_impl/linux_filesysteminfo.h"
#include "components/core/intercept_processing_impl/evaluation_report_impl.h"
#include "components/services/linux_filesystem_impl/linux_filesystem_factoryimpl.h"
#include "components/services/linux_personality_impl/linux_personality_factoryimpl.h"

#include "app_ctrl/iportability_app_ctrl.h"

/*
 * Forward declarations.
 */
static ISystemRoot* systemRoot(void);
static IFilesystemFactory*  filesystemFactory(void);
static IPersonalityFactory* personalityFactory(void);

static LinuxSystemRoot* mSystemRoot;
static StandardInterceptProcessor* mProcessor;

/*
 * Singleton Object.
 */
static IPortabilityApplicationControl GL_talpa_linux =
    {
        NULL,
        systemRoot,
        filesystemFactory,
        personalityFactory,
        NULL
    };

const IPortabilityApplicationControl* TALPA_Portability(void)
{
    return &GL_talpa_linux;
}

static ISystemRoot* systemRoot(void)
{
    return &mSystemRoot->i_ISystemRoot;
}

static IFilesystemFactory* filesystemFactory(void)
{
    return &(newLinuxFilesystemFactoryImpl()->i_IFilesystemFactory);
}

static IPersonalityFactory* personalityFactory(void)
{
    return &(newLinuxPersonalityFactoryImpl()->i_IPersonalityFactory);
}

typedef struct tag_TestFilter
{
    IInterceptFilter            i_IInterceptFilter;
    void                        (*delete)(struct tag_TestFilter* object);
    bool                        mEnabled;
    EInterceptAction            mAction;
} TestFilter;

static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);
static bool isEnabled(const void* self);
static void deleteTestFilter(struct tag_TestFilter* object);
static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);

static TestFilter template_TestFilter =
    {
        {
            examineFile,
            NULL,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            0,
            (void (*)(void*))deleteTestFilter
        },
        deleteTestFilter,
        true,
        EIA_Next
    };
#define this    ((TestFilter*)self)


/*
 * Object creation/destruction.
 */
TestFilter* newTestFilter(EInterceptAction action)
{
    TestFilter* object;


    object = kmalloc(sizeof(template_TestFilter), GFP_KERNEL);
    if (object != 0)
    {
        memcpy(object, &template_TestFilter, sizeof(template_TestFilter));
        object->i_IInterceptFilter.object = object;
        object->mAction = action;
    }
    return object;
}

static void deleteTestFilter(struct tag_TestFilter* object)
{
    if (object != 0)
    {
        kfree(object);
    }
    return;
}

/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    if (this->mEnabled)
    {
        report->setRecommendedAction(report, this->mAction);
        if ( report->recommendedAction(report) == EIA_Error )
        {
            report->setErrorCode(report, 0xdeadbeef);
        }
    }
    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info)
{
    if (this->mEnabled)
    {
        report->setRecommendedAction(report, this->mAction);
        if ( report->recommendedAction(report) == EIA_Error )
        {
            report->setErrorCode(report, 0xdeadbeef);
        }
    }
    return;
}

static void purgeEvaluationFilters(StandardInterceptProcessor* mProcessor)
{
    struct list_head*   posptr;
    struct list_head*   nptr;
    FilterEntry*        fe;
    IInterceptFilter*   filter;

    list_for_each_safe(posptr, nptr, &mProcessor->mEvaluationActions)
    {
        list_del(posptr);
        fe = list_entry(posptr, FilterEntry, list);
        filter = fe->filter;
        filter->delete(filter);
        kfree(fe);
    }
    return;
}

static void purgeAllowFilters(StandardInterceptProcessor* mProcessor)
{
    struct list_head*   posptr;
    struct list_head*   nptr;
    FilterEntry*        fe;
    IInterceptFilter*   filter;

    list_for_each_safe(posptr, nptr, &mProcessor->mAllowActions)
    {
        list_del(posptr);
        fe = list_entry(posptr, FilterEntry, list);
        filter = fe->filter;
        filter->delete(filter);
        kfree(fe);
    }
    return;
}

static void purgeDenyFilters(StandardInterceptProcessor* mProcessor)
{
    struct list_head*   posptr;
    struct list_head*   nptr;
    FilterEntry*        fe;
    IInterceptFilter*   filter;

    list_for_each_safe(posptr, nptr, &mProcessor->mDenyActions)
    {
        list_del(posptr);
        fe = list_entry(posptr, FilterEntry, list);
        filter = fe->filter;
        filter->delete(filter);
        kfree(fe);
    }
    return;
}

static struct talpa_file tf;
static struct talpa_filesystem tfs;

/*
 * Test ioctl interface.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
long talpa_ioctl(struct file *file, unsigned int cmd, unsigned long parm)
#else
int talpa_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long parm)
#endif
{
    int ret = -ENOTTY;
    LinuxFileInfo *fi;
    LinuxFilesystemInfo *fsi;
    TestFilter* filter;

    switch ( cmd )
    {
        case TALPA_TEST_STDINT_EVALFILTER:
            filter = newTestFilter(parm);
            if ( filter )
            {
                mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &filter->i_IInterceptFilter);
                ret = 0;
            }
            else
            {
                err("Failed to create filter!");
                ret = -ENOMEM;
            }
            break;
        case TALPA_TEST_STDINT_ALLOWFILTER:
            filter = newTestFilter(parm);
            if ( filter )
            {
                mProcessor->i_IInterceptProcessor.addAllowFilter(mProcessor, &filter->i_IInterceptFilter);
                ret = 0;
            }
            else
            {
                err("Failed to create filter!");
                ret = -ENOMEM;
            }
            break;
        case TALPA_TEST_STDINT_DENYFILTER:
            filter = newTestFilter(parm);
            if ( filter )
            {
                mProcessor->i_IInterceptProcessor.addDenyFilter(mProcessor, &filter->i_IInterceptFilter);
                ret = 0;
            }
            else
            {
                err("Failed to create filter!");
                ret = -ENOMEM;
            }
            break;
        case TALPA_TEST_STDINT_PURGEFILTERS:
            purgeEvaluationFilters(mProcessor);
            purgeAllowFilters(mProcessor);
            purgeDenyFilters(mProcessor);
            ret = 0;
            break;
        case TALPA_TEST_FILEINFO:
            ret = copy_from_user(&tf, (void *)parm, sizeof(struct talpa_file));
            if ( !ret )
            {
                fi = newLinuxFileInfo(tf.operation, tf.name, 0, 0);
                if ( fi )
                {
                    ret = mProcessor->i_IInterceptProcessor.examineFileInfo(mProcessor, &fi->i_IFileInfo, NULL);
                    fi->delete(fi);
                }
                else
                {
                    err("Failed to create IFileInfo!");
                    ret = -ENOMEM;
                }
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_FILESYSTEMINFO:
            ret = copy_from_user(&tfs, (void *)parm, sizeof(struct talpa_filesystem));
            if ( !ret )
            {
                /* err("dev=%s, target=%s, type=%s",tfs.dev, tfs.target, tfs.type); */
                fsi = newLinuxFilesystemInfo(tfs.operation, tfs.dev, tfs.target, tfs.type);
                if ( fsi )
                {
                    ret = mProcessor->i_IInterceptProcessor.examineFilesystemInfo(mProcessor, &fsi->i_IFilesystemInfo);
                    fsi->delete(fsi);
                }
                else
                {
                    err("Failed to create IFilesystemInfo!");
                    ret = -ENOMEM;
                }
            }
            else
            {
                err("copy_from_user!");
            }
            break;
    }

    return ret;
}

struct file_operations talpa_fops =
{
    owner:  THIS_MODULE,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
    unlocked_ioctl:  talpa_ioctl
#else
    ioctl:  talpa_ioctl
#endif
};

static int __init talpa_test_init(void)
{
    int ret;

    mSystemRoot = newLinuxSystemRoot();
    if (mSystemRoot == 0)
    {
        err("Failed to create system root");
        return -ENOMEM;
    }

    mProcessor = newStandardInterceptProcessor();
    if (mProcessor == 0)
    {
        mSystemRoot->delete(mSystemRoot);
        err("Failed to allocate processor");
        return -ENOMEM;
    }

    ret = register_chrdev(TALPA_MAJOR, TALPA_DEVICE, &talpa_fops);

    if ( ret )
    {
        err("Failed to register TALPA Test character device!");
        mProcessor->delete(mProcessor);
        mSystemRoot->delete(mSystemRoot);
        return ret;
    }

    return 0;
}

static void __exit talpa_test_exit(void)
{
    int ret;

    purgeEvaluationFilters(mProcessor);
    purgeAllowFilters(mProcessor);
    purgeDenyFilters(mProcessor);
    mProcessor->delete(mProcessor);
    mSystemRoot->delete(mSystemRoot);

    ret = talpa_unregister_chrdev(TALPA_MAJOR, TALPA_DEVICE);

    if ( ret )
    {
        err("Hmmmmmm... very strange things are happening!");
    }
}

static bool enable(void* self)
{
    if (!this->mEnabled)
    {
        this->mEnabled = true;
    }
    return true;
}

static void disable(void* self)
{
    if (this->mEnabled)
    {
        this->mEnabled = false;
    }
    return;
}

static bool isEnabled(const void* self)
{
    return this->mEnabled;
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Limited");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Test Module");
MODULE_LICENSE("GPL");

module_init(talpa_test_init);
module_exit(talpa_test_exit);
