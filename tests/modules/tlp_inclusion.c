/*
 * tlp-inclusion.c
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
#include <linux/limits.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/errno.h>

#include "tlp-test.h"


#include "common/bool.h"
#define TALPA_SUBSYS "inclusiontest"
#include "common/talpa.h"

#include "components/services/linux_personality_impl/linux_personality.h"
#include "components/services/linux_filesystem_impl/linux_fileinfo.h"
#include "components/services/linux_filesystem_impl/linux_filesysteminfo.h"
#include "components/core/intercept_filters_impl/fsobj_incl/filesystem_inclusion_processor.h"
#include "components/core/intercept_processing_impl/evaluation_report_impl.h"
#include "components/services/linux_filesystem_impl/linux_systemroot.h"
#include "app_ctrl/iportability_app_ctrl.h"

static ISystemRoot* systemRoot(void);
static LinuxSystemRoot* mSystemRoot;

/*
 * Singleton Object.
 */
static IPortabilityApplicationControl GL_talpa_linux =
    {
        NULL,
        systemRoot,
        NULL,
        NULL,
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

FilesystemInclusionProcessor *inclusion;
EvaluationReportImpl *erep;

char GL_path[PATH_MAX];

static struct talpa_file tf;
static struct talpa_filesystem tfs;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
long talpa_ioctl(struct file *file, unsigned int cmd, unsigned long parm)
#else
int talpa_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long parm)
#endif
{
    int ret = -ENOTTY;

    LinuxPersonality *pers;
    LinuxFileInfo *fi;
    LinuxFilesystemInfo *fsi;

    pers = newLinuxPersonality();

    inclusion->i_IInterceptFilter.enable(inclusion);
    erep->i_IEvaluationReport.setRecommendedAction(erep, EIA_Next);

    switch ( cmd )
    {
        case TALPA_TEST_INCL_SETPATH:
                ret = strnlen_user((char *)parm, PATH_MAX);
                if ( ret > 0 )
                {
                    ret = copy_from_user(GL_path, (void *)parm, ret); /* includes null-terminator! */
                    if ( !ret )
                    {
                        inclusion->setPath(inclusion, GL_path);
                    }
                }
                break;
        case TALPA_TEST_FILEINFO:
            ret = copy_from_user(&tf, (void *)parm, sizeof(struct talpa_file));
            if ( !ret )
            {
                fi = newLinuxFileInfo(tf.operation, tf.name, 0, 0);
                if ( fi )
                {
                    inclusion->i_IInterceptFilter.examineFile(inclusion, &erep->i_IEvaluationReport, &pers->i_IPersonality, &fi->i_IFileInfo, NULL);
                    fi->delete(fi);
                    ret = erep->i_IEvaluationReport.recommendedAction(erep);
                }
                else
                {
                    err("Failed to create IFileInfo!");
                    ret = -EINVAL;
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
                fsi = newLinuxFilesystemInfo(tfs.operation, tfs.dev, tfs.target, tfs.type);
                if ( fsi )
                {
                    inclusion->i_IInterceptFilter.examineFilesystem(inclusion, &erep->i_IEvaluationReport, &pers->i_IPersonality, &fsi->i_IFilesystemInfo);
                    fsi->delete(fsi);
                    ret = erep->i_IEvaluationReport.recommendedAction(erep);
                }
                else
                {
                    err("Failed to create IFilesystemInfo!");
                    ret = -EINVAL;
                }
            }
            else
            {
                err("copy_from_user!");
            }
            break;
    }

    pers->delete(pers);

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

    inclusion = newFilesystemInclusionProcessor();

    if ( !inclusion )
    {
        err("Failed to create filesystem inclusion processor!");
        mSystemRoot->delete(mSystemRoot);
        return 1;
    }

    erep = newEvaluationReportImpl(0);

    if ( !erep )
    {
        err("Failed to create evaluation report!");
        inclusion->delete(inclusion);
        mSystemRoot->delete(mSystemRoot);
        return 1;
    }


    ret = register_chrdev(TALPA_MAJOR, TALPA_DEVICE, &talpa_fops);

    if ( ret )
    {
        err("Failed to register TALPA Test character device!");
        erep->delete(erep);
        inclusion->delete(inclusion);
        mSystemRoot->delete(mSystemRoot);
        return ret;
    }

    return 0;
}

static void __exit talpa_test_exit(void)
{
    int ret;

    erep->delete(erep);
    inclusion->delete(inclusion);
    mSystemRoot->delete(mSystemRoot);

    ret = talpa_unregister_chrdev(TALPA_MAJOR, TALPA_DEVICE);

    if ( ret )
    {
        err("Hmmmmmm... very strange things are happening!");
    }
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

