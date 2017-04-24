/*
 * talpa_core_module.c
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

/*
 * Standard headers for LKMs
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kernel.h>

#include <asm/errno.h>


#include "common/bool.h"
#define TALPA_SUBSYS "core"
#include "common/talpa.h"
#include "components/core/intercept_processing_impl/std_intercept_processor.h"
#include "components/core/intercept_filters_impl/syslog/syslog_filter.h"
#include "components/core/intercept_filters_impl/deny_syslog/deny_syslog.h"
#include "components/core/intercept_filters_impl/allow_syslog/allow_syslog.h"
#include "components/core/intercept_filters_impl/fsobj_incl/filesystem_inclusion_processor.h"
#include "components/core/intercept_filters_impl/fsobj_excl/filesystem_exclusion_processor.h"
#include "components/core/intercept_filters_impl/operation_excl/operation_excl.h"
#include "components/core/intercept_filters_impl/vetting_ctrl/vetting_ctrl.h"
#include "components/core/intercept_filters_impl/proc_excl/process_exclusion.h"
#include "components/core/intercept_filters_impl/degraded_mode/degraded_mode.h"
#include "components/core/cache_impl/cache.h"
#include "components/core/intercept_filters_impl/cache/cache_eval.h"
#include "components/core/intercept_filters_impl/cache/cache_allow.h"
#include "components/core/intercept_filters_impl/cache/cache_deny.h"

#include "configurator/iconfigurator.h"

#include "app_ctrl/icore_app_ctrl.h"
#include "app_ctrl/iportability_app_ctrl.h"

/*
 * Forward declarations.
 */
static IInterceptProcessor* interceptProcessor(void);
static IVettingServer*      vettingServer(void);
static IProcessExcluder*    processExcluder(void);

#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

#ifdef TALPA_VERSION
const char talpa_version[] = "$TALPA_VERSION:" TALPA_VERSION;
#endif

/*
 * Instance data.
 */
static StandardInterceptProcessor*      mProcessor;
static SyslogFilter*                    mDebugSyslog;
static DenySyslogFilter*                mDenySyslog;
static AllowSyslogFilter*               mAllowSyslog;
static FilesystemInclusionProcessor*    mInclusion;
static FilesystemExclusionProcessor*    mExclusion;
static OperationExclusionProcessor*     mOpExcl;
static ProcessExclusionProcessor*       mProcExcl;
static DegradedModeProcessor*           mDegrMode;
static VettingController*               mVetCtrl;
static Cache*                           mCache;
static CacheEval*                       mCacheEval;
static CacheAllow*                      mCacheAllow;
static CacheDeny*                       mCacheDeny;

static IConfigurator*                   mConfig;

/*
 * Singleton Object.
 */
static ICoreApplicationControl GL_talpa_core =
    {
        interceptProcessor,
        vettingServer,
        processExcluder
    };

const ICoreApplicationControl* TALPA_Core(void)
{
    return &GL_talpa_core;
}

static IInterceptProcessor* interceptProcessor(void)
{
    return &mProcessor->i_IInterceptProcessor;
}

static IVettingServer* vettingServer(void)
{
    return &mVetCtrl->i_IVettingServer;
}

static IProcessExcluder* processExcluder(void)
{
    return &mProcExcl->i_IProcessExcluder;
}

static void deleteGlobals(void)
{
    if ( mDegrMode )
    {
        dbg("Deleting Degraded Mode Processor");
        mDegrMode->delete(mDegrMode);
    }
    if ( mProcExcl )
    {
        dbg("Deleting Process Exclusion Processor");
        mProcExcl->delete(mProcExcl);
    }
    if ( mVetCtrl )
    {
        dbg("Deleting Vetting Controller");
        mVetCtrl->delete(mVetCtrl);
    }
    if ( mOpExcl )
    {
        dbg("Deleting Operation Exclusion Processor");
        mOpExcl->delete(mOpExcl);
    }
    if ( mCacheEval )
    {
        dbg("Deleting CacheEval");
        mCacheEval->delete(mCacheEval);
    }
    if ( mCacheAllow )
    {
        dbg("Deleting CacheAllow");
        mCacheAllow->delete(mCacheAllow);
    }
    if ( mCacheDeny )
    {
        dbg("Deleting CacheDeny");
        mCacheDeny->delete(mCacheDeny);
    }
    if ( mCache )
    {
        dbg("Deleting Cache");
        mCache->delete(mCache);
    }
    if ( mExclusion )
    {
        dbg("Deleting Filesystem Exclusion Processor");
        mExclusion->delete(mExclusion);
    }
    if ( mInclusion )
    {
        dbg("Deleting Filesystem Inclusion Processor");
        mInclusion->delete(mInclusion);
    }
    if ( mDebugSyslog )
    {
        dbg("Deleting Debug Syslog filter");
        mDebugSyslog->delete(mDebugSyslog);
    }
    if ( mDenySyslog )
    {
        dbg("Deleting Deny Syslog filter");
        mDenySyslog->delete(mDenySyslog);
    }
    if ( mAllowSyslog )
    {
        dbg("Deleting Allow Syslog filter");
        mAllowSyslog->delete(mAllowSyslog);
    }
    if ( mProcessor )
    {
        dbg("Deleting Processor");
        mProcessor->delete(mProcessor);
    }
}

static int __init talpa_core_init(void)
{
    int ret = -ENOMEM;


    /*
     * Get the system configurator.
     */
    mConfig = TALPA_Portability()->configurator();
    if ( !mConfig )
    {
        err("Failed to obtain configurator!");
        return -ENOENT;
    }

    /*
     * Create the InterceptProcessor.
     */
    mProcessor = newStandardInterceptProcessor();
    if ( !mProcessor )
    {
        err("Failed to create processor!");
        return -ENOMEM;
    }

    /*
     * Create the VettingController.
     */
    mVetCtrl = newVettingController();
    if ( !mVetCtrl )
    {
        err("Failed to create vetting controller!");
        goto failed;
    }

    /*
     * Create the FilesystemInclusionProcessor.
     */
    mInclusion = newFilesystemInclusionProcessor();
    if ( !mInclusion )
    {
        err("Failed to create filesystem inclusion processor!");
        goto failed;
    }

    /*
     * Create the FilesystemExclusionProcessor.
     */
    mExclusion = newFilesystemExclusionProcessor();
    if ( !mExclusion )
    {
        err("Failed to create filesystem exclusion processor!");
        goto failed;
    }

    /*
     * Create the filters.
     */
    mDebugSyslog = newSyslogFilter("DebugSyslog");
    if ( !mDebugSyslog )
    {
        err("Failed to create debug syslog filter!");
        goto failed;
    }

    mDenySyslog = newDenySyslogFilter("DenySyslog");
    if ( !mDenySyslog )
    {
        err("Failed to create deny syslog filter!");
        goto failed;
    }

    mAllowSyslog = newAllowSyslogFilter("AllowSyslog");
    if ( !mAllowSyslog )
    {
        err("Failed to create allow syslog filter!");
        goto failed;
    }

    mOpExcl = newOperationExclusionProcessor();
    if ( !mOpExcl )
    {
        err("Failed to create operation exclusion processor!");
        goto failed;
    }

    mCache = newCache();
    if ( !mCache )
    {
        err("Failed to create cache!");
        goto failed;
    }

    mCacheEval = newCacheEval(&mCache->i_ICache);
    if ( !mCacheEval )
    {
        err("Failed to create cache eval!");
        goto failed;
    }

    mCacheAllow = newCacheAllow(&mCache->i_ICache);
    if ( !mCacheAllow )
    {
        err("Failed to create cache allow!");
        goto failed;
    }

    mCacheDeny = newCacheDeny(&mCache->i_ICache);
    if ( !mCacheDeny )
    {
        err("Failed to create cache deny!");
        goto failed;
    }

    mProcExcl = newProcessExclusionProcessor();
    if ( !mProcExcl )
    {
        err("Failed to create process exclusion processor!");
        goto failed;
    }

    mDegrMode = newDegradedModeProcessor();
    if ( !mDegrMode )
    {
        err("Failed to create degraded mode processor!");
        goto failed;
    }

    // ::::: CREATE OTHER OBJECTS HERE!

    /*
     * Configure the filters with platform dependent data
     */
    mExclusion->i_IConfigurable.set(mExclusion, "fstypes", "+proc");
    mExclusion->i_IConfigurable.set(mExclusion, "mount-fstypes", "+proc");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    mExclusion->i_IConfigurable.set(mExclusion, "fstypes", "+sysfs");
    mExclusion->i_IConfigurable.set(mExclusion, "mount-fstypes", "+sysfs");
#endif

#define ATTACH_CONFIG_OR_FAIL(chain, obj) \
{ \
    int _ret = mConfig->attach(mConfig->object, chain, &obj->i_IConfigurable); \
    if ( _ret != 0 ) \
    { \
        err("Failed to register configuration for %s!", obj->i_IConfigurable.name(obj)); \
        ret = _ret; \
        goto failed; \
    } \
}

    /*
     * Expose the objects' configuration.
     */
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptProcessor, mProcessor);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mDegrMode);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mProcExcl);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mVetCtrl);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mInclusion);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mExclusion);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mOpExcl);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mDebugSyslog);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mDenySyslog);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mAllowSyslog);
    ATTACH_CONFIG_OR_FAIL(ECG_InterceptFilter, mCache);

    /*
     * Add filters to the intercept processor.
     * Note: In the future we want to evalute the order of the filters. Possibly make
     * cache happen immediately after opexcl and make IFileInfo use just-in-time
     * creation of expensive data.
     */
    mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &mOpExcl->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &mInclusion->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &mExclusion->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &mCacheEval->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &mDebugSyslog->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &mProcExcl->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &mDegrMode->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addEvaluationFilter(mProcessor, &mVetCtrl->i_IInterceptFilter);

    mProcessor->i_IInterceptProcessor.addAllowFilter(mProcessor, &mCacheAllow->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addAllowFilter(mProcessor, &mAllowSyslog->i_IInterceptFilter);

    mProcessor->i_IInterceptProcessor.addDenyFilter(mProcessor, &mCacheDeny->i_IInterceptFilter);
    mProcessor->i_IInterceptProcessor.addDenyFilter(mProcessor, &mDenySyslog->i_IInterceptFilter);

    /*
     * Register for intermodule communication on 2.4 kernels.
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    inter_module_register("TALPA_Core", THIS_MODULE, (const void *)TALPA_Core);
#endif

    dbg("Ready");
    return 0;

    failed:
    deleteGlobals();

    return ret;
}

static void __exit talpa_core_exit(void)
{
    /*
     * Unregister intermodule communication on 2.4 kernels.
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    inter_module_unregister("TALPA_Core");
#endif

    dbg("Detaching Cache configurator");
    mConfig->detach(mConfig->object, &mCache->i_IConfigurable);
    dbg("Detaching Allow Syslog configurator");
    mConfig->detach(mConfig->object, &mAllowSyslog->i_IConfigurable);
    dbg("Detaching Debug Syslog configurator");
    mConfig->detach(mConfig->object, &mDenySyslog->i_IConfigurable);
    dbg("Detaching Debug Syslog configurator");
    mConfig->detach(mConfig->object, &mDebugSyslog->i_IConfigurable);
    dbg("Detaching Operation Exclusion Processor configurator");
    mConfig->detach(mConfig->object, &mOpExcl->i_IConfigurable);
    dbg("Detaching Filesystem Exclusion Processor configurator");
    mConfig->detach(mConfig->object, &mExclusion->i_IConfigurable);
    dbg("Detaching Filesystem Inclusion Processor configurator");
    mConfig->detach(mConfig->object, &mInclusion->i_IConfigurable);
    dbg("Detaching Vetting Controller configurator");
    mConfig->detach(mConfig->object, &mVetCtrl->i_IConfigurable);
    dbg("Detaching Process Exclusion Processor configurator");
    mConfig->detach(mConfig->object, &mProcExcl->i_IConfigurable);
    dbg("Detaching Degraded Mode Processor configurator");
    mConfig->detach(mConfig->object, &mDegrMode->i_IConfigurable);
    dbg("Detaching Processor configurator");
    mConfig->detach(mConfig->object, &mProcessor->i_IConfigurable);

    deleteGlobals();
    dbg("Unloaded");
    return;
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Limited");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Core Module");
MODULE_LICENSE("GPL");
#if defined TALPA_VERSION && defined MODULE_VERSION
MODULE_VERSION(TALPA_VERSION);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
EXPORT_SYMBOL(TALPA_Core);
#else
EXPORT_SYMBOL_NOVERS(TALPA_Core);
#endif

module_init(talpa_core_init);
module_exit(talpa_core_exit);


/*
 * End of talpa_core_module.c
 */
