/*
 * std_intercept_processor.c
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
#include <linux/kernel.h>

#include <linux/string.h>

#include <asm/errno.h>
#include <asm/atomic.h>
#include <linux/spinlock.h>

#include <common/talpa.h>

#include "app_ctrl/iportability_app_ctrl.h"
#include "personality/ipersonality.h"
#include "personality/ipersonality_factory.h"
#include "evaluation_report_impl.h"

#include "std_intercept_processor.h"

#include "platform/alloc.h"

/*
 * Forward declare implementation methods.
 */
static int examineFileInfo(const void* self, const IFileInfo* info, IFile* file);
static int examineInode(const void* self, const EFilesystemOperation op, const bool writable, const int flags, const uint32_t device, const uint32_t inode);
static int runAllowChain(const void* self, const IFileInfo* info);
static int examineFilesystemInfo(const void* self, const IFilesystemInfo* info);
static void addEvaluationFilter(void* self, IInterceptFilter* filter);
static void addAllowFilter(void* self, IInterceptFilter* filter);
static void addDenyFilter(void* self, IInterceptFilter* filter);
static void removeEvaluationFilter(void* self, const IInterceptFilter* filter);
static void removeAllowFilter(void* self, const IInterceptFilter* filter);
static void removeDenyFilter(void* self, const IInterceptFilter* filter);
static void resetEvaluationFilters(void* self);
static void resetAllowFilters(void* self);
static void resetDenyFilters(void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void deleteStandardInterceptProcessor(struct tag_StandardInterceptProcessor* object);

/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"

/*
 * Template Object.
 */
static StandardInterceptProcessor template_StandardInterceptProcessor =
    {
        {
            examineFileInfo,
            examineInode,
            runAllowChain,
            examineFilesystemInfo,
            addEvaluationFilter,
            addAllowFilter,
            addDenyFilter,
            removeEvaluationFilter,
            removeAllowFilter,
            removeDenyFilter,
            resetEvaluationFilters,
            resetAllowFilters,
            resetDenyFilters,
            NULL,
            (void (*)(void*))deleteStandardInterceptProcessor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteStandardInterceptProcessor
        },
        deleteStandardInterceptProcessor,
        {},
        {},
        {},
        ATOMIC_INIT(0),
        {
            {NULL, NULL, STDINTPROC_CFGDATASIZE, false, true },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_ENABLED }
    };
#define this    ((StandardInterceptProcessor*)self)


/*
 * Object creation/destruction.
 */
StandardInterceptProcessor* newStandardInterceptProcessor(void)
{
    StandardInterceptProcessor* object;


    object = talpa_alloc(sizeof(template_StandardInterceptProcessor));
    if ( object )
    {
        memcpy(object, &template_StandardInterceptProcessor, sizeof(template_StandardInterceptProcessor));
        object->i_IInterceptProcessor.object = object->i_IConfigurable.object = object;
        object->mConfig[0].name  = object->mConfigData.name;
        object->mConfig[0].value = object->mConfigData.value;
        TALPA_INIT_LIST_HEAD(&object->mEvaluationActions);
        TALPA_INIT_LIST_HEAD(&object->mAllowActions);
        TALPA_INIT_LIST_HEAD(&object->mDenyActions);
    }
    return object;
}

static void deleteStandardInterceptProcessor(struct tag_StandardInterceptProcessor* object)
{
    /*
     * We are not responsible for the filter objects.....so we do not need to destroy them.
     * However, we are responsible for the lists we put them in - clean up the lists first.
     */

    resetEvaluationFilters(object);
    resetAllowFilters(object);
    resetDenyFilters(object);

    talpa_free(object);

    return;
}

/*
 * IInterceptProcessor.
 */
static int examineFileInfo(const void* self, const IFileInfo* info, IFile* file)
{
    talpa_list_head*        actionList;
    FilterEntry*            posptr;
    EvaluationReportImpl*   evalReport;
    IPersonalityFactory*    pFactory;
    IPersonality*     userInfo;
    EInterceptAction action;
    int retCode;

    /*
     * Don't examine deleted files on close
     */
    if (info->isDeleted(info))
    {
        return 0;
    }

    /*
     * Create evaluation report, and obtain the user's personality information.
     */
    evalReport  = newEvaluationReportImpl(atomic_read(&this->mNumConsecutiveTimeouts));
    pFactory    = TALPA_Portability()->personalityFactory();
    userInfo    = pFactory->newPersonality(pFactory);
    if ( unlikely((evalReport == NULL) || (userInfo == NULL)) )
    {
        /* Allow access on extreme memory pressure. */
        if ( evalReport )
        {
            evalReport->delete(evalReport);
        }
        if ( userInfo )
        {
            userInfo->delete(userInfo);
        }
        return 0;
    }

    /*
     * Perform evaluation - anything but Next halts all processing.
     */
    start_eval:
    evalReport->i_IEvaluationReport.setRecommendedAction(evalReport, EIA_Next);
    talpa_list_for_each_entry(posptr, &this->mEvaluationActions, list)
    {
        if ( unlikely(!posptr->filter->examineFile || !posptr->filter->isEnabled(posptr->filter->object)) )
        {
            continue;
        }

        posptr->filter->examineFile(posptr->filter->object, &evalReport->i_IEvaluationReport, userInfo, info, file);
        action = evalReport->i_IEvaluationReport.recommendedAction(evalReport);

        if (action == EIA_Next)
        {
            continue;
        }
        else if ( unlikely(action == EIA_Restart) )
        {
            goto start_eval;
        }
        break;
    }

    /*
     * OK. Lets look at our verdict - if next assume allow.
     */
    if ((evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Next)
        || (evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Allow)
        || ((evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Timeout)
            && (evalReport->i_IEvaluationReport.errorCode(evalReport) != ETIME)))
    {
        actionList = &this->mAllowActions;
    }
    else
    {
        actionList = &this->mDenyActions;
    }
    talpa_list_for_each_entry(posptr, actionList, list)
    {
        if ( unlikely(!posptr->filter->examineFile || !posptr->filter->isEnabled(posptr->filter->object)) )
        {
            continue;
        }

        posptr->filter->examineFile(posptr->filter->object, &evalReport->i_IEvaluationReport, userInfo, info, file);
    }

    /*
     * Increment the timeout count if occured - else reset it. But only vetted by external client.
     */
    if ( unlikely(evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Timeout) )
    {
        atomic_inc(&this->mNumConsecutiveTimeouts);
    }
    else if ( evalReport->i_IEvaluationReport.hasBeenExternallyVetted(evalReport) )
    {
        atomic_set(&this->mNumConsecutiveTimeouts, 0);
    }

    /*
     * Tidy up.
     */
    userInfo->delete(userInfo);

    /*
     * Report back our verdict!
     */

    action = evalReport->i_IEvaluationReport.recommendedAction(evalReport);
    retCode = evalReport->i_IEvaluationReport.errorCode(evalReport);

    evalReport->delete(evalReport);

    switch ( action )
    {
        case EIA_Next:
        case EIA_Allow:
            break;
        case EIA_Error:
            return -retCode;
        case EIA_Timeout:
            return -retCode;
        case EIA_Deny:
            return -EPERM;
        case EIA_Restart:
            return -EPROTO;
    }

    return 0;
}

static int examineInode(const void* self, const EFilesystemOperation op, const bool writable, const int flags, const uint32_t device, const uint32_t inode)
{
    FilterEntry*        posptr;
    EInterceptAction    action;
    talpa_list_head*    actionList = NULL;
    int                 retCode = 0;


    /*
     * Perform evaluation - anything but Next halts all processing.
     */
     start_eval:
     action = EIA_Next;
     talpa_list_for_each_entry(posptr, &this->mEvaluationActions, list)
     {
        if ( unlikely( !posptr->filter->examineInode || !posptr->filter->isEnabled(posptr->filter->object) ) )
        {
            continue;
        }

        action = posptr->filter->examineInode(posptr->filter->object, op, writable, flags, device, inode);

        if ( action == EIA_Next )
        {
            continue;
        }
        else if ( unlikely( action == EIA_Restart ) )
        {
            goto start_eval;
        }
        break;
    }

    /*
     * OK. Lets look at our verdict - if next don't run allow or deny chains.
     * That will make the interceptor run the examineFileInfo eval chain instead.
     */
    if ( action == EIA_Allow )
    {
        actionList = &this->mAllowActions;
    }
    else if ( action != EIA_Next )
    {
        actionList = &this->mDenyActions;
    }

    if ( actionList )
    {
        talpa_list_for_each_entry(posptr, actionList, list)
        {
            if ( unlikely( !posptr->filter->examineInode || !posptr->filter->isEnabled(posptr->filter->object) ) )
            {
                continue;
            }

            if ( posptr->filter->examineInode(posptr->filter->object, op, writable, flags, device, inode) == EIA_Error )
            {
                break;
            }
        }
    }

    switch ( action )
    {
        case EIA_Allow:
            break;
        case EIA_Next:
            retCode = -EAGAIN;
            break;
        case EIA_Timeout:
            retCode = -ETIME;
            break;
        case EIA_Deny:
        case EIA_Error:
            retCode = -EPERM;
            break;
        case EIA_Restart:
            retCode = -EPROTO;
            break;
    }

    return retCode;
}

static int runAllowChain(const void* self, const IFileInfo* info)
{
    FilterEntry*            posptr;
    EvaluationReportImpl*   evalReport;
    IPersonalityFactory*    pFactory;
    IPersonality*           userInfo;
    EInterceptAction        action;
    int                     retCode;


    /*
     * Create evaluation report, and obtain the user's personality information.
     */
    evalReport  = newEvaluationReportImpl(atomic_read(&this->mNumConsecutiveTimeouts));
    pFactory    = TALPA_Portability()->personalityFactory();
    userInfo    = pFactory->newPersonality(pFactory);
    if ( unlikely((evalReport == NULL) || (userInfo == NULL)) )
    {
        /* Allow access on extreme memory pressure. */
        if ( evalReport )
        {
            evalReport->delete(evalReport);
        }
        if ( userInfo )
        {
            userInfo->delete(userInfo);
        }
        return 0;
    }

    /*
     * Traverse throught the allow chain and execute the filters.
     */
    talpa_list_for_each_entry(posptr, &this->mAllowActions, list)
    {
        if ( unlikely(!posptr->filter->examineFile || !posptr->filter->isEnabled(posptr->filter->object)) )
        {
            continue;
        }

        posptr->filter->examineFile(posptr->filter->object, &evalReport->i_IEvaluationReport, userInfo, info, NULL);

        if ( unlikely(evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Error) )
        {
            break;
        }
    }

    /*
     * Increment the timeout count if occured - else reset it. But only vetted by external client.
     */
    if ( unlikely(evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Timeout) )
    {
        atomic_inc(&this->mNumConsecutiveTimeouts);
    }
    else if ( evalReport->i_IEvaluationReport.hasBeenExternallyVetted(evalReport) )
    {
        atomic_set(&this->mNumConsecutiveTimeouts, 0);
    }

    /*
     * Tidy up.
     */
    userInfo->delete(userInfo);

    /*
     * Report back our verdict!
     */

    action = evalReport->i_IEvaluationReport.recommendedAction(evalReport);
    retCode = evalReport->i_IEvaluationReport.errorCode(evalReport);

    evalReport->delete(evalReport);

    switch ( action )
    {
        case EIA_Next:
        case EIA_Allow:
            break;
        case EIA_Error:
            return -retCode;
        case EIA_Timeout:
            return -retCode;
        case EIA_Deny:
            return -EPERM;
        case EIA_Restart:
            return -EPROTO;
    }

    return 0;
}

static int examineFilesystemInfo(const void* self, const IFilesystemInfo* info)
{
    talpa_list_head*       actionList;
    FilterEntry*            posptr;
    EvaluationReportImpl*   evalReport;
    IPersonalityFactory*    pFactory;
    IPersonality*     userInfo;
    EInterceptAction action;
    int retCode;

    /*
     * Create evaluation report.
     */
    evalReport  = newEvaluationReportImpl(atomic_read(&this->mNumConsecutiveTimeouts));
    pFactory    = TALPA_Portability()->personalityFactory();
    userInfo    = pFactory->newPersonality(pFactory);
    if ( unlikely((evalReport == NULL) || (userInfo == NULL)) )
    {
        /* Allow access on extreme memory pressure. */
        if ( evalReport )
        {
            evalReport->delete(evalReport);
        }
        if ( userInfo )
        {
            userInfo->delete(userInfo);
        }
        return 0;
    }

    /*
     * Perform evaluation - error halts all processing and returns.
     */
    start_eval:
    evalReport->i_IEvaluationReport.setRecommendedAction(evalReport, EIA_Next);
    talpa_list_for_each_entry(posptr, &this->mEvaluationActions, list)
    {
        if ( unlikely (!posptr->filter->examineFilesystem || !posptr->filter->isEnabled(posptr->filter->object)) )
        {
            continue;
        }

        posptr->filter->examineFilesystem(posptr->filter->object, &evalReport->i_IEvaluationReport, userInfo, info);
        action = evalReport->i_IEvaluationReport.recommendedAction(evalReport);

        if (action == EIA_Next)
        {
            continue;
        }
        else if ( unlikely(action == EIA_Restart) )
        {
            goto start_eval;
        }
        break;
    }

    /*
     * OK. Lets look at our verdict - if timeout/next assume allow.
     */
    if ((evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Next)
        || (evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Allow)
        || ((evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Timeout)
            && (evalReport->i_IEvaluationReport.errorCode(evalReport) != ETIME)))

    {
        actionList = &this->mAllowActions;
    }
    else
    {
        actionList = &this->mDenyActions;
    }
    talpa_list_for_each_entry(posptr, actionList, list)
    {
        if ( unlikely(!posptr->filter->examineFilesystem || !posptr->filter->isEnabled(posptr->filter->object)) )
        {
            continue;
        }

        posptr->filter->examineFilesystem(posptr->filter->object, &evalReport->i_IEvaluationReport, userInfo, info);

        if ( unlikely(evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Error) )
        {
            break;
        }
    }

    /*
     * Increment the timeout count if occured - else reset it. But only vetted by external client.
     */
    if ( unlikely(evalReport->i_IEvaluationReport.recommendedAction(evalReport) == EIA_Timeout) )
    {
        atomic_inc(&this->mNumConsecutiveTimeouts);
    }
    else if ( evalReport->i_IEvaluationReport.hasBeenExternallyVetted(evalReport) )
    {
        atomic_set(&this->mNumConsecutiveTimeouts, 0);
    }

    /*
     * Tidy up.
     */
    userInfo->delete(userInfo);

    /*
     * Report back our verdict!
     */

    action = evalReport->i_IEvaluationReport.recommendedAction(evalReport);
    retCode = evalReport->i_IEvaluationReport.errorCode(evalReport);

    evalReport->delete(evalReport);

    switch ( action )
    {
        case EIA_Next:
        case EIA_Allow:
            break;
        case EIA_Error:
            return -retCode;
        case EIA_Timeout:
            return -retCode;
        case EIA_Deny:
            return -EPERM;
        case EIA_Restart:
            return -EPROTO;
    }

    return 0;
}

static void addEvaluationFilter(void* self, IInterceptFilter* filter)
{
    FilterEntry*    filterInfo;


    filterInfo = talpa_alloc(sizeof(FilterEntry));
    if ( filterInfo )
    {
        filterInfo->filter = filter;
        talpa_list_add_tail(&filterInfo->list, &(this->mEvaluationActions));
    }
    return;
}

static void addAllowFilter(void* self, IInterceptFilter* filter)
{
    FilterEntry*    filterInfo;


    filterInfo = talpa_alloc(sizeof(FilterEntry));
    if ( filterInfo )
    {
        filterInfo->filter = filter;
        talpa_list_add_tail(&filterInfo->list, &(this->mAllowActions));
    }
    return;
}

static void addDenyFilter(void* self, IInterceptFilter* filter)
{
    FilterEntry*    filterInfo;


    filterInfo = talpa_alloc(sizeof(FilterEntry));
    if ( filterInfo )
    {
        filterInfo->filter = filter;
        talpa_list_add_tail(&filterInfo->list, &(this->mDenyActions));
    }
    return;
}

static void removeEvaluationFilter(void* self, const IInterceptFilter* filter)
{
    FilterEntry*   posptr;


    talpa_list_for_each_entry(posptr, &this->mEvaluationActions, list)
    {
        if (posptr->filter == filter)
        {
            talpa_list_del(&posptr->list);
            talpa_free(posptr);
            break;
        }
    }
    return;
}

static void removeAllowFilter(void* self, const IInterceptFilter* filter)
{
    FilterEntry*   posptr;


    talpa_list_for_each_entry(posptr, &this->mAllowActions, list)
    {
        if (posptr->filter == filter)
        {
            talpa_list_del(&posptr->list);
            talpa_free(posptr);
            break;
        }
    }
    return;
}

static void removeDenyFilter(void* self, const IInterceptFilter* filter)
{
    FilterEntry*   posptr;


    talpa_list_for_each_entry(posptr, &this->mDenyActions, list)
    {
        if (posptr->filter == filter)
        {
            talpa_list_del(&posptr->list);
            talpa_free(posptr);
            break;
        }
    }
    return;
}

static void resetEvaluationFilters(void* self)
{
    talpa_list_head*   posptr;
    talpa_list_head*   nptr;


    talpa_list_for_each_safe(posptr, nptr, &this->mEvaluationActions)
    {
        talpa_list_del(posptr);
        talpa_free(talpa_list_entry(posptr, FilterEntry, list));
    }
    return;
}

static void resetAllowFilters(void* self)
{
    talpa_list_head*   posptr;
    talpa_list_head*   nptr;


    talpa_list_for_each_safe(posptr, nptr, &this->mAllowActions)
    {
        talpa_list_del(posptr);
        talpa_free(talpa_list_entry(posptr, FilterEntry, list));
    }
    return;
}

static void resetDenyFilters(void* self)
{
    talpa_list_head*   posptr;
    talpa_list_head*   nptr;


    talpa_list_for_each_safe(posptr, nptr, &this->mDenyActions)
    {
        talpa_list_del(posptr);
        talpa_free(talpa_list_entry(posptr, FilterEntry, list));
    }
    return;
}

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "StandardInterceptProcessor";
}

static const PODConfigurationElement* allConfig(const void* self)
{
    return this->mConfig;
}

static const char* config(const void* self, const char* name)
{
    PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement != NULL; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Return what was found else a null pointer.
     */
    if ( cfgElement->name )
    {
        return cfgElement->value;
    }
    return 0;
}

static void  setConfig(void* self, const char* name, const char* value)
{
    /*
     * No configuration items that may be written to!
     */
    return;
}

/*
 * End of std_intercept_processor.c
 */

