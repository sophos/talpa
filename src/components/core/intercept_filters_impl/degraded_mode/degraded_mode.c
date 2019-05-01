/*
 * degraded_mode.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
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
#include <linux/sched.h>

#define TALPA_SUBSYS "degrmode"
#include "common/talpa.h"
#include "degraded_mode.h"

#include "platform/glue.h"
#include "platform/alloc.h"

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);

static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);

static void deleteDegradedModeProcessor(struct tag_DegradedModeProcessor* object);


/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_THRESHOLD       "threshold"
#define CFG_ACTIVE          "active"

#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"

#define CFG_DEFAULT_THRESHOLD (3)
#define CFG_VALUE_THRESHOLD "3"

#define CFG_VALUE_ACTIVE    "false"

/*
 * Template Object.
 */
static DegradedModeProcessor template_DegradedModeProcessor =
    {
        {
            examineFile,
            NULL,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteDegradedModeProcessor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteDegradedModeProcessor
        },
        deleteDegradedModeProcessor,
        true,
        TALPA_SIMPLE_UNLOCKED(talpa_degraded_mode_processor_lock),
        ATOMIC_INIT(CFG_DEFAULT_THRESHOLD),
        false,
        TALPA_MUTEX_INIT,
        {
            {NULL, NULL, DMD_CFGDATASIZE, true, true },
            {NULL, NULL, DMD_CFGDATASIZE, true, true },
            {NULL, NULL, DMD_CFGDATASIZE, true, true },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_ENABLED },
        { CFG_THRESHOLD, CFG_VALUE_THRESHOLD },
        { CFG_ACTIVE, CFG_VALUE_ACTIVE }
    };
#define this    ((DegradedModeProcessor*)self)



/*
 * Object creation/destruction.
 */
DegradedModeProcessor* newDegradedModeProcessor(void)
{
    DegradedModeProcessor* object;


    object = talpa_alloc(sizeof(template_DegradedModeProcessor));
    if ( object )
    {
        dbg("object at 0x%p", object);
        memcpy(object, &template_DegradedModeProcessor, sizeof(template_DegradedModeProcessor));
        object->i_IInterceptFilter.object = object->i_IConfigurable.object = object;

        talpa_simple_init(&object->mLock);
        talpa_mutex_init(&object->mConfigSerialize);

        object->mConfig[0].name  = object->mStateConfigData.name;
        object->mConfig[0].value = object->mStateConfigData.value;
        object->mConfig[1].name  = object->mThresholdConfigData.name;
        object->mConfig[1].value = object->mThresholdConfigData.value;
        object->mConfig[2].name  = object->mActiveConfigData.name;
        object->mConfig[2].value = object->mActiveConfigData.value;
    }
    return object;
}

static void deleteDegradedModeProcessor(struct tag_DegradedModeProcessor* object)
{
    talpa_free(object);
    return;
}

static inline bool checkDegraded(const void* self, IEvaluationReport* report)
{
    unsigned int consecutive = report->consecutiveTimeouts(report);


    if ( unlikely( consecutive > atomic_read(&this->mThreshold)) )
    {
        talpa_simple_lock(&this->mLock);
        if ( this->mActive == false )
        {
            info("Activated");
            this->mActive = true;
            strcpy(this->mActiveConfigData.value, "true");
        }
        if( __talpa_kuid_val(current_uid()) == 0 )
        {
            talpa_simple_unlock(&this->mLock);
            return true;
        }
        talpa_simple_unlock(&this->mLock);
    }
    else
    {
        if ( unlikely( this->mActive == true ) )
        {
            talpa_simple_lock(&this->mLock);
            if ( unlikely( this->mActive == true ) )
            {
                info("Deactivated");
                this->mActive = false;
                strcpy(this->mActiveConfigData.value, "false");
            }
            talpa_simple_unlock(&this->mLock);
        }
    }

    return false;
}
/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    if ( unlikely(checkDegraded(this, report) == true) )
    {
        report->setRecommendedAction(report, EIA_Allow);
    }

    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report,
                                const IPersonality* userInfo,
                                const IFilesystemInfo* info)
{
    if ( unlikely(checkDegraded(this, report) == true) )
    {
        report->setRecommendedAction(report, EIA_Allow);
    }

    return;
}

/*
 * Internal configuration.
 */

static bool enable(void* self)
{
    if (!this->mEnabled)
    {
        this->mEnabled = true;
        strcpy(this->mStateConfigData.value, CFG_VALUE_ENABLED);
        info("Enabled");
    }
    return true;
}

static void disable(void* self)
{
    if (this->mEnabled)
    {
        this->mEnabled = false;
        strcpy(this->mStateConfigData.value, CFG_VALUE_DISABLED);
        info("Disabled");
    }
    return;
}

static bool isEnabled(const void* self)
{
    return this->mEnabled;
}

static void setThreshold(const void* self, const char* string)
{
    unsigned int val;
    char* res;

    val = simple_strtoul(string, &res, 10);
    snprintf(this->mThresholdConfigData.value, DMD_CFGDATASIZE, "%u", val);
    atomic_set(&this->mThreshold, val);
    info("Threshold set to %u", val);

    return;
}

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "DegradedModeProcessor";
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
    for (cfgElement = this->mConfig; cfgElement->name != NULL; cfgElement++)
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
    return NULL;
}

static void  setConfig(void* self, const char* name, const char* value)
{
   PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement->name != NULL; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Cant set that which does not exist!
     */
    if ( !cfgElement->name )
    {
        return;
    }

    /*
     * OK time to do some work...
     */
    if (strcmp(name, CFG_STATUS) == 0)
    {
        if (strcmp(value, CFG_ACTION_ENABLE) == 0)
        {
            talpa_mutex_lock(&this->mConfigSerialize);
            enable(this);
            talpa_mutex_unlock(&this->mConfigSerialize);
        }
        else if (strcmp(value, CFG_ACTION_DISABLE) == 0)
        {
            talpa_mutex_lock(&this->mConfigSerialize);
            disable(this);
            talpa_mutex_unlock(&this->mConfigSerialize);
        }
    }
    else if ( !strcmp(name, CFG_THRESHOLD) )
    {
        talpa_mutex_lock(&this->mConfigSerialize);
        setThreshold(this, value);
        talpa_mutex_unlock(&this->mConfigSerialize);
    }

    return;
}

/*
 * End of degraded_mode.c
 */

