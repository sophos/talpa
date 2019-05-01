/*
 * operation_excl.c
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
#include <asm/fcntl.h>

#define TALPA_SUBSYS "opexcl"
#include "common/talpa.h"
#include "operation_excl.h"

#include "platform/alloc.h"

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static EInterceptAction examineInode(const void* self, const EFilesystemOperation op, const bool writable, const int flags, const uint32_t device, const uint32_t inode);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);
static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void deleteOperationExclusionProcessor(struct tag_OperationExclusionProcessor* object);

/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_ONLYBLOCKDEV    "fs-onlyblock"
#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"

/*
 * Template Object.
 */
static OperationExclusionProcessor template_OperationExclusionProcessor =
    {
        {
            examineFile,
            examineInode,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteOperationExclusionProcessor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteOperationExclusionProcessor
        },
        deleteOperationExclusionProcessor,
        true,
        true,
        TALPA_MUTEX_INIT,
        {
            {NULL, NULL, OPERATIONEXCLUSIONPROCESSOR_CFGDATASIZE, true, true },
            {NULL, NULL, OPERATIONEXCLUSIONPROCESSOR_CFGDATASIZE, true, true },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_ENABLED },
        { CFG_ONLYBLOCKDEV, CFG_VALUE_ENABLED }

    };
#define this    ((OperationExclusionProcessor*)self)



/*
 * Object creation/destruction.
 */
OperationExclusionProcessor* newOperationExclusionProcessor(void)
{
    OperationExclusionProcessor* object;


    object = talpa_alloc(sizeof(template_OperationExclusionProcessor));
    if ( object )
    {
        memcpy(object, &template_OperationExclusionProcessor, sizeof(template_OperationExclusionProcessor));
        object->i_IInterceptFilter.object = object->i_IConfigurable.object = object;

        talpa_mutex_init(&object->mConfigSerialize);

        object->mConfig[0].name  = object->mConfigStatus.name;
        object->mConfig[0].value = object->mConfigStatus.value;
        object->mConfig[1].name  = object->mConfigOnlyBlockDev.name;
        object->mConfig[1].value = object->mConfigOnlyBlockDev.value;
    }
    return object;
}

static void deleteOperationExclusionProcessor(struct tag_OperationExclusionProcessor* object)
{
    talpa_free(object);
    return;
}

/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    switch (info->operation(info))
    {
        case EFS_Open:
            /*
             * Allow if file was truncated on open, is write only
             * or is open for exclusive creation.
             */
            if ((info->flags(info) & (O_WRONLY | O_TRUNC))
                || ((info->flags(info) & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
               )
            {
                report->setRecommendedAction(report, EIA_Allow);
            }
            break;
        case EFS_Close:
            /*
             * Allow if we are closing and read-only file.
             */
            if ( ! info->isWritable(info) )
            {
                report->setRecommendedAction(report, EIA_Allow);
            }
            break;
        default:
            /*
             * Ignore the operation.
             */
            break;
    }
    return;
}

static EInterceptAction examineInode(const void* self, const EFilesystemOperation op, const bool writable, const int flags, const uint32_t device, const uint32_t inode)
{
    switch (op)
    {
        case EFS_Open:
            /*
             * Allow if file was truncated on open, is write only
             * or is open for exclusive creation.
             */
            if ( (flags & (O_WRONLY | O_TRUNC)) || ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) )
            {
                return EIA_Allow;
            }
            break;
        case EFS_Close:
            /*
             * Allow if we are closing and read-only file.
             */
            if ( !writable )
            {
                return EIA_Allow;
            }
            break;
        default:
            /*
             * Ignore the operation.
             */
            break;
    }

    return EIA_Next;
}

static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info)
{
    if ( this->mOnlyBlockDev && !info->device(info) )
    {
        report->setRecommendedAction(report, EIA_Allow);
    }

    return;
}

static bool enable(void* self)
{
    if (!this->mEnabled)
    {
        this->mEnabled = true;
        strcpy(this->mConfigStatus.value, CFG_VALUE_ENABLED);
        info("Enabled");
    }
    return true;
}

static void disable(void* self)
{
    if (this->mEnabled)
    {
        this->mEnabled = false;
        strcpy(this->mConfigStatus.value, CFG_VALUE_DISABLED);
        info("Disabled");
    }
    return;
}

static void onlyBlockDev(void* self, bool state)
{
    if ( !this->mOnlyBlockDev && state )
    {
        this->mOnlyBlockDev = true;
        strcpy(this->mConfigOnlyBlockDev.value, CFG_VALUE_ENABLED);
        info("Ignoring non-block device mount operations");
    }
    else if ( this->mOnlyBlockDev && !state )
    {
        this->mOnlyBlockDev = false;
        strcpy(this->mConfigOnlyBlockDev.value, CFG_VALUE_DISABLED);
        info("Intercepting all mount operations");
    }
    return;
}

static bool isEnabled(const void* self)
{
    return this->mEnabled;
}

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "OperationExclusionProcessor";
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
    else if (strcmp(name, CFG_ONLYBLOCKDEV) == 0)
    {
        if (strcmp(value, CFG_ACTION_ENABLE) == 0)
        {
            talpa_mutex_lock(&this->mConfigSerialize);
            onlyBlockDev(this, true);
            talpa_mutex_unlock(&this->mConfigSerialize);
        }
        else if (strcmp(value, CFG_ACTION_DISABLE) == 0)
        {
            talpa_mutex_lock(&this->mConfigSerialize);
            onlyBlockDev(this, false);
            talpa_mutex_unlock(&this->mConfigSerialize);
        }
    }
    return;
}

/*
 * End of operation_excl.c
 */

