/*
 * filesystem_inclusion_processor.c
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

#define TALPA_SUBSYS "inclusion"
#include "common/talpa.h"
#include "filesystem_inclusion_processor.h"

#include "platform/alloc.h"

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);
static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static void setPath(void* self, const char* path);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void deleteFilesystemInclusionProcessor(struct tag_FilesystemInclusionProcessor* object);

/*
 * Constants
 */
#define CFG_STATUS           "status"
#define CFG_VALUE_ENABLED    "enabled"
#define CFG_VALUE_DISABLED   "disabled"
#define CFG_ACTION_ENABLE    "enable"
#define CFG_ACTION_DISABLE   "disable"
#define CFG_INCLUDE_PATH     "include-path"
#define CFG_PATH_DEFAULT     "/"
#define CFG_PATH_DEFAULT_LEN (1)

/*
 * Template Object.
 */
static FilesystemInclusionProcessor template_FilesystemInclusionProcessor =
    {
        {
            examineFile,
            NULL,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteFilesystemInclusionProcessor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteFilesystemInclusionProcessor
        },
        deleteFilesystemInclusionProcessor,
        setPath,
        TALPA_RW_UNLOCKED(talpa_filesystem_inclusion_rw_lock),
        false,
        CFG_PATH_DEFAULT,
        CFG_PATH_DEFAULT_LEN,
        {
            {NULL, NULL, CFGDATASIZE, true, true },
            {NULL, NULL, PATH_MAX, true, false },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_DISABLED },
        { CFG_INCLUDE_PATH, CFG_PATH_DEFAULT }
    };
#define this    ((FilesystemInclusionProcessor*)self)



/*
 * Object creation/destruction.
 */
FilesystemInclusionProcessor* newFilesystemInclusionProcessor(void)
{
    FilesystemInclusionProcessor* object;


    object = talpa_alloc(sizeof(template_FilesystemInclusionProcessor));
    if ( object )
    {
        memcpy(object, &template_FilesystemInclusionProcessor, sizeof(template_FilesystemInclusionProcessor));
        object->i_IInterceptFilter.object = object->i_IConfigurable.object = object;
        object->mConfig[0].name  = object->mStateConfigData.name;
        object->mConfig[0].value = object->mStateConfigData.value;
        object->mConfig[1].name  = object->mPathConfigData.name;
        object->mConfig[1].value = object->mPathConfigData.value;
        talpa_rw_init(&object->mConfigLock);
    }
    return object;
}

static void deleteFilesystemInclusionProcessor(struct tag_FilesystemInclusionProcessor* object)
{
    talpa_free(object);
    return;
}

/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    const char* string;

    string = info->filename(info);
    if ( likely(string != NULL) )
    {
        char* path;
        unsigned int path_len;
        unsigned int string_len;

        path = this->mPath;
        path_len = this->mPathLen;

        talpa_read_lock(&this->mConfigLock);

        /* Do not include the file if the filename is shorter than our filter */
        string_len = strlen(string);
        if ( string_len < path_len )
        {
            goto not_included;
        }

        if ( likely( path[path_len-1] == '/' ) )
        {
            /* We have a directory exclusion - so it can match in full (exact) or in part (subdir). */
            if ( strncmp(string, path, path_len) )
            {
                goto not_included;
            }
        }
        else
        {
            /* Its a normal pathname exclusion - must match in full. */
            if ( (string_len != path_len) || strcmp(string, path) )
            {
                goto not_included;
            }
        }

        talpa_read_unlock(&this->mConfigLock);
    }

    return;

    not_included:
    talpa_read_unlock(&this->mConfigLock);
    report->setRecommendedAction(report, EIA_Allow);

    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info)
{
    char* path;
    unsigned int path_len;
    const char* string;

    path = this->mPath;
    path_len = this->mPathLen;

    string = info->mountPoint(info);
    if ( likely(string != NULL) )
    {
        char* path;
        unsigned int path_len;
        unsigned int string_len;

        path = this->mPath;
        path_len = this->mPathLen;

        talpa_read_lock(&this->mConfigLock);

        /* Do not include the file if the filename is shorter than our filter */
        string_len = strlen(string);
        if ( string_len < path_len )
        {
            goto not_included;
        }

        if ( likely( path[path_len-1] == '/' ) )
        {
            /* We have a directory exclusion - so it can match in full (exact) or in part (subdir). */
            if ( strncmp(string, path, path_len) )
            {
                goto not_included;
            }
        }
        else
        {
            /* Its a normal pathname exclusion - must match in full. */
            if ( (string_len != path_len) || strcmp(string, path) )
            {
                goto not_included;
            }
        }

        talpa_read_unlock(&this->mConfigLock);
    }

    return;

    not_included:
    talpa_read_unlock(&this->mConfigLock);
    report->setRecommendedAction(report, EIA_Allow);

    return;
}

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

static void setPath(void* self, const char* path)
{
    talpa_write_lock(&this->mConfigLock);
    strcpy(this->mPath, path);
    this->mPathLen = strlen(path);
    strcpy(this->mPathConfigData.value, path);
    info("Path set to %s", path);
    if ( !strcmp(path, CFG_PATH_DEFAULT) )
    {
        /* Automatically disable the filter if somebody set the whole root for inclusion */
        disable(this);
    }
    talpa_write_unlock(&this->mConfigLock);
    return;
}

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "FilesystemInclusionProcessor";
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
            enable(this);
        }
        else if (strcmp(value, CFG_ACTION_DISABLE) == 0)
        {
            disable(this);
        }
    }
    else if ( strcmp(name, CFG_INCLUDE_PATH) == 0 )
    {
        setPath(this, value);
    }
    return;
}

/*
 * End of filesystem_inclusion_processor.c
 */

