/*
 * allow_syslog.c
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
#include <linux/sched.h>

#define TALPA_SUBSYS "allow"
#include "common/talpa.h"
#include "allow_syslog.h"

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
static void deleteAllowSyslogFilter(struct tag_AllowSyslogFilter* object);

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
static AllowSyslogFilter template_AllowSyslogFilter =
    {
        {
            examineFile,
            NULL,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteAllowSyslogFilter
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteAllowSyslogFilter
        },
        deleteAllowSyslogFilter,
        TALPA_MUTEX_INIT,
        true,
        "AllowSyslog",
        {
            {NULL, NULL, ALLOWSYSLOGFILTER_CFGDATASIZE, true, true },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_ENABLED }

    };
#define this    ((AllowSyslogFilter*)self)



/*
 * Object creation/destruction.
 */
AllowSyslogFilter* newAllowSyslogFilter(const char *name)
{
    AllowSyslogFilter* object;


    object = talpa_alloc(sizeof(template_AllowSyslogFilter));
    if ( object )
    {
        memcpy(object, &template_AllowSyslogFilter, sizeof(template_AllowSyslogFilter));
        object->i_IInterceptFilter.object = object->i_IConfigurable.object = object;

        talpa_mutex_init(&object->mConfigSerialize);

        strncpy(object->mName, name, sizeof(object->mName)-1);
        object->mName[sizeof(object->mName)-1] = 0x00;

        object->mConfig[0].name  = object->mConfigData.name;
        object->mConfig[0].value = object->mConfigData.value;
    }
    return object;
}

static void deleteAllowSyslogFilter(struct tag_AllowSyslogFilter* object)
{
    talpa_free(object);
    return;
}


static char* actmsg_default = "Unsupported action required";
static char* actmsg_restart = "Standard interceptor processor failure";
static char* actmsg_next = "Unexpected pass through action request";
static char* actmsg_allow = "Unexpected allow action request";
static char* actmsg_deny = "Access denied";
static char* actmsg_error = "Error occurred";
static char* actmsg_timeout = "Timeout occurred";

static char* opmsg_default = "processing unsupported object type";
static char* opmsg_open = "opening";
static char* opmsg_close = "closing";
static char* opmsg_exec = "executing";
static char* opmsg_mount = "mounting";
static char* opmsg_umount = "unmounting";

static inline char *operationString(EFilesystemOperation op)
{
    switch ( op )
    {
        case EFS_Open:
            return opmsg_open;
        case EFS_Close:
            return opmsg_close;
        case EFS_Exec:
            return opmsg_exec;
        case EFS_Mount:
            return opmsg_mount;
        case EFS_Umount:
            return opmsg_umount;
    }

    return opmsg_default;
}

static inline char *actionString(EInterceptAction action)
{
    switch ( action )
    {
        case EIA_Restart:
            return actmsg_restart;
        case EIA_Next:
            return actmsg_next;
        case EIA_Allow:
            return actmsg_allow;
        case EIA_Deny:
            return actmsg_deny;
        case EIA_Error:
            return actmsg_error;
        case EIA_Timeout:
            return actmsg_timeout;
    }

    return actmsg_default;
}

/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    char* opmsg;
    char* actmsg;

    /* Don't log if interrupted by signal on close. */
    if (    (!report->hasBeenExternallyVetted(report->object))
         && (info->operation(info->object) == EFS_Close)
         && (report->errorCode(report->object) == ERESTARTSYS) )
    {
        return;
    }

    /* Don't log unless this is a timeout and error code is unset (allow) */
    if ( (report->recommendedAction(report) != EIA_Timeout)
        || (report->errorCode(report->object) == ETIME) )
    {
        return;
    }

    opmsg = operationString(info->operation(info));
    actmsg = actionString(report->recommendedAction(report));

    info("%s while %s %s on behalf of process %s[%u/%u] owned by %u(%u)/%u(%u) <%d>",
            actmsg, opmsg,
            info->filename(info),
            current->comm, current->tgid, current->pid,
            userInfo->uid(userInfo), userInfo->euid(userInfo), userInfo->gid(userInfo), userInfo->egid(userInfo),
            report->errorCode(report)
        );

    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info)
{
    char* opmsg;
    char* actmsg;

    /* Don't log unless this is a timeout and error code is unset (allow) */
    if ( (report->recommendedAction(report) != EIA_Timeout)
        || (report->errorCode(report->object) == ETIME) )
    {
        return;
    }

    opmsg = operationString(info->operation(info));
    actmsg = actionString(report->recommendedAction(report));

    info("%s while %s %s at %s (%s) on behalf of process %s[%u/%u] owned by %u(%u)/%u(%u) <%d>",
            actmsg, opmsg,
            info->deviceName(info), info->mountPoint(info), info->type(info),
            current->comm, current->tgid, current->pid,
            userInfo->uid(userInfo), userInfo->euid(userInfo), userInfo->gid(userInfo), userInfo->egid(userInfo),
            report->errorCode(report)
        );

    return;
}

static bool enable(void* self)
{
    talpa_mutex_lock(&this->mConfigSerialize);
    if (!this->mEnabled)
    {
        this->mEnabled = true;
        strcpy(this->mConfigData.value, CFG_VALUE_ENABLED);
        info("Enabled");
    }
    talpa_mutex_unlock(&this->mConfigSerialize);
    return true;
}

static void disable(void* self)
{
    talpa_mutex_lock(&this->mConfigSerialize);
    if (this->mEnabled)
    {
        this->mEnabled = false;
        strcpy(this->mConfigData.value, CFG_VALUE_DISABLED);
        info("Disabled");
    }
    talpa_mutex_unlock(&this->mConfigSerialize);
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
    return this->mName;
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
    return;
}

/*
 * End of allow_syslog.c
 */

