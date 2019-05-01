/*
 * process_exclusion.c
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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>

#define TALPA_SUBSYS "procexcl"
#include "common/talpa.h"
#include "process_exclusion.h"

#include "platform/alloc.h"

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);

static ProcessExcluded* registerProcess(void* self, pid_t pid, pid_t tid, void* files);
static void deregisterProcess(void* self, ProcessExcluded* obj);
static ProcessExcluded* active(void* self, ProcessExcluded* obj);
static ProcessExcluded* idle(void* self, ProcessExcluded* obj);

static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);

static void deleteProcessExclusionProcessor(struct tag_ProcessExclusionProcessor* object);


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
static ProcessExclusionProcessor template_ProcessExclusionProcessor =
    {
        {
            examineFile,
            NULL,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteProcessExclusionProcessor
        },
        {
            registerProcess,
            deregisterProcess,
            active,
            idle,
            NULL,
            (void (*)(void*))deleteProcessExclusionProcessor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteProcessExclusionProcessor
        },
        deleteProcessExclusionProcessor,
        TALPA_MUTEX_INIT,
        true,
        TALPA_RCU_UNLOCKED(talpa_process_exclusion_processor_excluded_lock),
        { },
        {
            {NULL, NULL, PROCEXCL_CFGDATASIZE, true, true },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_ENABLED }
    };
#define this    ((ProcessExclusionProcessor*)self)



/*
 * Object creation/destruction.
 */
ProcessExclusionProcessor* newProcessExclusionProcessor(void)
{
    ProcessExclusionProcessor* object;


    object = talpa_alloc(sizeof(template_ProcessExclusionProcessor));
    if ( object )
    {
        dbg("object at 0x%p", object);
        memcpy(object, &template_ProcessExclusionProcessor, sizeof(template_ProcessExclusionProcessor));
        object->i_IInterceptFilter.object =
            object->i_IProcessExcluder.object =
            object->i_IConfigurable.object = object;

        talpa_mutex_init(&object->mConfigSerialize);
        talpa_rcu_lock_init(&object->mExcludedLock);
        TALPA_INIT_LIST_HEAD(&object->mExcluded);

        object->mConfig[0].name  = object->mStateConfigData.name;
        object->mConfig[0].value = object->mStateConfigData.value;
    }
    return object;
}

static void deleteProcessExclusionProcessor(struct tag_ProcessExclusionProcessor* object)
{
    ProcessExcluded* process;
    struct list_head* excluded;
    struct list_head* iter;


    /* Cleanup registered processs */
    talpa_rcu_write_lock(&object->mExcludedLock);
    talpa_list_for_each_safe(excluded, iter, &object->mExcluded)
    {
        process = talpa_list_entry(excluded, ProcessExcluded, head);
        talpa_list_del(excluded);
        talpa_free(process);
    }
    talpa_rcu_write_unlock(&object->mExcludedLock);
    talpa_rcu_synchronize();

    talpa_free(object);
    return;
}

static inline bool checkProcessExcluded(const void* self)
{
    ProcessExcluded* excluded;
    pid_t pid = current->tgid;
    void* files = current->files;


    talpa_rcu_read_lock(&this->mExcludedLock);
    talpa_list_for_each_entry_rcu(excluded, &this->mExcluded, head)
    {
        if ( (excluded->files == files) || (excluded->processID == pid) )
        {
            talpa_rcu_read_unlock(&this->mExcludedLock);
            return excluded->active;
        }
    }
    talpa_rcu_read_unlock(&this->mExcludedLock);

    return false;
}

/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    if ( checkProcessExcluded(this) )
    {
        dbg("[intercepted %u-%u-%u] %s - excluded", processParentPID(current), current->tgid, current->pid, current->comm);
        report->setRecommendedAction(report, EIA_Allow);
    }

    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report,
                                const IPersonality* userInfo,
                                const IFilesystemInfo* info)
{
    if ( checkProcessExcluded(this) )
    {
        dbg("[intercepted %u-%u-%u] %s - excluded", processParentPID(current), current->tgid, current->pid, current->comm);
        report->setRecommendedAction(report, EIA_Allow);
    }

    return;
}

/*
 * IProcessExcluder.
 */
static ProcessExcluded* registerProcess(void* self, pid_t pid, pid_t tid, void* files)
{
    ProcessExcluded* process;
    ProcessExcluded* excluded;


    process = talpa_alloc(sizeof(ProcessExcluded));

    talpa_rcu_write_lock(&this->mExcludedLock);

    /* Check if we already have this process */
    talpa_list_for_each_entry_rcu(excluded, &this->mExcluded, head)
    {
        if ( (excluded->processID == pid) || (excluded->files == files) )
        {
            /* Increment reference count if different thread from the
               same process wants to register. */
            if ( excluded->threadID != tid )
            {
                atomic_inc(&excluded->refcnt);
            }
            talpa_rcu_write_unlock(&this->mExcludedLock);
            /* Free this since we don't need it */
            talpa_free(process);
            dbg("Process [%u/%u] re-registered", pid, tid);
            return excluded;
        }
    }

    /* This is a new process, so lets register it */
    if ( process )
    {
        TALPA_INIT_LIST_HEAD(&process->head);
        atomic_set(&process->refcnt, 1);
        process->processID = pid;
        process->threadID = tid;
        process->files = files;
        process->active = false;
        talpa_list_add_tail_rcu(&process->head, &this->mExcluded);
        dbg("Process [%u/%u] registered", process->processID, process->threadID);
    }
    else
    {
        err("Failed to allocate memory for process exclusion!");
    }

    talpa_rcu_write_unlock(&this->mExcludedLock);

    return process;
}

static void deregisterProcess(void* self, ProcessExcluded* obj)
{
    ProcessExcluded* excluded;


    talpa_rcu_write_lock(&this->mExcludedLock);

    /* Check if we know about the process which wants to deregister and do it */
    talpa_list_for_each_entry_rcu(excluded, &this->mExcluded, head)
    {
        if ( excluded == obj )
        {
            /* Only de-register when the last thread is going away. */
            if ( atomic_dec_and_test(&obj->refcnt) )
            {
                talpa_list_del_rcu(&obj->head);
                talpa_rcu_write_unlock(&this->mExcludedLock);
                dbg("Process [%u/%u] deregistered", obj->processID, obj->threadID);
                talpa_rcu_synchronize();
                talpa_free(obj);
            }
            else
            {
                talpa_rcu_write_unlock(&this->mExcludedLock);
            }
            return;
        }
    }

    talpa_rcu_write_unlock(&this->mExcludedLock);

    /* This can happen on core hot-swap */
    dbg("Isolated process [%u/%u] deregistred", current->tgid, current->pid);

    return;
}

static ProcessExcluded* active(void* self, ProcessExcluded* obj)
{
    obj->active = true;
    dbg("Process [%u-%u] Active", obj->processID, obj->threadID);

    return obj;
}

static ProcessExcluded* idle(void* self, ProcessExcluded* obj)
{
    obj->active = false;
    dbg("Process [%u-%u] Idle", obj->processID, obj->threadID);

    return obj;
}


/*
 * Internal configuration.
 */

static bool enable(void* self)
{
    talpa_mutex_lock(&this->mConfigSerialize);
    if (!this->mEnabled)
    {
        this->mEnabled = true;
        strcpy(this->mStateConfigData.value, CFG_VALUE_ENABLED);
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
        strcpy(this->mStateConfigData.value, CFG_VALUE_DISABLED);
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
    return "ProcessExclusionProcessor";
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
 * End of process_exclusion.c
 */

