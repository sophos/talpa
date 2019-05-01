/*
 * filesystem_exclusion_processor.c
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
#include <linux/stat.h>

#define TALPA_SUBSYS "exclusion"
#include "common/talpa.h"
#include "filesystem_exclusion_processor.h"

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
static void deleteFilesystemExclusionProcessor(struct tag_FilesystemExclusionProcessor* object);
static FSEPObject* findObject(const void* self, talpa_list_head* list, const char* value);
static void freeObject(FSEPObject* obj);
static void deleteObject(void *self, FSEPObject* obj);
static void constructSpecialSet(void* self);
static void doActionString(void* self, talpa_list_head* list, char** set, const char* value);

/*
 * Constants
 */
#define CFG_STATUS           "status"
#define CFG_VALUE_ENABLED    "enabled"
#define CFG_VALUE_DISABLED   "disabled"
#define CFG_ACTION_ENABLE    "enable"
#define CFG_ACTION_DISABLE   "disable"
#define CFG_PATHS            "paths"
#define CFG_FSTYPES          "fstypes"
#define CFG_SPECIALS         "specials"
#define CFG_MOUNTPATHS       "mount-paths"
#define CFG_MOUNTFSTYPES     "mount-fstypes"
#define CFG_VALUE_DUMMY      "(empty)"

#define TALPA_DIR       0x01
#define TALPA_LNK       0x02
#define TALPA_SOCK      0x04
#define TALPA_FIFO      0x08
#define TALPA_BLK       0x10
#define TALPA_CHR       0x20

/*
 * Template Object.
 */
static FilesystemExclusionProcessor template_FilesystemExclusionProcessor =
    {
        {
            examineFile,
            NULL,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteFilesystemExclusionProcessor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteFilesystemExclusionProcessor
        },
        deleteFilesystemExclusionProcessor,
        TALPA_RCU_UNLOCKED(talpa_filesystem_exclusion_processor_config_lock),
        TALPA_MUTEX_INIT,
        true,
        TALPA_LIST_HEAD_INIT(template_FilesystemExclusionProcessor.mPaths),
        TALPA_LIST_HEAD_INIT(template_FilesystemExclusionProcessor.mFilesystems),
        TALPA_LIST_HEAD_INIT(template_FilesystemExclusionProcessor.mMountPaths),
        TALPA_LIST_HEAD_INIT(template_FilesystemExclusionProcessor.mMountFilesystems),
        (TALPA_SOCK | TALPA_LNK | TALPA_BLK | TALPA_DIR | TALPA_CHR | TALPA_FIFO),
        {
            {NULL, NULL, FSEXCPROC_CFGDATASIZE, true, true },
            {NULL, NULL, PATH_MAX, true, false },
            {NULL, NULL, FSEXCPROC_FSCFGDATASIZE, true, false },
            {NULL, NULL, FSEXCPROC_CFGDATASIZE, true, false },
            {NULL, NULL, PATH_MAX, true, false },
            {NULL, NULL, FSEXCPROC_FSCFGDATASIZE, true, false },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_ENABLED },
        { CFG_PATHS, CFG_VALUE_DUMMY },
        { CFG_FSTYPES, CFG_VALUE_DUMMY },
        { CFG_SPECIALS, CFG_VALUE_DUMMY },
        { CFG_MOUNTPATHS, CFG_VALUE_DUMMY },
        { CFG_MOUNTFSTYPES, CFG_VALUE_DUMMY },
        NULL,
        NULL,
        NULL,
        NULL
    };
#define this    ((FilesystemExclusionProcessor*)self)



/*
 * Object creation/destruction.
 */
FilesystemExclusionProcessor* newFilesystemExclusionProcessor(void)
{
    FilesystemExclusionProcessor* object;


    object = talpa_alloc(sizeof(template_FilesystemExclusionProcessor));
    if ( object )
    {
        memcpy(object, &template_FilesystemExclusionProcessor, sizeof(template_FilesystemExclusionProcessor));
        object->i_IInterceptFilter.object = object->i_IConfigurable.object = object;

        object->mConfig[0].name  = object->mStateConfigData.name;
        object->mConfig[0].value = object->mStateConfigData.value;
        object->mConfig[1].name  = object->mPathConfigData.name;
        object->mConfig[1].value = object->mPathConfigData.value;
        object->mConfig[2].name  = object->mFSConfigData.name;
        object->mConfig[2].value = object->mFSConfigData.value;
        object->mConfig[3].name  = object->mSpecialConfigData.name;
        object->mConfig[3].value = object->mSpecialConfigData.value;
        object->mConfig[4].name  = object->mMountPathConfigData.name;
        object->mConfig[4].value = object->mMountPathConfigData.value;
        object->mConfig[5].name  = object->mMountFSConfigData.name;
        object->mConfig[5].value = object->mMountFSConfigData.value;

        talpa_rcu_lock_init(&object->mConfigLock);
        talpa_mutex_init(&object->mConfigSerialize);
        TALPA_INIT_LIST_HEAD(&object->mPaths);
        TALPA_INIT_LIST_HEAD(&object->mFilesystems);
        TALPA_INIT_LIST_HEAD(&object->mMountPaths);
        TALPA_INIT_LIST_HEAD(&object->mMountFilesystems);
        constructSpecialSet(object);
    }
    return object;
}

static void deleteFilesystemExclusionProcessor(struct tag_FilesystemExclusionProcessor* object)
{
    FSEPObject *obj, *tmp;

    talpa_rcu_synchronize();

    talpa_list_for_each_entry_safe(obj, tmp, &object->mPaths, head)
    {
        talpa_list_del(&obj->head);
        freeObject(obj);
    }

    talpa_list_for_each_entry_safe(obj, tmp, &object->mFilesystems, head)
    {
        talpa_list_del(&obj->head);
        freeObject(obj);
    }

    talpa_list_for_each_entry_safe(obj, tmp, &object->mMountPaths, head)
    {
        talpa_list_del(&obj->head);
        freeObject(obj);
    }

    talpa_list_for_each_entry_safe(obj, tmp, &object->mMountFilesystems, head)
    {
        talpa_list_del(&obj->head);
        freeObject(obj);
    }

    talpa_large_free(object->mPathsSet);
    talpa_large_free(object->mFilesystemsSet);
    talpa_large_free(object->mMountPathsSet);
    talpa_large_free(object->mMountFilesystemsSet);

    talpa_free(object);

    return;
}

/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    const char*  checkString = info->fsType(info);
    mode_t mode = info->mode(info);
    unsigned int mask = this->mSpecialsMask;
    FSEPObject*  obj;
    unsigned int checkLen;


    /*
     * Check the file type.
     */
    if (    (S_ISDIR(mode) && (mask & TALPA_DIR)) ||
            (S_ISLNK(mode) && (mask & TALPA_LNK)) ||
            (S_ISFIFO(mode) && (mask & TALPA_FIFO)) ||
            (S_ISSOCK(mode) && (mask & TALPA_SOCK)) ||
            (S_ISBLK(mode) && (mask & TALPA_BLK)) ||
            (S_ISCHR(mode) && (mask & TALPA_CHR))   )
    {
        report->setRecommendedAction(report, EIA_Allow);
        return;
    }

    /*
     * Check the filesystem type.
     */
    talpa_rcu_read_lock(&this->mConfigLock);
    if ( likely(checkString != NULL) )
    {
        checkLen = strlen(checkString);
        talpa_list_for_each_entry_rcu(obj, &this->mFilesystems, head)
        {
            if ( (checkLen == obj->len) && (strcmp(checkString, obj->value) == 0) )
            {
                talpa_rcu_read_unlock(&this->mConfigLock);
                report->setRecommendedAction(report, EIA_Allow);
                return;
            }
        }
    }

    /*
     * Check the filename against the list of excluded paths.
     */
    checkString = info->filename(info);
    if ( likely(checkString != NULL) )
    {
        checkLen = strlen(checkString);
        talpa_list_for_each_entry_rcu(obj, &this->mPaths, head)
        {
            /* Do not exclude the file if the filename is shorter than our filter. */
            if ( checkLen < obj->len )
            {
                continue;
            }

            if ( obj->value[obj->len-1] == '/' )
            {
                /*
                 * We have a directory exclusion - so it can match in full (exact) or in part (subdir).
                 */
                if ( strncmp(checkString, obj->value, obj->len) == 0 )
                {
                    report->setRecommendedAction(report, EIA_Allow);
                    break;
                }
            }
            else
            {
                /*
                 * Its a normal pathname exclusion - must match in full.
                 */
                if ( (checkLen == obj->len) && (strcmp(checkString, obj->value) == 0) )
                {
                    report->setRecommendedAction(report, EIA_Allow);
                    break;
                }
            }
        }
    }

    talpa_rcu_read_unlock(&this->mConfigLock);

    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info)
{
    const char*  checkString = info->type(info);
    FSEPObject*  obj;
    unsigned int checkLen;

    /*
     * Check the filesystem type.
     */

    talpa_rcu_read_lock(&this->mConfigLock);

    if ( likely(checkString != NULL) )
    {
        checkLen = strlen(checkString);
        talpa_list_for_each_entry_rcu(obj, &this->mMountFilesystems, head)
        {
            if ( (checkLen == obj->len) && (strcmp(checkString, obj->value) == 0) )
            {
                goto allow;
            }
        }
    }

    /*
     * Check the deviceName against the list of excluded paths.
     */
    checkString = info->deviceName(info);
    if ( likely(checkString != NULL) )
    {
        checkLen = strlen(checkString);
        talpa_list_for_each_entry_rcu(obj, &this->mMountPaths, head)
        {
            /* Do not exclude the file if the filename is shorter than our filter */
            if ( checkLen < obj->len )
            {
                continue;
            }

            if ( obj->value[obj->len-1] == '/' )
            {
                /*
                 * We have a directory exclusion - so it can match in full (exact) or in part (subdir).
                 */
                if ( strncmp(checkString, obj->value, obj->len) == 0 )
                {
                    goto allow;
                }
            }
            else
            {
                /*
                 * Its a normal pathname exclusion - must match in full.
                 */
                if ( (checkLen == obj->len) && (strcmp(checkString, obj->value) == 0) )
                {
                    goto allow;
                }
            }
        }
    }

    /*
     * Check the mountPoint against the list of excluded paths.
     */
    checkString = info->mountPoint(info);
    if ( likely(checkString != NULL) )
    {
        checkLen = strlen(checkString);
        talpa_list_for_each_entry_rcu(obj, &this->mMountPaths, head)
        {
            /* Do not exclude the file if the filename is shorter than our filter */
            if ( checkLen < obj->len )
            {
                continue;
            }

            if ( obj->value[obj->len-1] == '/' )
            {
                /*
                 * We have a directory exclusion - so it can match in full (exact) or in part (subdir).
                 */
                if ( strncmp(checkString, obj->value, obj->len) == 0 )
                {
                    goto allow;
                }
            }
            else
            {
                /*
                 * Its a normal pathname exclusion - must match in full.
                 */
                if ( (checkLen == obj->len) && (strcmp(checkString, obj->value) == 0) )
                {
                    goto allow;
                }
            }
        }
    }

    talpa_rcu_read_unlock(&this->mConfigLock);

    return;

    allow:
    talpa_rcu_read_unlock(&this->mConfigLock);
    report->setRecommendedAction(report, EIA_Allow);

    return;
}

/*
 * configuration list handling & objects
 */

static FSEPObject* newObject(void *self, const char* string)
{
    FSEPObject* obj = NULL;

    obj = talpa_alloc(sizeof(FSEPObject));

    if ( obj )
    {
        TALPA_INIT_LIST_HEAD(&obj->head);
        obj->len = strlen(string);
        obj->value = talpa_alloc(obj->len + 1);
        if ( !obj->value )
        {
            talpa_free(obj);
            return NULL;
        }
        strcpy(obj->value, string);
    }

    return obj;
}

static void freeObject(FSEPObject* obj)
{
    talpa_free(obj->value);
    talpa_free(obj);

    return;
}

static void deleteObject(void *self, FSEPObject* obj)
{
    talpa_rcu_synchronize();
    freeObject(obj);

    return;
}

#define catState(string, check, name) \
do \
{ \
    if ( this->mSpecialsMask & check ) \
    { \
        strcat(string, "+"); \
    } \
    else \
    { \
        strcat(string, "-"); \
    } \
    strcat(string, name); \
} \
while ( 0 )

static void constructSpecialSet(void* self)
{
    char* out = this->mSpecialConfigData.value;

    *out = 0;

    catState(out, TALPA_DIR, "dir\n");
    catState(out, TALPA_LNK, "symlink\n");
    catState(out, TALPA_FIFO, "fifo\n");
    catState(out, TALPA_SOCK, "socket\n");
    catState(out, TALPA_BLK, "blockdev\n");
    catState(out, TALPA_CHR, "chardev\n");

    return;
}

#undef catState

static void constructStringSet(void* self, talpa_list_head* list, char** set)
{
    unsigned int len;
    unsigned int alloc_len = 0;
    FSEPObject* obj;
    char* newset = NULL;
    char* out;


    /* We are doing the allocation in at least 2-passes.
     * That is because we want to allocate enough storage outside of
     * the lock holding section. */
try_alloc:
    /* We do not allocate anything in first pass. */
    if ( alloc_len )
    {
        newset = talpa_large_alloc(alloc_len);
        if ( !newset )
        {
            err("Failed to create string set!");
            return;
        }
    }

    len = 0;
    talpa_rcu_read_lock(&this->mConfigLock);
    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        len += obj->len + 1;
    }

    /* We will reallocate if the size has increased or this is a second pass (first allocation)/ */
    if ( (len + 1) > alloc_len )
    {
        talpa_rcu_read_unlock(&this->mConfigLock);
        alloc_len = len + 1;
        talpa_large_free(newset);
        goto try_alloc;
    }

    out = newset;
    talpa_large_free(*set);
    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        strcpy(out, obj->value);
        out += obj->len;
        *out++ = '\n';
    }
    if ( out > newset )
    {
        out--;
    }
    *out = 0;
    *set = newset;

    talpa_rcu_read_unlock(&this->mConfigLock);

    return;
}

static void destroyStringSet(void *self, char **set)
{
    talpa_large_free(*set);
    *set = NULL;
    return;
}

static FSEPObject* findObject(const void* self, talpa_list_head* list, const char* value)
{
    FSEPObject *obj;

    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        if ( !strcmp(obj->value, value) )
        {
            return obj;
        }
    }

    return NULL;
}

static FSEPObject* appendObject(void* self, talpa_list_head* list, const char* value)
{
    FSEPObject *obj;


    talpa_rcu_read_lock(&this->mConfigLock);
    obj = findObject(this, list, value);
    talpa_rcu_read_unlock(&this->mConfigLock);
    if ( obj )
    {
        dbg("String already in list!");
        return obj;
    }
    /* No problem here since appends and removes happen from userspace
     * which is serialised. */
    obj = newObject(this, value);
    if ( obj )
    {
        talpa_rcu_write_lock(&this->mConfigLock);
        talpa_list_add_tail_rcu(&obj->head, list);
        talpa_rcu_write_unlock(&this->mConfigLock);
    }

    return obj;
}

static bool removeObject(void *self, talpa_list_head* list, const char* value)
{
    FSEPObject *obj;


    talpa_rcu_write_lock(&this->mConfigLock);
    obj = findObject(this, list, value);
    if ( obj )
    {
        talpa_list_del_rcu(&obj->head);
        talpa_rcu_write_unlock(&this->mConfigLock);
        deleteObject(this, obj);
        return true;
    }
    talpa_rcu_write_unlock(&this->mConfigLock);

    return false;
}

static void doActionString(void* self, talpa_list_head* list, char** set, const char* value)
{
    if ( strlen(value) < 2 )
    {
        return;
    }

    if ( value[0] == '+' )
    {
        appendObject(this, list, &value[1]);
    }
    else if ( value[0] == '-' )
    {
        removeObject(this, list, &value[1]);
    }
    destroyStringSet(this, set);

    return;
}

static void doSpecialString(void* self, const char* value)
{
    unsigned long mask = 0;


    if ( strlen(value) >= 2 )
    {
        if ( !strcmp(&value[1], "dir") )
        {
            mask = TALPA_DIR;
        }
        else if ( !strcmp(&value[1], "symlink") )
        {
            mask = TALPA_LNK;
        }
        else if ( !strcmp(&value[1], "fifo") )
        {
            mask = TALPA_FIFO;
        }
        else if ( !strcmp(&value[1], "socket") )
        {
            mask = TALPA_SOCK;
        }
        else if ( !strcmp(&value[1], "blockdev") )
        {
            mask = TALPA_BLK;
        }
        else if ( !strcmp(&value[1], "chardev") )
        {
            mask = TALPA_CHR;
        }

        if ( value[0] == '+' )
        {
            this->mSpecialsMask |= mask;
        }
        else if ( value[0] == '-' )
        {
            this->mSpecialsMask &= ~(mask);
        }
    }

    constructSpecialSet(this);

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

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "FilesystemExclusionProcessor";
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
        char* retstring = cfgElement->value;


        talpa_mutex_lock(&this->mConfigSerialize);

        if ( !strcmp(cfgElement->name, CFG_PATHS) )
        {
            if ( !this->mPathsSet )
            {
                constructStringSet(this, &this->mPaths, &this->mPathsSet);
            }
            retstring = this->mPathsSet;
        }
        else if ( !strcmp(cfgElement->name, CFG_FSTYPES) )
        {
            if ( !this->mFilesystemsSet )
            {
                constructStringSet(this, &this->mFilesystems, &this->mFilesystemsSet);
            }
            retstring = this->mFilesystemsSet;
        }
        else if ( !strcmp(cfgElement->name, CFG_SPECIALS) )
        {
            retstring = cfgElement->value;
        }
        else if ( !strcmp(cfgElement->name, CFG_MOUNTPATHS) )
        {
            if ( !this->mMountPathsSet )
            {
                constructStringSet(this, &this->mMountPaths, &this->mMountPathsSet);
            }
            retstring = this->mMountPathsSet;
        }
        else if ( !strcmp(cfgElement->name, CFG_MOUNTFSTYPES) )
        {
            if ( !this->mMountFilesystemsSet )
            {
                constructStringSet(this, &this->mMountFilesystems, &this->mMountFilesystemsSet);
            }
            retstring = this->mMountFilesystemsSet;
        }

        talpa_mutex_unlock(&this->mConfigSerialize);

        return retstring;
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

    talpa_mutex_lock(&this->mConfigSerialize);

    if ( strcmp(name, CFG_STATUS) == 0 )
    {
        if ( strcmp(value, CFG_ACTION_ENABLE) == 0 )
        {
            enable(this);
        }
        else if ( strcmp(value, CFG_ACTION_DISABLE) == 0 )
        {
            disable(this);
        }
    }
    else if ( !strcmp(name, CFG_PATHS) )
    {
        doActionString(this, &this->mPaths, &(this->mPathsSet), value);
    }
    else if ( !strcmp(name, CFG_FSTYPES) )
    {
        doActionString(this, &this->mFilesystems, &(this->mFilesystemsSet), value);
    }
    else if ( !strcmp(name, CFG_SPECIALS) )
    {
        doSpecialString(this, value);
    }
    else if ( !strcmp(name, CFG_MOUNTPATHS) )
    {
        doActionString(this, &this->mMountPaths, &(this->mMountPathsSet), value);
    }
    else if ( !strcmp(name, CFG_MOUNTFSTYPES) )
    {
        doActionString(this, &this->mMountFilesystems, &(this->mMountFilesystemsSet), value);
    }

    talpa_mutex_unlock(&this->mConfigSerialize);

    return;
}

/*
 * End of filesystem_exclusion_processor.c
 */

