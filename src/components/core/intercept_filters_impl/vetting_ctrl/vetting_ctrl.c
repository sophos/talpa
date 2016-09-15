/*
 * vetting_ctrl.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2016 Sophos Limited, Oxford, England.
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
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/fcntl.h>


#define TALPA_SUBSYS "vetting"
#include "common/bool.h"
#include "common/talpa.h"
#include "vetting_ctrl.h"
#include "app_ctrl/iportability_app_ctrl.h"
#include "filesystem/efilesystem_operation.h"
#include "platform/glue.h"
#include "platform/quirks.h"
#include "platform/alloc.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
# define TALPA_RESTRICT_OPEN_DURING_EXIT
#endif

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);

static unsigned int queryMinPacketSize(const void* self);
static unsigned int queryMaxPacketSize(const void* self);
static unsigned int queryMinStreamPacket(const void* self);
static unsigned int queryMaxStreamPacket(const void* self);
static VettingClient* initializeClient(void* self);
static void destroyClient(void* self, VettingClient* client);
static struct TalpaProtocolHeader* registerClient(void* self, VettingClient* client, struct TalpaPacket_Register* packet);
static struct TalpaProtocolHeader* deregisterClient(void* self, VettingClient* client, struct TalpaPacket_Deregister* packet);
static struct TalpaProtocolHeader* processPacket(void* self, VettingClient* client, struct TalpaProtocolHeader* packet);
static struct TalpaProtocolHeader* setWaitTimeout(const void* self, VettingClient* client, struct TalpaPacket_SetWaitTimeout* packet);
static bool peekVettingQueue(const void* self, VettingClient* client);
static struct TalpaProtocolHeader* obtainVettingDetails(void* self, VettingClient* client);
static void releaseVettingDetails(const void* self, VettingClient* client);
static struct TalpaProtocolHeader* vettingResponse(void* self, VettingClient* client, struct TalpaPacket_VettingResponse* packet);
static struct TalpaProtocolHeader* streamLength(const void* self, VettingClient* client);
static struct TalpaProtocolHeader* streamSeek(void* self, VettingClient* client, struct TalpaPacket_StreamSeek* packet);
static struct TalpaProtocolHeader* streamRead(void* self, VettingClient* client, struct TalpaPacket_StreamRead* packet);
static struct TalpaProtocolHeader* streamWrite(void* self, VettingClient* client, struct TalpaPacket_StreamWrite* packet);
static struct TalpaProtocolHeader* streamReadAt(void* self, VettingClient* client, struct TalpaPacket_StreamReadAt* packet);
static struct TalpaProtocolHeader* streamWriteAt(void* self, VettingClient* client, struct TalpaPacket_StreamWriteAt* packet);
static struct TalpaProtocolHeader* streamUnlinkFile(void* self, VettingClient* client, struct TalpaPacket_StreamUnlinkFile* packet);
static struct TalpaProtocolHeader* streamTruncate(void* self, VettingClient* client, struct TalpaPacket_StreamTruncate* packet);

static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void constructSpecialSet(void* self);

static void deleteVettingController(struct tag_VettingController* object);

static void destroyVettingDetails(VettingDetails* details);

static VetCtrlConfigObject* findObject(const void* self, talpa_list_head* list, const char* value);
static void freeObject(VetCtrlConfigObject* obj);
static void deleteObject(const void *self, VetCtrlConfigObject* obj);


/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_TIMEOUT         "timeout-ms"
#define CFG_FSTIMEOUT       "fs-timeout-ms"
#define CFG_ROUTING         "routing"
#define CFG_XHACK           "xsmartsched-fix"
#define CFG_GROUPS          "groups"
#define CFG_OPS             "ops"
#define CFG_INTERRUPTIBLE   "interruptible"

#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"
#define CFG_DEFAULT_TIMEOUT 5000
#define CFG_VALUE_TIMEOUT   "5000"
#define CFG_DEFAULT_FSTIMEOUT 60000
#define CFG_VALUE_FSTIMEOUT   "60000"
#define CFG_VALUE_DUMMY     "(empty)"

#define HOOK_OPEN       0x01
#define HOOK_CLOSE      0x02
#define HOOK_EXEC       0x04
#define HOOK_MOUNT      0x10
#define HOOK_UMOUNT     0x20

#define HOOK_DEFAULT (HOOK_OPEN | HOOK_CLOSE | HOOK_EXEC | HOOK_MOUNT | HOOK_UMOUNT)

/*
 * Template Object.
 */
static VettingController template_VettingController =
    {
        {
            examineFile,
            NULL,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteVettingController
        },
        {
            queryMinPacketSize,
            queryMaxPacketSize,
            queryMinStreamPacket,
            queryMaxStreamPacket,
            initializeClient,
            destroyClient,
            registerClient,
            deregisterClient,
            processPacket,
            setWaitTimeout,
            peekVettingQueue,
            obtainVettingDetails,
            releaseVettingDetails,
            vettingResponse,
            streamLength,
            streamSeek,
            streamRead,
            streamWrite,
            streamReadAt,
            streamWriteAt,
            streamUnlinkFile,
            streamTruncate,
            NULL,
            (void (*)(void*))deleteVettingController
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            NULL,
            (void (*)(void*))deleteVettingController
        },
        deleteVettingController,
        true,
        HOOK_DEFAULT,
        TALPA_GROUP_UNLOCKED(talpa_vetting_controller_id_lock),
        0,
        TALPA_RCU_UNLOCKED(talpa_vetting_controller_clients_lock),
        { },
        0,
        { },
        { 0, TALPA_OPEN, TALPA_CLOSE, TALPA_EXEC, TALPA_MOUNT, TALPA_UMOUNT },
        true,
        true,

        TALPA_RCU_UNLOCKED(talpa_vetting_controller_config_lock),
        TALPA_MUTEX_INIT,
        { },
        ATOMIC_INIT(0),
        ATOMIC_INIT(0),
        NULL,

        {
            { NULL, NULL, VETCTRL_CFGDATASIZE, true, true },
            { NULL, NULL, VETCTRL_CFGDATASIZE, true, true },
            { NULL, NULL, VETCTRL_CFGDATASIZE, true, true },
            { NULL, NULL, PATH_MAX, true, false },
#ifdef TALPA_HAS_XHACK
            { NULL, NULL, VETCTRL_CFGDATASIZE, true, true },
#else
            { NULL, NULL, VETCTRL_CFGDATASIZE, false, true },
#endif
            { NULL, NULL, VETCTRL_GROUPSDATASIZE, false, true },
            { NULL, NULL, VETCTRL_OPSDATASIZE, true, true },
            { NULL, NULL, VETCTRL_CFGDATASIZE, true, true },
            { NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_ENABLED },
        { CFG_TIMEOUT, CFG_VALUE_TIMEOUT },
        { CFG_FSTIMEOUT, CFG_VALUE_FSTIMEOUT },
        { CFG_ROUTING, CFG_VALUE_DUMMY },
        { CFG_XHACK, CFG_VALUE_ENABLED },
        { CFG_GROUPS, CFG_VALUE_DUMMY },
        { CFG_OPS, CFG_VALUE_DUMMY },
        { CFG_INTERRUPTIBLE, CFG_VALUE_ENABLED },

        NULL,
        NULL
    };
#define this    ((VettingController*)self)



/*
 * Object creation/destruction.
 */
VettingController* newVettingController(void)
{
    VettingController* object;


    object = talpa_alloc(sizeof(template_VettingController));
    if ( object )
    {
        unsigned int group;

        dbg("object at 0x%p", object);
        memcpy(object, &template_VettingController,sizeof(template_VettingController));
        object->i_IInterceptFilter.object = object->i_IVettingServer.object = object->i_IConfigurable.object = object;

        constructSpecialSet(object);

        object->mFilesystemFactory = TALPA_Portability()->filesystemFactory();
        object->mThreadFactory = TALPA_Portability()->threadandprocessFactory();

        talpa_simple_init(&object->mVettingIDLock);
        talpa_rcu_lock_init(&object->mClientsLock);
        TALPA_INIT_LIST_HEAD(&object->mClients);

        for ( group = 0; group < VETTING_GROUPS; group++ )
        {
            dbg("group %d (0x%p)", group, &object->mGroups[group]);
            talpa_group_lock_init(&object->mGroups[group].lock);
            atomic_set(&object->mGroups[group].numClients, 0);
            init_waitqueue_head(&object->mGroups[group].clientWaitQueue);
            TALPA_INIT_LIST_HEAD(&object->mGroups[group].intercepted);
        }

        talpa_rcu_lock_init(&object->mConfigLock);
        talpa_mutex_init(&object->mConfigSerialize);
        TALPA_INIT_LIST_HEAD(&object->mRoutings);

        atomic_set(&object->mTimeout, CFG_DEFAULT_TIMEOUT);
        atomic_set(&object->mFSTimeout, CFG_DEFAULT_FSTIMEOUT);

        object->mConfig[0].name  = object->mStateConfigData.name;
        object->mConfig[0].value = object->mStateConfigData.value;
        object->mConfig[1].name  = object->mTimeoutConfigData.name;
        object->mConfig[1].value = object->mTimeoutConfigData.value;
        object->mConfig[2].name  = object->mFSTimeoutConfigData.name;
        object->mConfig[2].value = object->mFSTimeoutConfigData.value;
        object->mConfig[3].name  = object->mRoutingConfigData.name;
        object->mConfig[3].value = object->mRoutingConfigData.value;
        object->mConfig[4].name  = object->mXHackConfigData.name;
        object->mConfig[4].value = object->mXHackConfigData.value;
        object->mConfig[5].name  = object->mGroupsConfigData.name;
        object->mConfig[5].value = object->mGroupsConfigData.value;
        object->mConfig[6].name  = object->mOpsConfigData.name;
        object->mConfig[6].value = object->mOpsConfigData.value;
        object->mConfig[7].name  = object->mInterruptibleConfigData.name;
        object->mConfig[7].value = object->mInterruptibleConfigData.value;
    }
    return object;
}

static void deleteVettingController(struct tag_VettingController* object)
{
    VetCtrlConfigObject *obj, *tmp;

    talpa_rcu_synchronize();

    talpa_rcu_write_lock(&object->mConfigLock);
    talpa_list_for_each_entry_safe(obj, tmp, &object->mRoutings, head)
    {
        talpa_list_del(&obj->head);
        freeObject(obj);
    }
    talpa_free(object->mRoutingsSet);
    talpa_rcu_write_unlock(&object->mConfigLock);

    talpa_free(object);

    return;
}

static inline VettingGroup* routeRequest(const void* self, const char* path, unsigned int path_len, const char* fstype, unsigned int fstype_len)
{
    VettingGroup* group;
    VetCtrlConfigObject* obj;
    unsigned int groupID = 0;

    /* To which group should this request go? */
    talpa_rcu_read_lock(&this->mConfigLock);
    talpa_list_for_each_entry_rcu(obj, &this->mRoutings, head)
    {
        switch ( obj->type )
        {
            case FILESYSTEM:
                if ( likely(fstype != NULL) )
                {
                    if ( (fstype_len == obj->len) && !strcmp(fstype, obj->string) )
                    {
                        groupID = obj->group;
                        goto routed;
                    }
                }
                break;
            case PATH:
                if ( likely(path != NULL) )
                {
                    if ( (path_len >= obj->len) && !strncmp(path, obj->string, obj->len) )
                    {
                        groupID = obj->group;
                        goto routed;
                    }
                }
                break;
        }
    }

    routed:
    talpa_rcu_read_unlock(&this->mConfigLock);

    group = &this->mGroups[groupID];
    /* Are there any clients in this group? */
    if ( unlikely(atomic_read(&group->numClients) == 0) )
    {
//         dbg("[intercepted %u-%u-%u] no clients in group %u", processParentPID(current), current->tgid, current->pid, groupID);
        return NULL;
    }

    dbg("[intercepted %u-%u-%u] intercept directed to group %u (0x%p)", processParentPID(current), current->tgid, current->pid, groupID, group);

    return group;
}

static inline void waitVettingResponse(const void* self, VettingGroup* group, VettingDetails* details, const char* filename, atomic_t* timeout)
{
    int ret;
    bool status = this->mInterruptible & this->mXHack;
#ifdef DEBUG
    const char* actmsg;
    static char* actmsg_default = "EIA_Unknown";
    static char* actmsg_restart = "EIA_Restart";
    static char* actmsg_next = "EIA_Next";
    static char* actmsg_allow = "EIA_Allow";
    static char* actmsg_deny = "EIA_Deny";
    static char* actmsg_error = "EIA_Error";
    static char* actmsg_timeout = "EIA_Timeout";
#endif

    talpa_quirk_vc_sleep_init(&status);

    /* Going to sleep now... */
    do
    {
        dbg("[intercepted %u-%u-%u] going to sleep", processParentPID(current), current->tgid, current->pid);

        talpa_quirk_vc_pre_sleep(&status, atomic_read(timeout));
        if (this->mInterruptible)
        {
            ret = talpa_wait_event_interruptible_timeout(details->interceptedWaitQueue, atomic_read(&details->complete) || atomic_read(&details->reopen), msecs_to_jiffies(atomic_read(timeout)));
        }
        else
        {
            ret = talpa_wait_event_killable_timeout(details->interceptedWaitQueue, atomic_read(&details->complete) || atomic_read(&details->reopen), msecs_to_jiffies(atomic_read(timeout)));
        }
        talpa_quirk_vc_post_sleep(&status);

        /* Woken up because intercept is complete? */
        if ( likely(!ret) )
        {
            if ( likely(atomic_read(&details->complete) > 0) )
            {
#ifdef DEBUG
                switch ( details->report->recommendedAction(details->report->object) )
                {
                    case EIA_Restart:
                        actmsg = actmsg_restart;
                        break;
                    case EIA_Next:
                        actmsg = actmsg_next;
                        break;
                    case EIA_Allow:
                        actmsg = actmsg_allow;
                        break;
                    case EIA_Deny:
                        actmsg = actmsg_deny;
                        break;
                    case EIA_Error:
                        actmsg = actmsg_error;
                        break;
                    case EIA_Timeout:
                        actmsg = actmsg_timeout;
                        break;
                    default:
                        actmsg = actmsg_default;
                }
                dbg("[intercepted %u-%u-%u] Vetting complete - %s", processParentPID(current), current->tgid, current->pid, actmsg);
#endif
                break;
            }
            else if ( atomic_read(&details->reopen) )
            {
                loff_t offset;
                void* fsobj1;
                void* fsobj2;
                int ret = -ENODATA;


                /* Remember the current file position and close the file */
                offset = details->file->seek(details->file->object, 0, 1);
                details->file->close(details->file->object);

                dbg("[intercepted %u-%u-%u] requested re-open for writting (offset was %ld)", processParentPID(current), current->tgid, current->pid, (long int) offset);

                /* Try opening with low-level filesystem objects first */
                if ( details->fileInfo->fsObjects(details->fileInfo->object, &fsobj1, &fsobj2) )
                {
                    ret = details->file->openDentry(details->file->object, fsobj1, fsobj2, O_RDWR | O_LARGEFILE, true);
                }

                /* If that failed or wasn't attempted try with opening via filename */
                if ( ret && filename )
                {
                    ret = details->file->open(details->file->object, filename, O_RDWR | O_LARGEFILE, true);
                }

                if ( (ret == 0) && (offset != 0) )
                {
                    /* Restore previous offset */
                    loff_t res = details->file->seek(details->file->object, offset, 0);
                    if ( res != offset )
                    {
                        err("Failed to re-position in file!");
                        details->file->close(details->file->object);
                        if ( res < 0 )
                        {
                            ret = res;
                        }
                        else
                        {
                            ret = -ESPIPE;
                        }
                    }
                    else
                    {
                        dbg("[intercepted %u-%u-%u] offset %ld restored", processParentPID(current), current->tgid, current->pid, (long int) offset);
                    }
                }
                else
                {
                    dbg("[intercepted %u-%u-%u] re-open failed (%d)", processParentPID(current), current->tgid, current->pid, ret);
                }

                atomic_set(&details->reopen, 0);
                talpa_complete(&details->reopenCompletion);
            }
        }
        /* Timeout expired or signal received? */
        else if ( unlikely(ret < 0) )
        {
            talpa_list_head* posptr;


            if ( ret == -ETIME )
            {
                /* Go back to sleep if we have timeouted while external
                   filesystem operation is in progress. Or if there was some
                   activity in the meantime. */
                if ( details->externalOperation || (time_diff(details->lastActivity, jiffies) < msecs_to_jiffies(atomic_read(timeout))) )
                {
                    continue;
                }
            }

            /* Unlink the details if they are still on the list */
            talpa_group_lock(&group->lock);
            talpa_list_for_each(posptr, &group->intercepted)
            {
                if ( posptr == &details->head )
                {
                    dbg("[intercepted %u-%u-%u] unlinking details from the intercepted list", processParentPID(current), current->tgid, current->pid);
                    talpa_list_del(&details->head);
                    break;
                }
            }
            talpa_group_unlock(&group->lock);
            if ( ret == -ETIME )
            {
                dbg("[intercepted %u-%u-%u] timeout", processParentPID(current), current->tgid, current->pid);
                details->report->setRecommendedAction(details->report->object, EIA_Timeout);
            }
            else
            {
                dbg("[intercepted %u-%u-%u] interrupted", processParentPID(current), current->tgid, current->pid);
                details->report->setRecommendedAction(details->report->object, EIA_Error);
                details->report->setErrorCode(details->report->object, ERESTARTSYS);
            }
            break;
        }
    } while (true); /* We are sleeping until success or error breaks the loop */

    atomic_set(&details->clientGone, 1);
    return;
}

static inline bool excludeClient(const void* self)
{
    VettingClient* client;
    struct task_struct* intercepted = current;

    talpa_rcu_read_lock(&this->mClientsLock);
    talpa_list_for_each_entry_rcu(client, &this->mClients, head)
    {
        if ( unlikely( client->process == intercepted ) )
        {
            talpa_rcu_read_unlock(&this->mClientsLock);
            return true;
        }
    }
    talpa_rcu_read_unlock(&this->mClientsLock);

    return false;
}

/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    const char* filename;
    const char* fstype;
    unsigned int len;
    unsigned int filename_len = 0;
    unsigned int fstype_len = 0;
    VettingDetails* details;
    VettingGroup* group;
    IThreadInfo* threadInfo;
    unsigned int rootdir_len = 0;
    const char* rootdir;
    unsigned int operation;
    int ret;
    char* local_filename;
    struct TalpaPacket_VettingDetails* packet;


    operation = info->operation(info);
    if (!(    ((operation == EFS_Open) && (this->mVettingMask&HOOK_OPEN))
           || ((operation == EFS_Close) && (this->mVettingMask&HOOK_CLOSE))
           || ((operation == EFS_Exec) && (this->mVettingMask&HOOK_EXEC)) ))
    {
        return;
    }

    if ( unlikely(excludeClient(this) == true) )
    {
        return;
    }

    filename = info->filename(info);
    if ( likely(filename != NULL) )
    {
        filename_len = strlen(filename);
    }
    fstype = info->fsType(info);
    if ( likely(fstype != NULL) )
    {
        fstype_len = strlen(fstype);
    }

    group = routeRequest(this, filename, filename_len, fstype, fstype_len);
    if ( unlikely(!group) )
    {
        return;
    }

    /* Obtain ThreadInfo */
    threadInfo = this->mThreadFactory->newThreadInfo(this->mThreadFactory);
    if ( unlikely(!threadInfo) )
    {
        err("Failed to obtain thread info!");
        return;
    }

    /* Construct a new VettingDetail */
    details = talpa_alloc(sizeof(VettingDetails));
    if ( unlikely(!details) )
    {
        err("Not enough memory to create vetting details!");
        threadInfo->delete(threadInfo);
        return;
    }

    dbg("[intercepted %u-%u-%u] allocated %lu bytes at 0x%p for vetting details", processParentPID(current), current->tgid, current->pid, (long unsigned int) sizeof(VettingDetails), details);

    /* See how much memory do we need for VettingDetails packet */
    rootdir = threadInfo->rootDir(threadInfo);

    len = sizeof(struct TalpaPacket_VettingDetails);
    len += sizeof(struct TalpaPacketFragment_FileDetails);
    if ( likely(filename != NULL) )
    {
        len += filename_len + 1;
    }
    if ( likely(rootdir != NULL) )
    {
        rootdir_len = strlen(rootdir);
        /* Accomodate lazy userspace by saying that this process has no root. Poor process. ;( */
        if ( likely(rootdir_len == 1) )
        {
            rootdir_len = 0;
        }
    }

    /* Allocate it */
    packet = talpa_alloc(len);
    if ( unlikely(!packet) )
    {
        err("Not enough memory to create vetting details packet!");
        threadInfo->delete(threadInfo);
        talpa_free(details);
        return;
    }

    dbg("[intercepted %u-%u-%u] allocated %u bytes at 0x%p for vetting details packet", processParentPID(current), current->tgid, current->pid, len, packet);

    /* Fill in the packet */
    packet->header.version = TALPA_PROTOCOL_VERSION;
    packet->header.payloadLength = len - sizeof(struct TalpaProtocolHeader);
    packet->processID = threadInfo->processId(threadInfo);
    packet->threadID = threadInfo->threadId(threadInfo);
    packet->rootdir_len = rootdir_len;
    packet->uid = userInfo->uid(userInfo);
    packet->euid = userInfo->euid(userInfo);
    packet->fsuid = userInfo->fsuid(userInfo);
    packet->gid = userInfo->gid(userInfo);
    packet->egid = userInfo->egid(userInfo);
    {
        struct TalpaPacketFragment_FileDetails* file = (struct TalpaPacketFragment_FileDetails *)(((char *)packet) + sizeof(struct TalpaPacket_VettingDetails));
        file->operation = this->mFOPLookup[operation];
        file->flags = info->flags(info);
        file->mode = info->mode(info);
        if ( likely(filename != NULL) )
        {
            strcpy(((char *)file) + sizeof(struct TalpaPacketFragment_FileDetails), filename);
        }
    }

    /* Fill in the rest... */
    TALPA_INIT_LIST_HEAD(&details->head);
    atomic_set(&details->refcnt, 1);
    init_waitqueue_head(&details->interceptedWaitQueue);
    talpa_init_completion(&details->reopenCompletion);
    atomic_set(&details->reopen, 0);
    atomic_set(&details->clientGone, 0);
    details->externalOperation = false;
    details->lastActivity = jiffies;
    details->report = report;
    details->userInfo = (IPersonality *)userInfo;
    details->threadInfo = (IThreadInfo *)threadInfo;
    details->fileInfo = (IFileInfo *)info;
    details->filesystemInfo = NULL;
    details->extendedInfoRequested = false;
    details->extendedInfo = NULL;
    details->vettingDetails = (struct TalpaProtocolHeader *)packet;
    details->packet = NULL;

    details->responseRequired = true;

    packet->header.type = TALPA_PKT_FILEDETAIL;
    packet->responseReqd = TALPA_RESPOND;
    packet->extOffset = 0;

    atomic_set(&details->complete, 0);

    /* See did we get the File object? */
    if ( file == NULL )
    {
        file = this->mFilesystemFactory->newFile(this->mFilesystemFactory);
        dbg("Created file object 0x%p", file);
    }
    else
    {
        file->get(file->object);
        dbg("Took file object 0x%p", file);
    }

    details->file = file;

    ret = -ENOMEM;

    if ( unlikely( !file ) )
    {
        dbg("[intercepted %u-%u-%u] File object not available", processParentPID(current), current->tgid, current->pid);
        report->setRecommendedAction(report->object, EIA_Error);
        report->setErrorCode(report->object, -ret);
        talpa_free(packet);
        talpa_free(details);
        threadInfo->delete(threadInfo);
        return;
    }

    local_filename = (char *)filename;

    if ( likely( !file->isOpen(file->object) ) )
    {
        void* fsobj1;
        void* fsobj2;
        unsigned int openFlags = O_RDONLY | O_LARGEFILE;
        unsigned int openDentryFlags;

#ifdef FMODE_NONOTIFY
        openFlags |= FMODE_NONOTIFY;
#endif

        openDentryFlags = openFlags;

        /* If low-level filesystem objects are available open the file using them. */
        if ( likely( (operation != EFS_Exec) && (info->fsObjects(info, &fsobj1, &fsobj2) == true) ) )
        {
            ret = details->file->openDentry(file->object, fsobj1, fsobj2, openDentryFlags, operation != EFS_Close);
        }

        /* If open via fs object failed or wasn't attempted try opening via filename. */
        if ( ret != 0 )
        {
            if ( local_filename )
            {
                /* Use just the process relative part of the filename if the process is
                    not at the system root. It used
                    to be rootdir_len > 1 but userspace wants to have a special case. */
                if ( unlikely( rootdir_len > 0 ) )
                {
                    local_filename += rootdir_len;
                }


#ifdef TALPA_RESTRICT_OPEN_DURING_EXIT
                if ((current->flags & PF_EXITING) == 0)
                {
#endif
                    /* Open the file for the stream server. Use the appropriate method depending on operation code. */
                    if ( unlikely( operation == EFS_Exec ) )
                    {
                        ret = details->file->openExec(file->object, local_filename);
                    }
                    else
                    {
                        dbg("[intercepted %u-%u-%u] failed to openDentry %d - trying open of %s",processParentPID(current), current->tgid, current->pid, ret,local_filename);
                        ret = details->file->open(file->object, local_filename, openFlags, operation != EFS_Close);
                        /* We cannot distinguish between open and exec with vfs interceptor
                        so it is possible that this failed because of the lack of read permission.
                        Try to with open_exec as a last resort. */
                        if ( unlikely( ret == -EACCES ) )
                        {
                            ret = details->file->openExec(file->object, local_filename);
                        }
                    }
#ifdef TALPA_RESTRICT_OPEN_DURING_EXIT
                }
                else
                {
                    dbg("[intercepted %u-%u-%u] failed to openDentry %d - can't open %s due to process exiting",processParentPID(current), current->tgid, current->pid, ret,local_filename);
                }
#endif
            }
            else
            {
                ret = -ENODATA;
            }
        }

        if ( unlikely( ret != 0 ) )
        {
            err("[intercepted %u-%u-%u] Open failed (%d), will have no stream", processParentPID(current), current->tgid, current->pid, ret);
        }
        else
        {
            dbg("[intercepted %u-%u-%u] Opened readonly for op=%d", processParentPID(current), current->tgid, current->pid, operation);
        }
    }
    else
    {
        dbg("[intercepted %u-%u-%u] File already open", processParentPID(current), current->tgid, current->pid);
    }

    /* Get the next vettingId */
    talpa_simple_lock(&this->mVettingIDLock);
    packet->vettingID = details->vettingID = ++this->mNextVettingID;
    talpa_simple_unlock(&this->mVettingIDLock);
    dbg("[intercepted %u-%u-%u] vettingID = %u", processParentPID(current), current->tgid, current->pid, details->vettingID);

    /* Increase the reference count on objects provided by standard intercept process. */
    /* Note, file is taken earlier above! */
    report->get(report);
    userInfo->get(userInfo);
    info->get(info);

    /* Insert the details on a list */
    talpa_group_lock(&group->lock);
    talpa_list_add_tail(&details->head, &group->intercepted);
    talpa_group_unlock(&group->lock);

    /* Wake up the clients */
    wake_up(&group->clientWaitQueue);

    /* Wait for the response from vetting client */
    waitVettingResponse(this, group, details, local_filename, &this->mTimeout);

    /* Now returning control to intercepted process,
        destroy everything we have created. Since objects are reference counted
        it is safe to do so even if somebody else is still using them */
    destroyVettingDetails(details);

    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report,
                                const IPersonality* userInfo,
                                const IFilesystemInfo* info)
{
    const char* path;
    const char* dev;
    const char* fstype;
    unsigned int len;
    unsigned int path_len = 0;
    unsigned int dev_len = 0;
    unsigned int fstype_len = 0;
    VettingDetails* details;
    VettingGroup* group;
    IThreadInfo* threadInfo;
    unsigned int rootdir_len = 0;
    const char* rootdir;
    unsigned int operation;
    struct TalpaPacket_VettingDetails* packet;


    operation = info->operation(info);
    if (!(    ((operation == EFS_Mount) && (this->mVettingMask&HOOK_MOUNT))
           || ((operation == EFS_Umount) && (this->mVettingMask&HOOK_UMOUNT)) ))
    {
        return;
    }

    if ( excludeClient(this) )
    {
        return;
    }

    path = info->mountPoint(info);
    dev = info->deviceName(info);
    fstype = info->type(info);

    if ( path )
    {
        path_len = strlen(path);
    }

    if ( likely(dev != NULL) )
    {
        dev_len = strlen(dev);
    }

    if ( fstype )
    {
        fstype_len = strlen(fstype);
    }

    group = routeRequest(this, path, path_len, fstype, fstype_len);
    if ( unlikely(!group) )
    {
        return;
    }

    /* Obtain ThreadInfo */
    threadInfo = this->mThreadFactory->newThreadInfo(this->mThreadFactory);
    if ( unlikely(!threadInfo) )
    {
        err("Failed to obtain thread info!");
        return;
    }

    /* Construct a new VettingDetail */
    details = talpa_alloc(sizeof(VettingDetails));
    if ( unlikely(!details) )
    {
        err("Not enough memory to create vetting details!");
        threadInfo->delete(threadInfo);
        return;
    }

    dbg("[intercepted %u-%u-%u] allocated %lu bytes at 0x%p for vetting details", processParentPID(current), current->tgid, current->pid, (long unsigned int) sizeof(VettingDetails), details);

    /* See how much memory do we need for VettingDetails packet */
    rootdir = threadInfo->rootDir(threadInfo);

    len = sizeof(struct TalpaPacket_VettingDetails) + sizeof(struct TalpaPacketFragment_FilesystemDetails);
    if ( likely(rootdir != NULL) )
    {
        rootdir_len = strlen(rootdir);
        /* See comment in examineFile */
        if ( likely(rootdir_len == 1) )
        {
            rootdir_len = 0;
        }
    }
    len += dev_len + 1;
    len += path_len + 1;
    len += fstype_len + 1;

    /* Allocate it */
    packet = talpa_alloc(len);
    if ( unlikely(!packet) )
    {
        err("Not enough memory to create vetting details packet!");
        threadInfo->delete(threadInfo);
        talpa_free(details);
        return;
    }

    dbg("[intercepted %u-%u-%u] allocated %u bytes at 0x%p for vetting details packet", processParentPID(current), current->tgid, current->pid, len, packet);

    /* Fill in the packet */
    packet->header.version = TALPA_PROTOCOL_VERSION;
    packet->header.payloadLength = len - sizeof(struct TalpaProtocolHeader);
    packet->processID = threadInfo->processId(threadInfo);
    packet->threadID = threadInfo->threadId(threadInfo);
    packet->rootdir_len = rootdir_len;
    packet->uid = userInfo->uid(userInfo);
    packet->euid = userInfo->euid(userInfo);
    packet->fsuid = userInfo->fsuid(userInfo);
    packet->gid = userInfo->gid(userInfo);
    packet->egid = userInfo->egid(userInfo);
    {
        struct TalpaPacketFragment_FilesystemDetails* filesystem = (struct TalpaPacketFragment_FilesystemDetails *)(((char *)packet) + sizeof(struct TalpaPacket_VettingDetails));
        filesystem->operation = this->mFOPLookup[operation];
        filesystem->device_offset = sizeof(struct TalpaPacket_VettingDetails) - sizeof(struct TalpaProtocolHeader) + sizeof(struct TalpaPacketFragment_FilesystemDetails);
        filesystem->mountpoint_offset = filesystem->device_offset + dev_len + 1;
        filesystem->fstype_offset = filesystem->mountpoint_offset + path_len + 1;
        if ( likely(dev != NULL) )
        {
            strcpy(((char *)packet) + sizeof(struct TalpaProtocolHeader) + filesystem->device_offset, dev);
        }
        else
        {
            *(((char *)packet) + filesystem->device_offset + sizeof(struct TalpaProtocolHeader)) = 0;
        }
        if ( path )
        {
            strcpy(((char *)packet) + sizeof(struct TalpaProtocolHeader) + filesystem->mountpoint_offset, path);
        }
        else
        {
            *(((char *)packet) + filesystem->mountpoint_offset + sizeof(struct TalpaProtocolHeader)) = 0;
        }
        if ( fstype )
        {
            strcpy(((char *)packet) + sizeof(struct TalpaProtocolHeader) + filesystem->fstype_offset, fstype);
        }
        else
        {
            *(((char *)packet) + filesystem->fstype_offset + sizeof(struct TalpaProtocolHeader)) = 0;
        }
    }

    /* Fill in the rest... */
    TALPA_INIT_LIST_HEAD(&details->head);
    atomic_set(&details->refcnt, 1);
    init_waitqueue_head(&details->interceptedWaitQueue);
    talpa_init_completion(&details->reopenCompletion);
    atomic_set(&details->reopen, 0);
    details->externalOperation = false;
    details->lastActivity = jiffies;
    details->report = report;
    details->userInfo = (IPersonality *)userInfo;
    details->threadInfo = (IThreadInfo *)threadInfo;
    details->fileInfo = NULL;
    details->filesystemInfo = (IFilesystemInfo *)info;
    details->file = NULL;
    details->extendedInfoRequested = false;
    details->extendedInfo = NULL;
    details->vettingDetails = (struct TalpaProtocolHeader *)packet;
    details->packet = NULL;

    details->responseRequired = true;

    packet->header.type = TALPA_PKT_FILESYSTEMDETAIL;
    packet->responseReqd = TALPA_RESPOND;
    packet->extOffset = 0;

    atomic_set(&details->complete, 0);

    /* Get the next vettingId */
    talpa_simple_lock(&this->mVettingIDLock);
    packet->vettingID = details->vettingID = ++this->mNextVettingID;
    talpa_simple_unlock(&this->mVettingIDLock);
    dbg("[intercepted %u-%u-%u] vettingID = %u", processParentPID(current), current->tgid, current->pid, details->vettingID);

    /* Increase the reference count on objects provided by standard intercept process. */
    report->get(report);
    userInfo->get(userInfo);
    info->get(info);

    /* Insert the details on a list */
    talpa_group_lock(&group->lock);
    talpa_list_add_tail(&details->head, &group->intercepted);
    talpa_group_unlock(&group->lock);

    /* Wake up the clients */
    wake_up(&group->clientWaitQueue);

    /* Wait for the response from vetting client */
    waitVettingResponse(this, group, details, NULL, &this->mFSTimeout);

    /* Now returning control to intercepted process,
        destroy everything we have created. Since objects are reference counted
        it is safe to do so even if somebody else is still using them */
    destroyVettingDetails(details);

    return;
}

/*
 * configuration list handling & objects
 */

static VetCtrlConfigObject* newObject(const void *self, EVetCtrlRoutingType type, const char* string, unsigned int group)
{
    VetCtrlConfigObject* obj = NULL;

    obj = talpa_alloc(sizeof(VetCtrlConfigObject));

    if ( obj )
    {
        TALPA_INIT_LIST_HEAD(&obj->head);
        obj->type = type;
        obj->group = group;
        obj->len = strlen(string);
        obj->string = talpa_alloc(obj->len + 1);
        if ( !obj->string )
        {
            talpa_free(obj);
            return NULL;
        }
        strcpy(obj->string, string);
    }

    return obj;
}

static void freeObject(VetCtrlConfigObject* obj)
{
    talpa_free(obj->string);
    talpa_free(obj);

    return;
}

static void deleteObject(const void *self, VetCtrlConfigObject* obj)
{
    talpa_rcu_synchronize();
    freeObject(obj);

    return;
}

static void constructStringSet(const void* self, talpa_list_head* list, char** set)
{
    unsigned int len;
    unsigned int alloc_len = 0;
    VetCtrlConfigObject* obj;
    char* newset = NULL;
    char* out;


    /* We are doing the allocation in at least 2-passes.
     * That is because we want to allocate enough storage outside of
     * the lock holding section. */
try_alloc:
    /* We do not allocate anything in first pass. */
    if ( alloc_len )
    {
        newset = talpa_alloc(alloc_len);
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
        len += 8 + 10 + obj->len + 1 + 10;
    }

    /* We will reallocate if the size has increased or this is a second pass (first allocation)/ */
    if ( (len + 1) > alloc_len )
    {
        talpa_rcu_read_unlock(&this->mConfigLock);
        alloc_len = len + 1;
        talpa_free(newset);
        goto try_alloc;
    }

    out = newset;
    talpa_free(*set);
    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        len = 0;
        switch ( obj->type )
        {
            case FILESYSTEM:
                strcpy(out, "fs:");
                out += 3;
                break;
            case PATH:
                strcpy(out, "path:");
                out += 5;
                break;
            default:
                len = sprintf(out, "unknown:%u", obj->type);
                out += len;
        }
        len = sprintf(out, "%s:%u\n", obj->string, obj->group);
        out += len;
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
    talpa_free(*set);
    *set = NULL;
    return;
}

static VetCtrlConfigObject* findObject(const void* self, talpa_list_head* list, const char* value)
{
    VetCtrlConfigObject *obj;

    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        if ( !strcmp(obj->string, value) )
        {
            return obj;
        }
    }

    return NULL;
}

static VetCtrlConfigObject* appendObject(const void* self, talpa_list_head* list, EVetCtrlRoutingType type, const char* value, unsigned int group)
{
    VetCtrlConfigObject *obj;

    talpa_rcu_read_lock(&this->mConfigLock);
    obj = findObject(this, list, value);
    talpa_rcu_read_unlock(&this->mConfigLock);
    if ( obj )
    {
        obj->group = group;
        switch ( obj->type )
        {
            case FILESYSTEM:
                info("Filesystem %s re-routed to group %u", value, group);
                break;
            case PATH:
                info("Path %s re-routed to group %u", value, group);
                break;
            default:
                err("Unsupported routing type!");
        }
        return obj;
    }
    /* No problem here since appends and removes happen from userspace
     * which is serialised. */
    obj = newObject(this, type, value, group);
    if ( obj )
    {
        talpa_rcu_write_lock(&this->mConfigLock);
        talpa_list_add_tail_rcu(&obj->head, list );
        talpa_rcu_write_unlock(&this->mConfigLock);
        switch ( obj->type )
        {
            case FILESYSTEM:
                info("Filesystem %s routed to group %u", value, group);
                break;
            case PATH:
                info("Path %s routed to group %u", value, group);
                break;
            default:
                err("Unsupported routing type!");
        }
    }

    return obj;
}

static bool removeObject(const void *self, talpa_list_head* list, const char* value)
{
    VetCtrlConfigObject *obj;

    talpa_rcu_write_lock(&this->mConfigLock);
    obj = findObject(this, list, value);
    if ( obj )
    {
        talpa_list_del_rcu(&obj->head);
        talpa_rcu_write_unlock(&this->mConfigLock);
        deleteObject(this, obj);
        switch ( obj->type )
        {
            case FILESYSTEM:
                info("Filesystem %s removed from routing table", value);
                break;
            case PATH:
                info("Path %s removed from routing table", value);
                break;
        }
        return true;
    }
    talpa_rcu_write_unlock(&this->mConfigLock);

    return false;
}

static void doActionString(const void* self, talpa_list_head* list, char** set, const char* value)
{
    if ( strlen(value) < 2 )
    {
        return;
    }

    if ( value[0] == '+' )
    {
        const char* type_string;
        char* value_string;
        char* group_string;

        type_string = &value[1];
        value_string = strchr(type_string, ':');
        if ( value_string )
        {
            EVetCtrlRoutingType type = 0;

            *value_string++ = 0;

            if ( !strcmp(type_string, "fs") )
            {
                type = FILESYSTEM;
            }
            else if ( !strcmp(type_string, "path") )
            {
                type = PATH;
            }

            if ( (type > 0) && strlen(value_string) )
            {
                group_string = strchr(value_string, ':');
                if ( group_string )
                {
                    *group_string++ = 0;
                    if ( strlen(group_string) )
                    {
                        unsigned int group;
                        char* res;

                        group = simple_strtoul(group_string, &res, 10);
                        appendObject(this, list, type, value_string, group);
                        destroyStringSet(this, set);
                        return;
                    }
                }
            }
        }

        err("Syntax error in routing command!");
    }
    else if ( value[0] == '-' )
    {
        removeObject(this, list, &value[1]);
        destroyStringSet(this, set);
    }

    return;
}


/*
 * IVettingServer.
 */

static unsigned int queryMinPacketSize(const void* self)
{
    unsigned int mininsize = ~0;

    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_Register));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_Deregister));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_SetWaitTimeout));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_ObtainVettingDetails));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_VettingResponse));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_StreamLength));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_StreamSeek));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_StreamRead));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_StreamWrite));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_StreamReadAt));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_StreamWriteAt));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_StreamUnlinkFile));
    mininsize = MIN(mininsize, sizeof(struct TalpaPacket_StreamTruncate));

    return mininsize;
}

static unsigned int queryMaxPacketSize(const void* self)
{
    unsigned int maxinsize = 0;

    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_Register));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_Deregister));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_SetWaitTimeout));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_ObtainVettingDetails));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_VettingResponse));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_StreamLength));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_StreamSeek));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_StreamRead));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_StreamWrite));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_StreamReadAt));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_StreamWriteAt));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_StreamUnlinkFile));
    maxinsize = MAX(maxinsize, sizeof(struct TalpaPacket_StreamTruncate));

    return maxinsize;
}

static unsigned int queryMinStreamPacket(const void* self)
{
    return MIN_STREAM_PACKET_SIZE;
}

static unsigned int queryMaxStreamPacket(const void* self)
{
    return MAX_STREAM_PACKET_SIZE;
}

static VettingClient* initializeClient(void* self)
{
    VettingClient* client;

    client = talpa_zalloc(sizeof(VettingClient));

    if ( !client )
    {
        err("Failed to allocate client!");
        return NULL;
    }

    client->streamSize = MAX_STREAM_PACKET_SIZE;

    while ( client->streamSize >= MIN_STREAM_PACKET_SIZE )
    {
        client->stream = talpa_alloc(client->streamSize);
        if ( client->stream )
        {
            break;
        }
        client->streamSize >>= 1;
    }

    /* Account for the posibility that max packet size is very small to begin with */
    if ( !client->stream )
    {
        client->stream = talpa_alloc(client->streamSize);
    }

    if ( !client->stream )
    {
        err("Failed to allocate stream buffer!");
        talpa_free(client);
        return NULL;
    }

    dbg("allocated %u bytes for stream interface", client->streamSize);

    /* Decrement by carrier packet size so that the checks in stream methods are simpler */
    client->streamSize -= sizeof(struct TalpaPacket_StreamData);

    atomic_set(&client->registered, 0);
    client->process = current;
    client->response.header.version = TALPA_PROTOCOL_VERSION;

    dbg("Client 0x%p initialized", client);
    return client;
}

static void destroyClient(void* self, VettingClient* client)
{
    if ( atomic_read(&client->registered) )
    {
        warn("[%u] Abnormal client exit!", (unsigned int)client->id);

        deregisterClient(this, client, NULL);
    }

    talpa_free(client->stream);
    talpa_free(client);

    return;
}

#define pktreturn_ok \
do \
{ \
    client->response.header.type = TALPA_PKT_OK; \
    client->response.header.payloadLength = 0; \
    return &client->response.header; \
} while (0)

#define pktreturn_fail(code) \
do \
{ \
    client->response.header.type = TALPA_PKT_FAIL; \
    client->response.header.payloadLength = 1; \
    client->response.errorCode = (code); \
    return &client->response.header; \
} while (0)

#define pktreturn_stream(payloadlen, streamlen) \
do \
{ \
    atomic_set(&client->instream, 1); \
    client->stream->header.payloadLength = (payloadlen); \
    client->stream->size = (streamlen); \
    dbg("stream prepared, packet payload=%u, streamlen=%u", (payloadlen), (streamlen)); \
    return &client->stream->header; \
} while (0)


static struct TalpaProtocolHeader* registerClient(void* self, VettingClient* client, struct TalpaPacket_Register* packet)
{
    uint32_t groupID;
    VettingGroup* group;


    if ( packet->header.version != TALPA_PROTOCOL_VERSION )
    {
        dbg("[%u] Protocol mismatch!", (unsigned int)client->id);
        pktreturn_fail(-EPROTO);
    }

    groupID = packet->group;
    if ( groupID > 7 )
    {
        dbg("Group %u out of range!", groupID);
        pktreturn_fail(-ECHRNG);
    }

    group = &(this->mGroups[groupID]);
    dbg("[client %u-%u-%u] register client 0x%p to group %u (0x%p)", processParentPID(current), current->tgid, current->pid, client, groupID, group);
    TALPA_INIT_LIST_HEAD(&client->head);
    client->group = group;
    client->groupID = groupID;
    atomic_set(&client->vetting, 0);
    client->timeout_ms = 0;
    client->currentVettingID = 0;
    client->vettingDetails = NULL;
    client->extDetailsRequested = false;
    client->stream->header.version = TALPA_PROTOCOL_VERSION;
    client->stream->header.type = TALPA_PKT_STREAMDATA;

    talpa_rcu_write_lock(&this->mClientsLock);
    talpa_list_add_tail_rcu(&client->head, &this->mClients);
    client->id = ++this->mNextClientID;
    talpa_rcu_write_unlock(&this->mClientsLock);

    atomic_set(&client->registered, 1);
    atomic_inc(&group->numClients);

    talpa_rcu_synchronize();

    dbg("Thread [%u/%u] registered as client %u", current->tgid, current->pid, (unsigned int)client->id);

    dbg("[client %u-%u-%u] Client 0x%p registered to group %u with ID %u. Group now has %u clients.", processParentPID(current), current->tgid, current->pid,
            client, client->groupID, (unsigned int)client->id, atomic_read(&group->numClients));

    pktreturn_ok;
}

static void destroyVettingDetails(VettingDetails* details)
{
    dbg("decrementing reference count");

    /* This is an ref counted object, only destroy it
        if the last user is doing so */

    if ( atomic_dec_and_test(&details->refcnt) )
    {
        dbg("destroying...");

        /* The following deletes will only destroy the object if
            we are the last user because they are ref counted */

        if ( likely(details->report != NULL) )
        {
            dbg("destroying report");
            details->report->delete(details->report);
        }

        if ( likely(details->threadInfo != NULL) )
        {
            dbg("destroying thread info");
            details->threadInfo->delete(details->threadInfo);
        }

        if ( likely(details->userInfo != NULL) )
        {
            dbg("destroying personality");
            details->userInfo->delete(details->userInfo);
        }

        if ( likely(details->fileInfo != NULL) )
        {
            dbg("destroying file info");
            details->fileInfo->delete(details->fileInfo);
        }

        /* Look above, look below. Here we are optimizing for file access of course. */

        if ( unlikely(details->filesystemInfo != NULL) )
        {
            dbg("destroying filesystem info");
            details->filesystemInfo->delete(details->filesystemInfo);
        }

        /* Stream server */
        if ( likely(details->file != NULL) )
        {
            dbg("destroying file");
            details->file->delete(details->file->object);
        }

        talpa_free(details->vettingDetails);
        talpa_free(details->extendedInfo);
        talpa_free(details);
    }

    return;
}

static struct TalpaProtocolHeader* deregisterClient(void* self, VettingClient* client, struct TalpaPacket_Deregister* packet)
{
    VettingGroup* group = client->group;


    dbg("[client %u-%u-%u] deregister client %d (0x%p)", processParentPID(current), current->tgid, current->pid, (unsigned int)client->id, client);

    if ( packet && (packet->header.version != TALPA_PROTOCOL_VERSION) )
    {
        dbg("[%u] Protocol mismatch!", (unsigned int)client->id);
        pktreturn_fail(-EPROTO);
    }

    if ( !atomic_read(&client->registered) )
    {
        dbg("[%u] Unregistered client tried to deregister!", (unsigned int)client->id);
        pktreturn_fail(-EIO);
    }

    talpa_group_lock(&group->lock);
    if ( atomic_dec_and_test(&client->group->numClients) )
    {
        /* This group has no more clients, clean up queued jobs if any */
        VettingDetails* details;
        VettingDetails* tmp;
        unsigned int orphaned = 0;

        talpa_list_for_each_entry_safe(details, tmp, &group->intercepted, head)
        {
            talpa_list_del(&details->head);
            atomic_set(&details->complete, 1);
            wake_up(&details->interceptedWaitQueue);
            orphaned++;
        }

        if ( orphaned )
        {
            dbg("Completed %u orphaned details from group %u", orphaned, client->groupID);
        }
    }
    talpa_group_unlock(&group->lock);

    atomic_set(&client->registered, 0);

    talpa_rcu_write_lock(&this->mClientsLock);
    talpa_list_del_rcu(&client->head);
    talpa_rcu_write_unlock(&this->mClientsLock);

    talpa_rcu_synchronize();

    /* If the client is currently vetting, clean that up. */
    if ( atomic_read(&client->vetting) )
    {
        VettingDetails* details = client->vettingDetails;


        /* Mark vetting as failed and deny access */
        details->report->setRecommendedAction(details->report, EIA_Error);
        details->report->setErrorCode(details->report, EUNATCH);
        /* Wake up the process which is waiting for this clients response */
        atomic_set(&details->complete, 1);
        wake_up(&details->interceptedWaitQueue);

        dbg("[%u] Cleaning up stale vetting details %u", (unsigned int)client->id, details->vettingID);

        atomic_set(&client->instream, 0);
        atomic_set(&client->vetting, 0);
        client->extDetailsRequested = false;
        client->vettingDetails = NULL;

        /* This is ok regardless of the phase vetting is in. destroyVettingDetails
           always happens at the end of the vetting process. Since it is a reference
           counted structure we are only just decrementing it here while the
           intercepted process will actualy destroy it. */
        destroyVettingDetails(details);
    }

    dbg("[%u] Deregistered", (unsigned int)client->id);

    pktreturn_ok;
}

static struct TalpaProtocolHeader* processPacket(void* self, VettingClient* client, struct TalpaProtocolHeader* packet)
{
    struct TalpaProtocolHeader* response = NULL;

    if ( packet->version != TALPA_PROTOCOL_VERSION )
    {
        dbg("[%u] Protocol mismatch!", (unsigned int)client->id);
        pktreturn_fail(-EPROTO);
    }

    switch ( packet->type )
    {
        case TALPA_PKT_REG:
            response = registerClient(this, client, (struct TalpaPacket_Register *)packet);
            break;
        case TALPA_PKT_DEREG:
            response = deregisterClient(this, client, (struct TalpaPacket_Deregister *)packet);
            break;
        case TALPA_PKT_SETVETTIMEOUT:
            response = setWaitTimeout(this, client, (struct TalpaPacket_SetWaitTimeout *)packet);
            break;
        case TALPA_PKT_OBTAINVETDET:
            response = obtainVettingDetails(this, client);
            break;
        case TALPA_PKT_VETRESPONSE:
            response = vettingResponse(this, client, (struct TalpaPacket_VettingResponse *)packet);
            break;
        case TALPA_PKT_STREAMLENGTH:
            response = streamLength(this, client);
            break;
        case TALPA_PKT_STREAMSEEK:
            response = streamSeek(this, client, (struct TalpaPacket_StreamSeek *)packet);
            break;
        case TALPA_PKT_STREAMREAD:
            response = streamRead(this, client, (struct TalpaPacket_StreamRead *)packet);
            break;
        case TALPA_PKT_STREAMWRITE:
            response = streamWrite(this, client, (struct TalpaPacket_StreamWrite *)packet);
            break;
        case TALPA_PKT_STREAMREADAT:
            response = streamReadAt(this, client, (struct TalpaPacket_StreamReadAt *)packet);
            break;
        case TALPA_PKT_STREAMWRITEAT:
            response = streamWriteAt(this, client, (struct TalpaPacket_StreamWriteAt *)packet);
            break;
        case TALPA_PKT_STREAMUNLINKFILE:
            response = streamUnlinkFile(this, client, (struct TalpaPacket_StreamUnlinkFile *)packet);
            break;
        case TALPA_PKT_STREAMTRUNCATE:
            response = streamTruncate(this, client, (struct TalpaPacket_StreamTruncate *)packet);
            break;
        default:
            dbg("[%u] Unsupported packet type 0x%x received", (unsigned int)client->id, packet->type);
    }

    /* Reset the vetting timeout if vetting is in progress. */
    if ( atomic_read(&client->vetting) && client->vettingDetails )
    {
        client->vettingDetails->lastActivity = jiffies;
    }

    return response;
}

static struct TalpaProtocolHeader* setWaitTimeout(const void* self, VettingClient* client, struct TalpaPacket_SetWaitTimeout* packet)
{
    if ( packet->header.version != TALPA_PROTOCOL_VERSION )
    {
        dbg("[%u] Protocol mismatch!", (unsigned int)client->id);
        pktreturn_fail(-EPROTO);
    }

    client->timeout_ms = msecs_to_jiffies(packet->timeout_ms);
    dbg("[%u] Timeout set to %ums", (unsigned int)client->id, packet->timeout_ms);

    pktreturn_ok;
}

static bool peekVettingQueue(const void* self, VettingClient* client)
{
    VettingGroup* group;

    group = client->group;
    talpa_group_lock(&group->lock);
    if ( likely(!talpa_list_empty(&group->intercepted)) )
    {
        talpa_group_unlock(&group->lock);
        return true;
    }
    talpa_group_unlock(&group->lock);

    return false;
}

/*
 * WARNING: This is a internal function which doesn't release the semaphore!
 */
static inline bool checkVettingQueue(VettingGroup* group)
{
    talpa_group_lock(&group->lock);
    if ( likely(!talpa_list_empty(&group->intercepted)) )
    {
        return true;
    }
    talpa_group_unlock(&group->lock);
    return false;
}

static struct TalpaProtocolHeader* obtainVettingDetails(void* self, VettingClient* client)
{
    VettingGroup* group;
    VettingDetails* job = NULL;

    /* We have three possibilities: we are getting a new job for this client,
        we are just requesting extended details for existing job, or we are
        requesting to read the result of a stream operation */

    if ( atomic_read(&client->instream) )
    {
        dbg("[client %u-%u-%u]  client 0x%p will get the stream data it requested before, details 0x%p", processParentPID(current), current->tgid, current->pid, client, client->vettingDetails);
        job = client->vettingDetails;
        job->packet = (struct TalpaProtocolHeader *)client->stream;

        return job->packet;
    }
    /* Check if this client is allowed to take the job */
    else if ( unlikely((atomic_read(&client->vetting) == 1) && (client->extDetailsRequested == true)) )
    {
        dbg("[%u] Client requested a vetting details while already processing one!", (unsigned int)client->id);
        pktreturn_fail(-EBUSY);
    }
    else if ( likely(atomic_read(&client->vetting) == 0) )
    {
        /* Extract a job from the intercepted list */
        group = client->group;
        talpa_group_lock(&group->lock);
        if ( likely(!talpa_list_empty(&group->intercepted)) )
        {
            get_job:
            job = talpa_list_entry(group->intercepted.next, VettingDetails, head);
            talpa_list_del(&job->head);
            /* Increase vetting details reference count (but only if reponse is required) */
            if ( job->responseRequired )
            {
                atomic_inc(&job->refcnt);
            }
        }
        else
        {
            /* No job available, we must wait for one */
            dbg("[client %u-%u-%u] no details available", processParentPID(current), current->tgid, current->pid);
            /* We will sleep if were opened without O_NONBLOCK */
            if ( !(client->flags & O_NONBLOCK) )
            {
                int ret;

                dbg("[client %u-%u-%u] going to sleep", processParentPID(current), current->tgid, current->pid);
                talpa_group_unlock(&group->lock);
                if ( client->timeout_ms == 0 )
                {
                    ret = talpa_wait_event_interruptible_exclusive(client->group->clientWaitQueue, checkVettingQueue(group));
                }
                else
                {
                    ret = talpa_wait_event_interruptible_exclusive_timeout(client->group->clientWaitQueue, checkVettingQueue(group), client->timeout_ms);
                }

                if ( !ret )
                {
                    /* Job waiting, semaphore is already taken by checkVettingQueue */
                    dbg("[client %u-%u-%u] job waiting", processParentPID(current), current->tgid, current->pid);
                    goto get_job;
                }
                else if ( ret == -ETIME )
                {
                    dbg("[client %u-%u-%u] sleep timed-out", processParentPID(current), current->tgid, current->pid);
                    pktreturn_fail(-EAGAIN);
                }
                else
                {
                    dbg("[client %u-%u-%u] sleep interrupted %d", processParentPID(current), current->tgid, current->pid, ret);
                    pktreturn_fail(ret);
                }
                /* This point is never reached */
            }
        }
        talpa_group_unlock(&group->lock);

        if ( likely(job != NULL) )
        {
            /* Set the active packet to point to vetting details */
            job->packet = job->vettingDetails;
            /* Assign the job to this client */
            client->currentVettingID = job->vettingID;
            client->vettingDetails = job;
            atomic_set(&client->vetting, 1);
            dbg("[client %u-%u-%u] Details<%u> 0x%p assigned to client %u", processParentPID(current), current->tgid, current->pid, job->vettingID, job, (unsigned int)client->id);

            return job->packet;
        }
    }
    else
    {
        job = client->vettingDetails;
        dbg("[client %u-%u-%u] client wants extended info for details 0x%p", processParentPID(current), current->tgid, current->pid, job);
        client->extDetailsRequested = true;
        job->extendedInfo = talpa_alloc(sizeof(struct TalpaPacket_ExtDetailsOnly) + job->threadInfo->environmentSize(job->threadInfo));
        if ( likely(job->extendedInfo != NULL) )
        {
            dbg("[client %u-%u-%u] extInfo allocated %lu bytes at 0x%p", processParentPID(current), current->tgid, current->pid, sizeof(struct TalpaPacket_ExtDetailsOnly) + job->threadInfo->environmentSize(job->threadInfo), job->extendedInfo);
            job->extendedInfo->header.type = TALPA_PKT_EXTVETDETAILONLY;
            job->extendedInfo->header.version = TALPA_PROTOCOL_VERSION;
            job->extendedInfo->header.payloadLength = sizeof(struct TalpaPacketFragment_ExtDetails) + job->threadInfo->environmentSize(job->threadInfo);
            job->extendedInfo->extDetails.controllingTTY = job->threadInfo->controllingTTY(job->threadInfo);
            job->extendedInfo->extDetails.envLength = job->threadInfo->environmentSize(job->threadInfo);
            if ( likely(job->extendedInfo->extDetails.envLength > 0) )
            {
                memcpy(((char *)job->extendedInfo) + sizeof(struct TalpaPacket_ExtDetailsOnly), job->threadInfo->environment(job->threadInfo), job->threadInfo->environmentSize(job->threadInfo));
            }
            job->packet = (struct TalpaProtocolHeader *)job->extendedInfo;

            return job->packet;
        }
        else
        {
            warn("Failed to allocate extended info!");
            pktreturn_fail(-ENOMEM);
        }
    }

    pktreturn_fail(-EAGAIN);
}

static void releaseVettingDetails(const void* self, VettingClient* client)
{
    VettingDetails* job = client->vettingDetails;

    dbg("[client %u-%u-%u] client %u", processParentPID(current), current->tgid, current->pid, (unsigned int)client->id);
    /* Check if this was a stream read */
    if ( atomic_read(&client->instream) )
    {
        dbg("[client %u-%u-%u] stream data read complete", processParentPID(current), current->tgid, current->pid);
        atomic_set(&client->instream, 0);
    }
    /* Check if we can destroy the details */
    else if ( !job->responseRequired )
    {
        /* Now reset the client */
        dbg("[client %u-%u-%u] response not required, releasing details", processParentPID(current), current->tgid, current->pid);
        atomic_set(&client->vetting, 0);
        client->extDetailsRequested = false;
        client->vettingDetails = NULL;
        destroyVettingDetails(job);
    }

    return;
}

static struct TalpaProtocolHeader* vettingResponse(void* self, VettingClient* client, struct TalpaPacket_VettingResponse* packet)
{
    VettingDetails* job;


    /* Check if this client can respond */
    if ( unlikely(atomic_read(&client->vetting) == 0) )
    {
        dbg("[%u] Client responded but vetting is not in progress!", (unsigned int)client->id);
        pktreturn_fail(-EPIPE);
    }

    /* Check if client has something to respond to */
    if ( unlikely(!client->vettingDetails) )
    {
        dbg("[%u] Client has nothing to respond to!", (unsigned int)client->id);
        pktreturn_fail(-EIO);
    }

    /* Check if vetting id matches */
    if ( unlikely(packet->vettingID != client->currentVettingID) )
    {
        dbg("[%u] Client responded to a wrong vetting id!", (unsigned int)client->id);
        pktreturn_fail(-ESRCH);
    }

    job = client->vettingDetails;

    /* Check if client is expected to respond */
    if ( unlikely(!job->responseRequired) )
    {
        dbg("[%u] Client responds to wrong packets!", (unsigned int)client->id);
        pktreturn_fail(-ENXIO);
    }

    dbg("[client %u-%u-%u] response %u", processParentPID(current), current->tgid, current->pid, packet->response);
    switch ( packet->response )
    {
        case TALPA_ALLOW:
            job->report->setRecommendedAction(job->report, EIA_Allow);
            break;
        case TALPA_DENY:
            job->report->setRecommendedAction(job->report, EIA_Deny);
            break;
        case TALPA_ERROR:
            job->report->setRecommendedAction(job->report, EIA_Error);
            job->report->setErrorCode(job->report, packet->errorCode);
            break;
        case TALPA_TIMEOUT:
            job->report->setRecommendedAction(job->report, EIA_Timeout);
            break;
        default:
            dbg("[%u] Client responded with a unknown response %u!", (unsigned int)client->id, packet->response);
    }

    /* Wake up the intercepted process */
    job->report->externallyVetted(job->report);
    atomic_set(&job->complete, 1);
    wake_up(&job->interceptedWaitQueue);

    /* Now reset the client */
    atomic_set(&client->vetting, 0);
    atomic_set(&client->instream, 0);
    client->extDetailsRequested = false;
    client->vettingDetails = NULL;
    destroyVettingDetails(job);

    pktreturn_ok;
}

static inline int streamValidateRequest(const void* self, VettingClient* client, VettingDetails *job)
{
    /* Check if this client has vetting assigned to it */
    if ( unlikely(atomic_read(&client->vetting) == 0) )
    {
        dbg("[%u] Stream server not available while vetting is not in progress!", (unsigned int)client->id);
        return -ENOSR;
    }

    /* Check if the vetting details are available */
    if ( unlikely(!job) )
    {
        dbg("[%u] Stream server not available because there are no vetting details!", (unsigned int)client->id);
        return -EPIPE;
    }

    /* Check if the file is available */
    if ( unlikely(!job->file) )
    {
        dbg("[%u] Stream server not available because file object is missing!", (unsigned int)client->id);
        return -EBADF;
    }

    /* Check if the file is open */
    if ( unlikely(!job->file->isOpen(job->file->object)) )
    {
        dbg("[%u] Stream server not available because file is not open!", (unsigned int)client->id);
        return -ENOSTR;
    }

    return 0;
}

static struct TalpaProtocolHeader* streamLength(const void* self, VettingClient* client)
{
    VettingDetails* job = client->vettingDetails;
    int ret = streamValidateRequest(this, client, job);

    if ( ret )
    {
        pktreturn_fail(ret);
    }

    pktreturn_stream( ( unsigned int ) (sizeof(struct TalpaPacket_StreamData) - sizeof(struct TalpaProtocolHeader) ), (unsigned int) job->file->length(job->file->object));
}

static struct TalpaProtocolHeader* streamSeek(void* self, VettingClient* client, struct TalpaPacket_StreamSeek* packet)
{
    VettingDetails* job = client->vettingDetails;
    int ret = streamValidateRequest(this, client, job);
    loff_t retval;


    if ( ret )
    {
        pktreturn_fail(ret);
    }

    job->externalOperation = true;
    retval = job->file->seek(job->file->object, packet->offset, packet->mode);
    job->externalOperation = false;
    dbg("seek offset:%ld mode:%d (%ld)", (long int) packet->offset, packet->mode, (long int) ret);

    if ( retval < 0 )
    {
        pktreturn_fail(retval);
    }

    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamRead(void* self, VettingClient* client, struct TalpaPacket_StreamRead* packet)
{
    VettingDetails* job = client->vettingDetails;
    int ret = streamValidateRequest(this, client, job);

    if ( ret )
    {
        pktreturn_fail(ret);
    }

    if ( packet->size > client->streamSize )
    {
        packet->size = client->streamSize;
    }

    job->externalOperation = true;
    ret = job->file->read(job->file->object, (unsigned char *)client->stream + sizeof(struct TalpaPacket_StreamData), packet->size);
    job->externalOperation = false;
    dbg("read %d bytes", ret);

    if ( ret < 0 )
    {
        pktreturn_fail(ret);
    }

    pktreturn_stream( (unsigned int ) (ret + (sizeof(struct TalpaPacket_StreamData) - sizeof(struct TalpaProtocolHeader)) ), ret);
}

static inline void streamMaybeReopenWritable(VettingDetails* job)
{
    if ( !job->file->isWritable(job->file->object) )
    {
        if ( unlikely(atomic_read(&job->clientGone) == 1) )
        {
            dbg("request has gone away - not reopening writable!");
            return;
        }

        dbg("file not writable, will request reopen");
        atomic_set(&job->reopen, 1);
        wake_up(&job->interceptedWaitQueue);
        dbg("now waiting for a intercepted process to do it");
        talpa_wait_for_completion(&job->reopenCompletion);
    }

    return;
}

static struct TalpaProtocolHeader* streamWrite(void* self, VettingClient* client, struct TalpaPacket_StreamWrite* packet)
{
    VettingDetails* job = client->vettingDetails;
    int ret = streamValidateRequest(this, client, job);

    if ( ret )
    {
        pktreturn_fail(ret);
    }

    streamMaybeReopenWritable(job);
    dbg("write %lld bytes", ( long long int ) packet->size);
    job->externalOperation = true;
    ret = job->file->write(job->file->object, (unsigned char *)packet + sizeof(struct TalpaPacket_StreamWrite), packet->size);
    job->externalOperation = false;

    if ( ret < 0 )
    {
        pktreturn_fail(ret);
    }

    pktreturn_stream( ( unsigned int ) (sizeof(struct TalpaPacket_StreamData) - sizeof(struct TalpaProtocolHeader)), ret);
}

static struct TalpaProtocolHeader* streamReadAt(void* self, VettingClient* client, struct TalpaPacket_StreamReadAt* packet)
{
    VettingDetails* job = client->vettingDetails;
    int ret = streamValidateRequest(this, client, job);
    loff_t retval;


    if ( ret )
    {
        pktreturn_fail(ret);
    }

    job->externalOperation = true;
    retval = job->file->seek(job->file->object, packet->offset, packet->mode);
    job->externalOperation = false;

    if ( retval < 0 )
    {
        pktreturn_fail(retval);
    }

    if ( packet->size > client->streamSize )
    {
        packet->size = client->streamSize;
    }

    job->externalOperation = true;
    ret = job->file->read(job->file->object, (unsigned char *)client->stream + sizeof(struct TalpaPacket_StreamData), packet->size);
    job->externalOperation = false;
    dbg("read %d bytes", ret);

    if ( ret < 0 )
    {
        pktreturn_fail(ret);
    }

    pktreturn_stream( (unsigned int) (ret + (sizeof(struct TalpaPacket_StreamData) - sizeof(struct TalpaProtocolHeader))), ret);
}

static struct TalpaProtocolHeader* streamWriteAt(void* self, VettingClient* client, struct TalpaPacket_StreamWriteAt* packet)
{
    VettingDetails* job = client->vettingDetails;
    int ret = streamValidateRequest(this, client, job);
    loff_t retval;


    if ( ret )
    {
        pktreturn_fail(ret);
    }

    streamMaybeReopenWritable(job);

    job->externalOperation = true;
    retval = job->file->seek(job->file->object, packet->offset, packet->mode);
    job->externalOperation = false;

    if ( retval < 0 )
    {
        pktreturn_fail(retval);
    }

    dbg("write %lld bytes", (long long int) packet->size);

    job->externalOperation = true;
    ret = job->file->write(job->file->object, (unsigned char *)packet + sizeof(struct TalpaPacket_StreamWriteAt), packet->size);
    job->externalOperation = false;

    if ( ret < 0 )
    {
        pktreturn_fail(ret);
    }

    pktreturn_stream( (unsigned int) (sizeof(struct TalpaPacket_StreamData) - sizeof(struct TalpaProtocolHeader)), ret);
}

static struct TalpaProtocolHeader* streamUnlinkFile(void* self, VettingClient* client, struct TalpaPacket_StreamUnlinkFile* packet)
{
    VettingDetails* job = client->vettingDetails;
    int ret = streamValidateRequest(this, client, job);

    if ( ret )
    {
        pktreturn_fail(ret);
    }

    dbg("unlink file");

    job->externalOperation = true;
    ret = job->file->unlink(job->file->object);
    job->externalOperation = false;

    if ( ret )
    {
        pktreturn_fail(ret);
    }

    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamTruncate(void* self, VettingClient* client, struct TalpaPacket_StreamTruncate* packet)
{
    VettingDetails* job = client->vettingDetails;
    int ret = streamValidateRequest(this, client, job);

    if ( ret )
    {
        pktreturn_fail(ret);
    }

    streamMaybeReopenWritable(job);
    dbg("truncate file %u", (unsigned int) packet->length);
    job->externalOperation = true;
    ret = job->file->truncate(job->file->object, packet->length);
    job->externalOperation = false;

    if ( ret )
    {
        pktreturn_fail(ret);
    }

    pktreturn_ok;
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

static void setTimeout(const void* self, const char* string)
{
    unsigned int ms;
    char* res;

    ms = simple_strtoul(string, &res, 10);
    snprintf(this->mTimeoutConfigData.value, VETCTRL_CFGDATASIZE, "%u", ms);
    atomic_set(&this->mTimeout, ms);
    dbg("Timeout set to %ums", ms);

    return;
}

static void setFSTimeout(const void* self, const char* string)
{
    unsigned int ms;
    char* res;

    ms = simple_strtoul(string, &res, 10);
    snprintf(this->mFSTimeoutConfigData.value, VETCTRL_CFGDATASIZE, "%u", ms);
    atomic_set(&this->mFSTimeout, ms);
    dbg("FS-Timeout set to %ums", ms);

    return;
}

static bool isEnabled(const void* self)
{
    return this->mEnabled;
}

#define catState(string, check, name) \
do \
{ \
    if ( this->mVettingMask & check ) \
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
    char* out = this->mOpsConfigData.value;

    *out = 0;

    catState(out, HOOK_OPEN, "open\n");
    catState(out, HOOK_CLOSE, "close\n");
    catState(out, HOOK_EXEC, "exec\n");
    catState(out, HOOK_MOUNT, "mount\n");
    catState(out, HOOK_UMOUNT, "umount\n");

    return;
}

#undef catState

static void doSpecialString(void* self, const char* value)
{
    unsigned long mask = 0;


    if ( strlen(value) >= 2 )
    {
        if ( !strcmp(&value[1], "open") )
        {
            mask = HOOK_OPEN;
        }
        else if ( !strcmp(&value[1], "close") )
        {
            mask = HOOK_CLOSE;
        }
        else if ( !strcmp(&value[1], "exec") )
        {
            mask = HOOK_EXEC;
        }
        else if ( !strcmp(&value[1], "mount") )
        {
            mask = HOOK_MOUNT;
        }
        else if ( !strcmp(&value[1], "umount") )
        {
            mask = HOOK_UMOUNT;
        }

        if ( value[0] == '+' )
        {
            this->mVettingMask |= mask;
        }
        else if ( value[0] == '-' )
        {
            this->mVettingMask &= ~(mask);
        }
    }

    constructSpecialSet(this);

    return;
}
/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "VettingController";
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

        if ( !strcmp(cfgElement->name, CFG_ROUTING) )
        {
            if ( !this->mRoutingsSet )
            {
                constructStringSet(this, &this->mRoutings, &this->mRoutingsSet);
            }
            retstring = this->mRoutingsSet;
        }
        else if ( !strcmp(cfgElement->name, CFG_GROUPS) )
        {
            unsigned int idx;
            VettingGroup* group;
            unsigned int queue;
            char* buf;
            talpa_list_head* posptr;


            buf = this->mGroupsConfigData.value;

            for ( idx = 0; idx < VETTING_GROUPS; idx++ )
            {
                group = &this->mGroups[idx];
                buf += sprintf(buf, "%u\t", atomic_read(&group->numClients));
            }

            --buf;
            *buf++ = '\n';

            for ( queue = 0, idx = 0; idx < VETTING_GROUPS; idx++, queue = 0 )
            {
                group = &this->mGroups[idx];
                talpa_group_lock(&group->lock);
                talpa_list_for_each(posptr, &group->intercepted)
                {
                    queue++;
                }
                talpa_group_unlock(&group->lock);
                buf += sprintf(buf, "%u\t", queue);
            }

            --buf;
            *buf = '\0';
        }

        talpa_mutex_unlock(&this->mConfigSerialize);

        return retstring;
    }
    return 0;
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
    else if ( !strcmp(name, CFG_TIMEOUT) )
    {
        setTimeout(this, value);
    }
    else if ( !strcmp(name, CFG_FSTIMEOUT) )
    {
        setFSTimeout(this, value);
    }
    else if ( !strcmp(name, CFG_ROUTING) )
    {
        doActionString(this, &this->mRoutings, &(this->mRoutingsSet), value);
    }
    else if (strcmp(name, CFG_XHACK) == 0)
    {
        if (strcmp(value, CFG_ACTION_ENABLE) == 0)
        {
            this->mXHack = true;
            strcpy(this->mXHackConfigData.value, CFG_VALUE_ENABLED);
        }
        else if (strcmp(value, CFG_ACTION_DISABLE) == 0)
        {
            this->mXHack = false;
            strcpy(this->mXHackConfigData.value, CFG_VALUE_DISABLED);
        }
    }
    else if ( !strcmp(name, CFG_OPS) )
    {
        doSpecialString(this, value);
    }
    else if (strcmp(name, CFG_INTERRUPTIBLE) == 0)
    {
        if (strcmp(value, CFG_ACTION_ENABLE) == 0)
        {
            this->mInterruptible = true;
            strcpy(this->mInterruptibleConfigData.value, CFG_VALUE_ENABLED);
        }
        else if (strcmp(value, CFG_ACTION_DISABLE) == 0)
        {
            this->mInterruptible = false;
            strcpy(this->mInterruptibleConfigData.value, CFG_VALUE_DISABLED);
        }
    }

    talpa_mutex_unlock(&this->mConfigSerialize);

    return;
}

/*
 * End of vetting_ctrl.c
 */

