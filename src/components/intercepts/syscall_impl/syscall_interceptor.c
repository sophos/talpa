/*
 * syscall_interceptor.c
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
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/unistd.h>
#include <linux/binfmts.h>

#include "syscall_interceptor.h"
#include "app_ctrl/iportability_app_ctrl.h"
#include "filesystem/ifile_info.h"


/*
 * Forward declare implementation methods.
 */

static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static void addInterceptProcessor(void* self, IInterceptProcessor* processor);
static IInterceptProcessor* interceptProcessor(const void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void deleteSyscallInterceptor(struct tag_SyscallInterceptor* object);

static long talpaOpenHook(unsigned int fd);
static void talpaCloseHook(unsigned int fd);
static long talpaUselibHook(const char* library);
static int  talpaExecveHook(const TALPA_FILENAME_T* name);
static long talpaMountHook(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
static long talpaMountDummy(int err, char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
static void talpaUmountHook(char* name, int flags, void** ctx);
static void talpaUmountDummy(int err, char* name, int flags, void *ctx);

static bool hook(void* self);
static bool unhook(void* self);

static void constructSpecialSet(void* self);

/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_OPS             "ops"
#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"
#define CFG_VALUE_DUMMY     "(empty)"


#define HOOK_OPEN       0x01
#define HOOK_CLOSE      0x02
#define HOOK_EXEC       0x04
#define HOOK_USELIB     0x08
#define HOOK_MOUNT      0x10
#define HOOK_UMOUNT     0x20

#define HOOK_DEFAULT (HOOK_OPEN | HOOK_CLOSE | HOOK_EXEC | HOOK_USELIB | HOOK_MOUNT | HOOK_UMOUNT)

/*
 * Singleton object.
 */

static SyscallInterceptor GL_object =
    {
        {
            enable,
            disable,
            isEnabled,
            addInterceptProcessor,
            interceptProcessor,
            &GL_object,
            (void (*)(void*))deleteSyscallInterceptor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            &GL_object,
            (void (*)(void*))deleteSyscallInterceptor
        },
        deleteSyscallInterceptor,
        false,
        TALPA_STATIC_MUTEX(GL_object.mSemaphore),
        false,
        HOOK_DEFAULT,
        NULL,
        {
            {GL_object.mConfigData.name, GL_object.mConfigData.value, SYSCALL_CFGDATASIZE, true, true },
            {GL_object.mOpsConfigData.name, GL_object.mOpsConfigData.value, SYSCALL_OPSCFGDATASIZE, true, false },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_DISABLED },
        { CFG_OPS, CFG_VALUE_DUMMY },
        NULL,
        NULL,
        NULL,
        {
            .open_post = talpaOpenHook,
            .close_pre = talpaCloseHook,
            .execve_pre = talpaExecveHook,
            .uselib_pre = talpaUselibHook,
            .mount_pre = talpaMountHook,
            .mount_post = talpaMountDummy,
            .umount_pre = talpaUmountHook,
            .umount_post = talpaUmountDummy,
        },
    };

#define this    ((SyscallInterceptor*)self)

/*
 * Object creation/destruction.
 */
SyscallInterceptor* newSyscallInterceptor(void)
{
    talpa_mutex_lock(&GL_object.mSemaphore);

    if ( GL_object.mInitialized )
    {
        talpa_mutex_unlock(&GL_object.mSemaphore);
        err("Duplicate initialization attempted!");
        return NULL;
    }

    constructSpecialSet(&GL_object);
    GL_object.mLinuxFilesystemFactory = TALPA_Portability()->filesystemFactory()->object;
    GL_object.mInitialized = true;

    talpa_mutex_unlock(&GL_object.mSemaphore);

    return &GL_object;
}

static void deleteSyscallInterceptor(struct tag_SyscallInterceptor* object)
{
    talpa_mutex_lock(&object->mSemaphore);

    if ( !object->mInitialized )
    {
        talpa_mutex_unlock(&object->mSemaphore);
        err("Tried to delete before initializing!");
        return;
    }

    if ( object->mInterceptEnabled )
    {
        unhook(object);
        object->mInterceptEnabled = false;
        strcpy(object->mConfigData.value, CFG_VALUE_DISABLED);
    }

    object->mLinuxFilesystemFactory->delete(object->mLinuxFilesystemFactory);
    object->mInitialized = false;

    talpa_mutex_unlock(&object->mSemaphore);

    return;
}

/*
 * Hook helper functions
 */

static inline int examineFile(EFilesystemOperation op, const char *filename, int flags, int mode)
{
    int decision = 0;
    TALPA_FILENAME_T* tmp = talpa_getname(filename);

    if ( !IS_ERR(tmp) )
    {
        IFileInfo *pFInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfo(GL_object.mLinuxFilesystemFactory, op, getCStr(tmp), flags, mode);
        if ( likely(pFInfo != NULL) )
        {
            decision = GL_object.mTargetProcessor->examineFileInfo(GL_object.mTargetProcessor, pFInfo, NULL);
            pFInfo->delete(pFInfo);
        }

        talpa_putname(tmp);
    }

    return decision;
}

static inline int examineFd(EFilesystemOperation op, int fd)
{
    int decision = 0;
    IFileInfo *pFInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfoFromFd(GL_object.mLinuxFilesystemFactory, op, fd);

    if ( likely(pFInfo != NULL) )
    {
        decision = GL_object.mTargetProcessor->examineFileInfo(GL_object.mTargetProcessor, pFInfo, NULL);
        pFInfo->delete(pFInfo);
    }

    return decision;
}

static inline const char* getRealExecutable(IFile *pFile, const char* filename, char* buf)
{
    char* interpreter = NULL;
    int rc;
    unsigned int ilen = 0;
    unsigned int ipos = 0;


    /* Read the chunk of the file that must contain the hash bang */
    rc = pFile->read(pFile->object, buf, BINPRM_BUF_SIZE);

    /* Seek back to the beginning of the file */
    pFile->seek(pFile->object, 0, 0);

    if ( unlikely( rc < 0 ) )
    {
        return ERR_PTR(rc);
    }
    else if ( unlikely( rc == 0 ) )
    {
        return filename;
    }

    /* Parse the buffer and try to extract interpreter name */
    /* Check for '#!' */
    if ( *buf++ != '#' )
    {
        return filename;
    }
    rc--;
    ipos++;
    if ( !rc || (*buf++ != '!') )
    {
        return filename;
    }
    rc--;
    ipos++;
    /* Skip whitespace */
    while ( rc && ((*buf == ' ') || (*buf == '\t')) )
    {
        buf++;
        rc--;
        ipos++;
    }
    /* Abort if string exausted */
    if ( !rc )
    {
        return filename;
    }

    /* From here to the next whitespace is the interpreter name */
    interpreter = buf;
    while ( rc && ((*buf != ' ') && (*buf != '\t') && (*buf != '\n')) )
    {
        buf++;
        rc--;
        ilen++;
        ipos++;
    }

    /* Null-terminate if there is enough space in the buffer,
       or return the 'script' name if no interpreter in BINPRM_BUF_SIZE. */
    if ( ipos <= BINPRM_BUF_SIZE )
    {
        *buf = '\0';
    }
    else
    {
        return filename;
    }

    /* We have our interpreter if it is at least 1 byte long */
    if ( ilen > 0 )
    {
        return interpreter;
    }

    return filename;
}

static inline int examineExecve(const TALPA_FILENAME_T *filename)
{
    int    decision = 0;
    IFile* pFile    = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFile(GL_object.mLinuxFilesystemFactory);


    if ( likely(pFile != NULL) )
    {
        IFileInfo* pFInfo;
        char buf[BINPRM_BUF_SIZE + 1];
        const char* real;
        const char* fname = getCStr(filename);


        decision = pFile->openExec(pFile->object, getCStr(filename));

        if (  unlikely(decision < 0) )
        {
            dbg("[intercepted %u-%u-%u] Failed to open file! error-code:%d", processParentPID(current), current->tgid, current->pid, decision);
            pFile->delete(pFile);

            return decision;
        }

        real = getRealExecutable(pFile, fname, buf);

        if ( unlikely( IS_ERR(real) ) )
        {
            dbg("[intercepted %u-%u-%u] Failed to parse executable! error-code:%ld", processParentPID(current), current->tgid, current->pid, PTR_ERR(real));
            pFile->delete(pFile);

            return PTR_ERR(real);
        }
        else if ( unlikely( real != fname ) )
        {
            pFile->close(pFile->object);
            decision = pFile->openExec(pFile->object, real);

            if (  unlikely(decision < 0) )
            {
                dbg("[intercepted %u-%u-%u] Failed to open interpreter! error-code:%d", processParentPID(current), current->tgid, current->pid, decision);
                pFile->delete(pFile);

                return decision;
            }
        }

        pFInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfo(GL_object.mLinuxFilesystemFactory, EFS_Exec, real, 0, 0);

        if ( likely(pFInfo != NULL) )
        {
            decision = GL_object.mTargetProcessor->examineFileInfo(GL_object.mTargetProcessor, pFInfo, pFile);
            pFInfo->delete(pFInfo);
        }

        pFile->delete(pFile->object);
    }

    return decision;
}

static int talpa_copy_mount_string(const void __user *data, char **where)
{
	char *tmp;

	if (!data) {
		*where = NULL;
		return 0;
	}

#ifdef TALPA_HAS_STRNDUP_USER
	tmp = strndup_user(data, PAGE_SIZE);
#else
    tmp = talpa_getname(data);
#endif
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	*where = tmp;
	return 0;
}

static int examineMount(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data)
{
    char* dev = 0;
    TALPA_FILENAME_T* dir;
    char* fstype = 0;
    int decision = 0;
    IFilesystemInfo *pFSInfo;

    decision = talpa_copy_mount_string(dev_name,&dev);
    if ( decision < 0 )
    {
        goto out;
    }

    dir = talpa_getname(dir_name);

    if ( IS_ERR(dir) )
    {
        goto out1;
    }

    decision = talpa_copy_mount_string(type,&fstype);
    if ( decision < 0 )
    {
        goto out2;
    }

    pFSInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFilesystemInfo(GL_object.mLinuxFilesystemFactory, EFS_Mount, dev, getCStr(dir), fstype);

    if ( likely(pFSInfo != NULL) )
    {
        decision = GL_object.mTargetProcessor->examineFilesystemInfo(GL_object.mTargetProcessor, pFSInfo);
        pFSInfo->delete(pFSInfo);
        if ( unlikely( decision < 0 ) )
        {
            dbg("[intercepted %u-%u-%u] Mount blocked! decision:%d", processParentPID(current), current->tgid, current->pid, decision);
            goto out3;
        }
    }
    else
    {
        dbg("[intercepted %u-%u-%u] Failed to examine mount!", processParentPID(current), current->tgid, current->pid);
    }

out3:
    kfree(fstype);
out2:
    talpa_putname(dir);
out1:
    kfree(dev);
out:
    return decision;
}

static void examineUmount(char* name, int flags)
{
    TALPA_FILENAME_T* kname;


    kname = talpa_getname(name);

    if ( !IS_ERR(kname) )
    {
        IFilesystemInfo *pFSInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFilesystemInfo(GL_object.mLinuxFilesystemFactory, EFS_Umount, NULL, getCStr(kname), NULL);

        if ( likely(pFSInfo != NULL) )
        {
            GL_object.mTargetProcessor->examineFilesystemInfo(GL_object.mTargetProcessor, pFSInfo);
            pFSInfo->delete(pFSInfo);
        }
        else
        {
            dbg("Failed to examine umount!");
        }

        talpa_putname(kname);
    }
}

/*
 * Hook functions
 */

static long talpaOpenHook(unsigned int fd)
{
    int decision;


    if ( unlikely( !(GL_object.mHookingMask & HOOK_OPEN) ) )
    {
        return 0;
    }

    decision = examineFd(EFS_Open, fd);

    if ( unlikely(decision != 0) )
    {
        dbg("[intercepted %u-%u-%u] Open refused. decision:%d", processParentPID(current), current->tgid, current->pid, decision);
    }

    return decision;
}

static void talpaCloseHook(unsigned int fd)
{
    if ( likely( !(GL_object.mHookingMask & HOOK_CLOSE) ) )
    {
        return;
    }

    examineFd(EFS_Close, fd);
}

static long talpaUselibHook(const char* library)
{
    int decision;


    if ( unlikely( !(GL_object.mHookingMask & HOOK_USELIB) ) )
    {
        return 0;
    }

    decision = examineFile(EFS_Open, library, O_RDONLY, 0);

    if ( unlikely(decision != 0) )
    {
        dbg("[intercepted %u-%u-%u] Uselib refused:%d", processParentPID(current), current->tgid, current->pid, decision);
    }

    return decision;
}

static int  talpaExecveHook(const TALPA_FILENAME_T* name)
{
    int decision;


    if ( unlikely( !(GL_object.mHookingMask & HOOK_EXEC) ) )
    {
        return 0;
    }

    decision = examineExecve(name);

    if ( unlikely(decision < 0) )
    {
        dbg("[intercepted %u-%u-%u] Exec refused. error:%d", processParentPID(current), current->tgid, current->pid, decision);
    }

    return decision;
}

static long talpaMountHook(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data)
{
    int decision;


    if ( unlikely( !(GL_object.mHookingMask & HOOK_MOUNT) ) )
    {
        return 0;
    }

    decision = examineMount(dev_name, dir_name, type, flags, data);

    if ( unlikely(decision != 0) )
    {
        dbg("[intercepted %u-%u-%u] Open refused. decision:%d", processParentPID(current), current->tgid, current->pid, decision);
    }

    return decision;
}

static long talpaMountDummy(int err, char* dev_name, char* dir_name, char* type, unsigned long flags, void* data)
{
    return 0;
}

static void talpaUmountHook(char* name, int flags, void** ctx)
{
    if ( unlikely( !(GL_object.mHookingMask & HOOK_UMOUNT) ) )
    {
        return;
    }

    examineUmount(name, flags);
}

static void talpaUmountDummy(int err, char* name, int flags, void* ctx)
{
    return;
}

/*
 * IInterceptor.
 */
static bool hook(void* self)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    this->syscallhook_register = (int (*)(unsigned int, struct talpa_syscall_operations* ops))inter_module_get("__talpa_syscallhook_register");
    this->syscallhook_unregister = (void (*)(struct talpa_syscall_operations* ops))inter_module_get("talpa_syscallhook_unregister");
#else
    this->syscallhook_register = symbol_get(__talpa_syscallhook_register);
    this->syscallhook_unregister = symbol_get(talpa_syscallhook_unregister);
#endif

    if ( this->syscallhook_register && this->syscallhook_unregister )
    {
        int err;

        err = this->syscallhook_register(TALPA_SYSCALLHOOK_IFACE_VERSION, &this->mSyscallOps);
        if ( err )
        {
            err("Failed to register with talpa-syscallhook! (%d)", err);
            goto error;
        }

        info("Enabled");

        return true;
    }
    else
    {
            err("Failed to register with talpa-syscallhook!");
            goto error;
    }

error:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        if ( this->syscallhook_register )
        {
            inter_module_put("__talpa_syscallhook_register");
        }
        if ( this->syscallhook_unregister )
        {
            inter_module_put("talpa_syscallhook_unregister");
        }
#else
        if ( this->syscallhook_register )
        {
            symbol_put(__talpa_syscallhook_register);
        }
        if ( this->syscallhook_unregister )
        {
            symbol_put(talpa_syscallhook_unregister);
        }
#endif

    return false;
}

static bool unhook(void* self)
{
    if ( this->syscallhook_register && this->syscallhook_unregister )
    {
        this->syscallhook_unregister(&this->mSyscallOps);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        inter_module_put("__talpa_syscallhook_register");
        inter_module_put("talpa_syscallhook_unregister");
#else
        symbol_put(__talpa_syscallhook_register);
        symbol_put(talpa_syscallhook_unregister);
#endif
        info("Disabled");

        return true;
    }

    return false;
}

#define catState(string, check, name) \
do \
{ \
    if ( this->mHookingMask & check ) \
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
    catState(out, HOOK_USELIB, "uselib\n");
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
        else if ( !strcmp(&value[1], "uselib") )
        {
            mask = HOOK_USELIB;
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
            this->mHookingMask |= mask;
        }
        else if ( value[0] == '-' )
        {
            this->mHookingMask &= ~(mask);
        }
    }

    constructSpecialSet(this);

    return;
}

static bool enable(void* self)
{
    if (!this->mInterceptEnabled)
    {
        if ( this->mTargetProcessor )
        {
            if ( hook(self) )
            {
                this->mInterceptEnabled = true;
                strcpy(this->mConfigData.value, CFG_VALUE_ENABLED);
            }
        }
        else
        {
            err("No processor!");
            return false;
        }
    }
    return true;
}

static void disable(void* self)
{
    if (this->mInterceptEnabled)
    {
        if ( unhook(self) )
        {
            this->mInterceptEnabled = false;
            strcpy(this->mConfigData.value, CFG_VALUE_DISABLED);
        }
    }
    return;
}

static bool isEnabled(const void* self)
{
    return this->mInterceptEnabled;
}

static void addInterceptProcessor(void* self, IInterceptProcessor* processor)
{

    this->mTargetProcessor = processor;
    return;
}

static IInterceptProcessor* interceptProcessor(const void* self)
{
    return this->mTargetProcessor;
}

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "SyscallInterceptor";
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

    talpa_mutex_lock(&this->mSemaphore);

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
    else if ( !strcmp(name, CFG_OPS) )
    {
        doSpecialString(this, value);
    }

    talpa_mutex_unlock(&this->mSemaphore);

    return;
}

/*
 * End of syscall_interceptor.c
 */
