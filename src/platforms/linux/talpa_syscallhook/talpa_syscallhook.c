/*
 * talpa_syscallhook.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright(C) 2004-2016 Sophos Limited, Oxford, England.
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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <asm/atomic.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
    #include <linux/syscalls.h>
  #endif
  #include <linux/ptrace.h>
  #include <linux/moduleparam.h>
#endif
#ifdef TALPA_NEED_MANUAL_RODATA
#include <asm/page.h>
#include <asm/cacheflush.h>
#endif
#ifdef TALPA_HAS_PROBE_KERNEL_WRITE
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#endif

#if defined(CONFIG_DEBUG_SET_MODULE_RONX) || defined(CONFIG_DEBUG_RODATA)
#define TALPA_SHADOW_MAP
#endif

#include "platforms/linux/glue.h"
#include "platforms/linux/locking.h"

#include "platforms/linux/talpa_syscallhook.h"

#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

#ifdef TALPA_VERSION
const char talpa_version[] = "$TALPA_VERSION:" TALPA_VERSION;
#endif

const char talpa_iface_version[] = "$TALPA_IFACE_VERSION:" TALPA_SYSCALLHOOK_IFACE_VERSION_STR;

#define err(format, arg...) printk(KERN_ERR "talpa-syscallhook: " format "\n" , ## arg)
#define warn(format, arg...) printk(KERN_WARNING "talpa-syscallhook: " format "\n" , ## arg)
#define notice(format, arg...) printk(KERN_NOTICE "talpa-syscallhook: " format "\n" , ## arg)
#define info(format, arg...) printk(KERN_INFO "talpa-syscallhook: " format "\n" , ## arg)
#ifdef DEBUG
  #define dbg_start() printk(KERN_DEBUG "TALPA [" __FILE__ " ### %s] " , __FUNCTION__)
  #define dbg_cont(format, arg...) printk(format,## arg)
  #define dbg_end() printk("\n")
  #define dbg(format, arg...) printk(KERN_DEBUG "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#else
  #define dbg_start() do {} while (0)
  #define dbg_cont(format, arg...) do {} while (0)
  #define dbg_endt() do {} while (0)
  #define dbg(format, arg...) do {} while (0)
#endif


#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
  #define __builtin_expect(x, expected_value) (x)
#endif

#ifndef likely
  #define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
  #define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#ifndef prevent_tail_call
# define prevent_tail_call(ret) do { } while (0)
#endif

#ifndef MODULE_LICENSE
  #define MODULE_LICENSE(x) const char module_license[] = x
#endif

#ifdef CONFIG_X86_64
  #undef TALPA_EXECVE_SUPPORT
#endif


static atomic_t usecnt = ATOMIC_INIT(0);
static struct talpa_syscall_operations* interceptor;
static DECLARE_WAIT_QUEUE_HEAD(unregister_wait);

static asmlinkage long (*orig_open)(const char* filename, int flags, int mode);
static asmlinkage long (*orig_close)(unsigned int fd);
static asmlinkage long (*orig_uselib)(const char* library);
#ifdef TALPA_EXECVE_SUPPORT
static asmlinkage int (*orig_execve)(struct pt_regs regs);
#endif
static asmlinkage long (*orig_mount)(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
#if defined CONFIG_X86 && !defined CONFIG_X86_64
static asmlinkage long (*orig_umount)(char* name);
#endif
static asmlinkage long (*orig_umount2)(char* name, int flags);

#ifdef CONFIG_IA32_EMULATION
static asmlinkage long (*orig_open_32)(const char* filename, int flags, int mode);
static asmlinkage long (*orig_close_32)(unsigned int fd);
  #ifdef CONFIG_IA32_AOUT
static asmlinkage long (*orig_uselib_32)(const char* library);
  #endif
static asmlinkage long (*orig_mount_32)(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
static asmlinkage long (*orig_umount_32)(char* name);
static asmlinkage long (*orig_umount2_32)(char* name, int flags);
#endif

#ifdef TALPA_SHADOW_MAP
static void *talpa_syscallhook_unro(void *addr, size_t len, int rw);
#endif

static unsigned int check_table(void);

/*
 * Hooking mask:
 * o = open
 * c = close
 * l = uselib
 * e = execve
 * m = mount
 * u = umount
 */
#ifdef TALPA_EXECVE_SUPPORT
static char *hook_mask = "oclemu";
#else
static char *hook_mask = "oclmu";
#endif

#ifdef TALPA_HIDDEN_SYSCALLS
  #ifdef TALPA_SYSCALL_TABLE
static unsigned long syscall_table = TALPA_SYSCALL_TABLE;
  #else
static unsigned long syscall_table;
  #endif

  #ifdef CONFIG_IA32_EMULATION
    #ifdef TALPA_SYSCALL32_TABLE
static unsigned long syscall32_table = TALPA_SYSCALL32_TABLE;
    #else
static unsigned long syscall32_table;
    #endif
  #endif

static unsigned long force;
#endif

#ifdef TALPA_NEED_MANUAL_RODATA
  #ifdef TALPA_RODATA_START
static unsigned long rodata_start = TALPA_RODATA_START;
  #else
static unsigned long rodata_start;
  #endif

  #ifdef TALPA_RODATA_END
static unsigned long rodata_end = TALPA_RODATA_END;
  #else
static unsigned long rodata_end;
  #endif

static long rwdata_offset = 0;
#endif

#if defined(TALPA_HAS_RODATA) && !defined(TALPA_RODATA_MAP_WRITABLE)
/* Only need the mutex if we have to unprotect/reprotect around each access */
TALPA_DEFINE_MUTEX(rodata_lock);
#endif

/*
 * Exported interface
 */

unsigned int talpa_syscallhook_can_unload(void)
{
    return check_table() == 0;
}

int __talpa_syscallhook_register(unsigned int version, struct talpa_syscall_operations* ops)
{
    if ( version != TALPA_SYSCALLHOOK_IFACE_VERSION )
    {
        return -EPROTO;
    }

    if ( interceptor )
    {
        return -EBUSY;
    }

    if ( !ops )
    {
        return -EINVAL;
    }

    atomic_inc(&usecnt);
    interceptor = ops;

    return 0;
}

void talpa_syscallhook_unregister(struct talpa_syscall_operations* ops)
{
    if ( (!interceptor) || (!ops) || (ops != interceptor) )
    {
        err("Interface misuse!");
        return;
    }

    /* Remove interceptor, so that no new callers can get into it */
    interceptor = NULL;
    /* We will now care about wake ups */
    atomic_dec(&usecnt);
    /* Now wait for a last caller to exit */
    wait_event(unregister_wait, atomic_read(&usecnt) == 0);

    return;
}

#ifdef TALPA_HAS_MARK_RODATA_RW
extern void mark_rodata_rw(void);
extern void mark_rodata_ro(void);
#endif


#ifdef TALPA_HAS_RODATA

static int _talpa_syscallhook_modify_start(void)
{
  #ifndef TALPA_HAS_MARK_RODATA_RW
    unsigned long rwshadow;
  #endif

  #ifndef TALPA_RODATA_MAP_WRITABLE
    /* Don't need a lock if we are using shadow mappings */
    talpa_mutex_lock(&rodata_lock);
  #endif

  #ifdef TALPA_HAS_MARK_RODATA_RW
    mark_rodata_rw();
  #else
    rwshadow = (unsigned long)talpa_syscallhook_unro((void *)rodata_start, rodata_end - rodata_start, 1);
    if (!rwshadow)
    {
        dbg("RODATA: failed to map (0x%p - 0x%p)", (void *)rodata_start, (void *)rodata_end);
        return 1;
    }
    rwdata_offset = rwshadow - rodata_start;
  #endif

    return 0;
}

static void _talpa_syscallhook_modify_finish(void)
{
  #ifdef TALPA_HAS_MARK_RODATA_RW
    mark_rodata_ro();
  #else
    talpa_syscallhook_unro((void *)(rodata_start + rwdata_offset), rodata_end - rodata_start, 0);
    rwdata_offset = 0;
  #endif

  #ifndef TALPA_RODATA_MAP_WRITABLE
    /* Don't need a lock if we are using shadow mappings */
    talpa_mutex_unlock(&rodata_lock);
  #endif
}

  #ifdef TALPA_RODATA_MAP_WRITABLE
int talpa_syscallhook_modify_start(void)
{
    /* External functions don't need to do anything */
    return 0;
}

void talpa_syscallhook_modify_finish(void)
{
    /* External functions don't need to do anything */
    return;
}
  #else
int talpa_syscallhook_modify_start(void)
{
    return _talpa_syscallhook_modify_start();
}

void talpa_syscallhook_modify_finish(void)
{
    _talpa_syscallhook_modify_finish();
}
  #endif
#else /* TALPA_HAS_RODATA */

/* Don't need any implementation if the structures are writable anyway */

static int _talpa_syscallhook_modify_start(void)
{
    return 0;
}

int talpa_syscallhook_modify_start(void)
{
    return 0;
}

static void _talpa_syscallhook_modify_finish(void)
{
}

void talpa_syscallhook_modify_finish(void)
{
}
#endif



void *talpa_syscallhook_poke(void *addr, void *val)
{
    unsigned long target = (unsigned long)addr;

#ifdef TALPA_HAS_PROBE_KERNEL_WRITE
    long probeRes;
#endif


#if defined(TALPA_HAS_RODATA) && defined(TALPA_RODATA_MAP_WRITABLE)

    if (target >= rodata_start && target <= rodata_end)
    {
        target += rwdata_offset;
        *(void **)target = val;
        return (void *)target;
    }
#endif

#ifdef TALPA_HAS_PROBE_KERNEL_WRITE
    probeRes = probe_kernel_write((void*)target,(void*)&val,sizeof(void*));

#ifdef TALPA_SHADOW_MAP
    if (probeRes == -EFAULT)
    {
        unsigned long rwshadow;

        dbg("Write to 0x%p would have caused a fault, so shadow mapping a replacement.",(void*)target);

        rwshadow = (unsigned long)talpa_syscallhook_unro((void *)target, sizeof(void*), 1);
        if (rwshadow)
        {
            probeRes = probe_kernel_write((void*)rwshadow,(void*)&val,sizeof(void*));
            talpa_syscallhook_unro((void *)(rwshadow), sizeof(void*), 0);
        }
    }
#endif

    if (probeRes == -EFAULT)
    {
        err("Write to  0x%p would have caused a fault and failed to shadow map replacement.",(void*)target);
    }
#else
    *(void **)target = val;
#endif

    return (void *)target;
}

/*
 * Hooks
 */

static asmlinkage long talpa_open(const char* filename, int flags, int mode)
{
    struct talpa_syscall_operations* ops;
    int fd;


    atomic_inc(&usecnt);

    fd = orig_open(filename, flags, mode);

    if ( unlikely( fd < 0 ) )
    {
        goto out;
    }

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        int err;


        err = ops->open_post(fd);
        if ( unlikely ( err < 0 ) )
        {
            orig_close(fd);
            fd = err;
        }
    }

out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    prevent_tail_call(fd);
    return fd;
}

static asmlinkage long talpa_close(unsigned int fd)
{
    struct talpa_syscall_operations* ops;
    int err;


    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        ops->close_pre(fd);
    }

    err = orig_close(fd);

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    prevent_tail_call(err);
    return err;
}

static asmlinkage long talpa_uselib(const char* library)
{
    struct talpa_syscall_operations* ops;
    int err = 0;

    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        err = ops->uselib_pre(library);
        if ( unlikely( err < 0 ) )
        {
            goto out;
        }
    }

    err = orig_uselib(library);

out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    prevent_tail_call(err);
    return err;
}

/* This is a original sys_execve with talpa code injected */
#ifdef TALPA_EXECVE_SUPPORT
  #ifdef CONFIG_X86_64
static asmlinkage long talpa_execve(char __user * name,
                                    char __user * __user *argv,
                                    char __user * __user *envp,
                                    struct pt_regs regs)
{
    long error;
    TALPA_FILENAME_T * filename;
    struct talpa_syscall_operations* ops;
    #ifdef TALPA_HIDDEN_EXECVE
    long (*talpa_do_execve)(char *filename, char **argv, char **envp, struct pt_regs * regs) = (long (*)(char *filename, char **argv, char **envp, struct pt_regs * regs))TALPA_HIDDEN_EXECVE_ADDRESS;
    #else
    long (*talpa_do_execve)(char *filename, char **argv, char **envp, struct pt_regs * regs) = &do_execve;
    #endif

    atomic_inc(&usecnt);
    ops = interceptor;

    filename = talpa_getname(name);
    error = PTR_ERR(filename);
    if (IS_ERR(filename))
        goto out;

    if ( likely( ops != NULL ) )
    {
        error = ops->execve_pre(filename);
        if ( unlikely( error < 0 ))
        {
            goto out2;
        }
    }

    error = talpa_do_execve(name, argv, envp, &regs);
    if (error == 0)
    {
        task_lock(current);
        #ifdef PT_DTRACE
        current->ptrace &= ~PT_DTRACE;
        #endif
        task_unlock(current);
    }

out2:
    talpa_putname(filename);
out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    prevent_tail_call(error);
    return error;
}
  #elif defined CONFIG_X86
static asmlinkage int talpa_execve(struct pt_regs regs)
{
    int error;
    TALPA_FILENAME_T * filename;
    struct talpa_syscall_operations* ops;
    #ifdef TALPA_HIDDEN_EXECVE
    int (*talpa_do_execve)(char *filename, char **argv, char **envp, struct pt_regs * regs) = (int (*)(char *filename, char **argv, char **envp, struct pt_regs * regs))TALPA_HIDDEN_EXECVE_ADDRESS;
    #else
    int (*talpa_do_execve)(char *filename, char **argv, char **envp, struct pt_regs * regs) = &do_execve;
    #endif

    atomic_inc(&usecnt);
    ops = interceptor;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
    filename = talpa_getname((char *) regs.bx);
    #else
    filename = talpa_getname((char *) regs.ebx);
    #endif
    error = PTR_ERR(filename);
    if (IS_ERR(filename))
        goto out;

    if ( likely( ops != NULL ) )
    {
        error = ops->execve_pre(filename);
        if ( unlikely( error < 0 ))
        {
            goto out2;
        }
    }

    #ifdef TALPA_HAS_STRUCT_FILENAME
    error = talpa_do_execve((char *) regs.bx, (char **) regs.cx, (char **) regs.dx, &regs);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
    error = talpa_do_execve(filename, (char **) regs.cx, (char **) regs.dx, &regs);
    #else
    error = talpa_do_execve(filename, (char **) regs.ecx, (char **) regs.edx, &regs);
    #endif
    if (error == 0)
    {
        task_lock(current);
        #ifdef PT_DTRACE
        current->ptrace &= ~PT_DTRACE;
        #endif
        task_unlock(current);
        #ifdef TIF_IRET
        /* Make sure we don't return using sysenter.. */
        set_thread_flag(TIF_IRET);
        #endif
    }

out2:
    talpa_putname(filename);
out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    prevent_tail_call(error);
    return error;
}
  #else
    #warning "execve is not implemented on this architecture!"
  #endif
#else
/* This is not a #warning, as some kernels compile modules with -Werror */
#endif

static asmlinkage long talpa_mount(char __user *dev_name,
                                   char __user *dir_name,
                                   char __user *type,
                                   unsigned long flags,
                                   void __user *data)
{
    struct talpa_syscall_operations* ops;
    int err, err2;


    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        err = ops->mount_pre(dev_name, dir_name, type, flags, data);
        if ( unlikely( err < 0 ) )
        {
            goto out;
        }
    }

    err = orig_mount(dev_name, dir_name, type, flags, data);

    if ( likely( ops != NULL ) )
    {
        err2 = ops->mount_post(err, dev_name, dir_name, type, flags, data);
        if ( unlikely( err2 != 0 ) )
        {
            orig_umount2(dir_name, 0);
            err = err2;
        }
    }
out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    prevent_tail_call(err);
    return err;
}

#if defined CONFIG_X86 && (!defined CONFIG_X86_64 || CONFIG_IA32_EMULATION)
static asmlinkage long talpa_umount(char* name)
{
    struct talpa_syscall_operations* ops;
    int err;
    void* ctx = NULL;


    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        ops->umount_pre(name, 0, &ctx);
    }

  #ifdef CONFIG_IA32_EMULATION
    err = orig_umount_32(name);
  #else
    err = orig_umount(name);
  #endif

    if ( likely( ops != NULL ) )
    {
        ops->umount_post(err, name, 0, ctx);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    prevent_tail_call(err);
    return err;
}
#endif

static asmlinkage long talpa_umount2(char* name, int flags)
{
    struct talpa_syscall_operations* ops;
    int err;
    void* ctx = NULL;


    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        ops->umount_pre(name, flags, &ctx);
    }

    err = orig_umount2(name, flags);

    if ( likely( ops != NULL ) )
    {
        ops->umount_post(err, name, flags, ctx);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    prevent_tail_call(err);
    return err;
}

/*
 * System call table helpers
 */
#ifdef TALPA_HIDDEN_SYSCALLS
static void **sys_call_table;

  #ifdef CONFIG_IA32_EMULATION
static void **ia32_sys_call_table;
  #endif

/* Code below, which finds the hidden system call table,
   is borrowed from the ARLA project and modified.
   It is confirmed to work on 2.6 (x86, x86_64) and
   patched 2.4 (x86) kernels. */

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
static void *lower_bound = 0;
  #elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    #include <linux/kallsyms.h>
static void *lower_bound = &kernel_thread;
  #else
    #include <asm/pgtable.h>
static void *lower_bound = &empty_zero_page;
  #endif

const char * __attribute__((weak)) kallsyms_lookup(unsigned long addr, unsigned long *symbolsize, unsigned long *offset, char **modname, char *namebuf);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)

static void **get_start_addr(void)
{
    /* This isn't used very much as the address is compiled in by the configure script
     * so we won't deal with it for 2.6.39+ as I can't find a symbol to use
     */
#ifdef TALPA_HIDDEN_SYSCALLS
  #ifndef TALPA_SYSCALL_TABLE
    #error "Syscall table address not built in"
  #endif
#endif
    dbg("Syscall searching not available for 2.6.39+");
    return (void **)0;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
static void **get_start_addr(void)
{
    #ifdef CONFIG_SMP
      #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
    return (void **)&_lock_kernel;
      #else
    return (void **)&lock_kernel;
      #endif
    #else
      #include <linux/mutex.h>
      #ifdef CONFIG_DEBUG_LOCK_ALLOC
    return (void **)&mutex_lock_nested;
      #else
    return (void **)&mutex_lock;
      #endif
    #endif
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16) */

static void **get_start_addr(void)
{
    #ifdef CONFIG_X86_64
      return (void **)&tasklist_lock - 0x4000;
    #else
      return (void **)&init_mm;
    #endif
}

#endif

#ifdef CONFIG_IA32_EMULATION

# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)

static void **get_start_addr_ia32(void)
{
    /* This isn't used very much as the address is compiled in by the configure script
     * so we won't deal with it for 2.6.39+ as I can't find a symbol to use
     */
#ifdef TALPA_HIDDEN_SYSCALLS
  #ifndef TALPA_SYSCALL32_TABLE
    #error "Syscall32 table address not built in"
  #endif
#endif
    dbg("Syscall searching not available for 2.6.39+");
    return (void **)0;
}
#else /* ! LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) */
static void **get_start_addr_ia32(void)
{
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
      #ifdef CONFIG_SMP
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
    return (void **)&_lock_kernel;
        #else
    return (void **)&lock_kernel;
        #endif
      #else
        #include <linux/mutex.h>
    return (void **)&mutex_lock;
      #endif
    #else
    return (void **)&console_printk - 0x4000;
    #endif
}
# endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) */
#endif /* CONFIG_IA32_EMULATION */

static int kallsym_is_equal(unsigned long addr, const char *name)
{
    char namebuf[128];
    const char *retname;
    unsigned long size, offset;
    char *modname;


    retname = kallsyms_lookup(addr, &size, &offset, &modname, namebuf);

    if ( (retname != NULL) && (strcmp(name, retname) == 0) && (offset == 0) )
    {
        return 1;
    }

    return 0;
}

static int verify(void **p, const unsigned int unique_syscalls[], const unsigned int num_unique_syscalls, const unsigned int zapped_syscalls[], const unsigned int num_zapped_syscalls, int symlookup)
{
    unsigned int i, s;


    /* Check that not implemented system calls all point to the same address.
        This is where heuristic usually immediately fails. */
    for ( i = 1; i < num_zapped_syscalls; i++ )
    {
        if ( p[zapped_syscalls[i]] != p[zapped_syscalls[0]] )
        {
                dbg("  [0x%p] not same %u", p, zapped_syscalls[i]);
            return 0;
        }
    }

    /* Check that all different sysmte calls are really different */
    for ( i = 0; i < num_unique_syscalls; i++ )
    {
        for ( s = 0; s < 223; s++ )
        {
            if ( (p[s] == p[unique_syscalls[i]]) && (s != unique_syscalls[i]) )
            {
                dbg("  [0x%p] not unique %u", p, unique_syscalls[i]);
                return 0;
            }
        }
    }

    /* Lookup symbols (if we can) as a final check */
    if (    symlookup
         && kallsyms_lookup
         && !IS_ERR(kallsyms_lookup)
         && (    !kallsym_is_equal((unsigned long)p[__NR_close], "sys_close")
              || !kallsym_is_equal((unsigned long)p[__NR_chdir], "sys_chdir")) )
    {
        dbg("  [0x%p] lookup mismatch", p);
        return 0;
    }

    return 1;
}

static int looks_good(void **p)
{
    if ( (*p <= (void*)lower_bound) || (*p >= (void*)p) )
    {
        return 0;
    }

    return 1;
}

static void **talpa_find_syscall_table(void **ptr, const unsigned int unique_syscalls[], const unsigned int num_unique_syscalls, const unsigned int zapped_syscalls[], const unsigned int num_zapped_syscalls, int symlookup)
{
    void **limit = ptr + 0xa000;
    void **table = NULL;
#ifdef DEBUG
    unsigned int i;

    dbg_start();
    dbg_cont("unique: ");
    for ( i = 0; i < num_unique_syscalls; i++ )
    {
        dbg_cont("%u ", unique_syscalls[i]);
    }
    dbg_end();

    dbg_start();
    dbg_cont("zapped: ");
    for ( i = 0; i < num_zapped_syscalls; i++ )
    {
        dbg_cont("%u ", zapped_syscalls[i]);
    }
    dbg_end();

    dbg("scan from 0x%p to 0x%p", ptr, limit);
#endif

    for ( ; ptr < limit && table == NULL; ptr++ )
    {
        unsigned int ok = 1;
        unsigned int i;


        for ( i = 0; i < 222; i++ )
        {
            if ( !looks_good(ptr + i) )
            {
                ok = 0;
                ptr = ptr + i;
                break;
            }
        }

        if ( ok && verify(ptr, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, symlookup) )
        {
            table = ptr;
            break;
        }
    }

    return table;
}

#else
extern void *sys_call_table[];
#endif

#ifdef TALPA_SHADOW_MAP

#if defined(TALPA_RODATA_MAP_WRITABLE)
/*
 * map_writable creates a shadow page mapping of the range
 * [addr, addr + len) so that we can write to code mapped read-only.
 *
 * It is similar to a generalized version of x86's text_poke.  But
 * because one cannot use vmalloc/vfree() inside stop_machine, we use
 * map_writable to map the pages before stop_machine, then use the
 * mapping inside stop_machine, and unmap the pages afterwards.
 */
static void *map_writable(void *addr, size_t len)
{
        void *vaddr;
        int nr_pages = DIV_ROUND_UP(offset_in_page(addr) + len, PAGE_SIZE);
        struct page **pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL);
        void *page_addr = (void *)((unsigned long)addr & PAGE_MASK);
        int i;

        if (pages == NULL)
                return NULL;

        for (i = 0; i < nr_pages; i++) {
                if (__module_address((unsigned long)page_addr) == NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22) || !defined(CONFIG_X86_64)
                        pages[i] = virt_to_page(page_addr);
#else /* LINUX_VERSION_CODE < && CONFIG_X86_64 */
/* e3ebadd95cb621e2c7436f3d3646447ac9d5c16d was after 2.6.21
 * This works around a broken virt_to_page() from the RHEL 5 backport
 * of x86-64 relocatable kernel support.
 */
                        pages[i] =
                            pfn_to_page(__pa_symbol(page_addr) >> PAGE_SHIFT);
#endif /* LINUX_VERSION_CODE || !CONFIG_X86_64 */
                        WARN_ON(!PageReserved(pages[i]));
                } else {
                        pages[i] = vmalloc_to_page(addr);
                }
                if (pages[i] == NULL) {
                        kfree(pages);
                        return NULL;
                }
                page_addr += PAGE_SIZE;
        }
        vaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
        kfree(pages);
        if (vaddr == NULL)
                return NULL;
        return vaddr + offset_in_page(addr);
}

static void *talpa_syscallhook_unro(void *addr, size_t len, int rw)
{
    if ( rw )
    {
        return map_writable(addr, len);
    }
    else
    {
        vunmap((void *)((unsigned long)addr & PAGE_MASK));
        return NULL;
    }
}

#elif defined(TALPA_NEED_MANUAL_RODATA)

#  ifdef TALPA_NEEDS_VA_CPA

#    ifdef TALPA_NO_PA_SYMBOL
static unsigned long *talpa_phys_base = (unsigned long *)TALPA_PHYS_BASE;

#      define talpa_pa_symbol(x) \
        ({unsigned long v;  \
          asm("" : "=r" (v) : "0" (x)); \
          ((v - __START_KERNEL_map) + (*talpa_phys_base)); })
#    else
#      define talpa_pa_symbol __pa_symbol
#    endif

#    define talpa_ka_to_cpa(adr) ((unsigned long)__va(talpa_pa_symbol(adr)))

#  else /* NEEDS_VA_CPA */
#    define talpa_ka_to_cpa(adr) ((unsigned long)adr)
#  endif /* NEEDS_VA_CPA */

static void *talpa_syscallhook_unro(void *addr, size_t len, int rw)
{
    unsigned long nr_pages = len / PAGE_SIZE;


  #ifdef TALPA_HAS_SET_PAGES
    #ifdef CONFIG_X86_64
    typedef int (*kfunc)(unsigned long addr, int numpages);
    kfunc set_memory_rwro;


    if ( rw )
    {
        set_memory_rwro  = (kfunc)TALPA_KFUNC_SET_MEMORY_RW;
    }
    else
    {
        set_memory_rwro  = (kfunc)TALPA_KFUNC_SET_MEMORY_RO;
    }

    set_memory_rwro(addr, nr_pages);
    #elif CONFIG_X86
    typedef int (*kfunc)(struct page *page, int numpages);
    kfunc set_pages_rwro;


    if ( rw )
    {
        set_pages_rwro  = (kfunc)TALPA_KFUNC_SET_PAGES_RW;
    }
    else
    {
        set_pages_rwro  = (kfunc)TALPA_KFUNC_SET_PAGES_RO;
    }

    set_pages_rwro(virt_to_page(addr), nr_pages);
    #endif
  #else /* HAS_SET_PAGES */
    #ifdef CONFIG_X86_64
    typedef int (*kfunc)(unsigned long addr, int numpages, pgprot_t prot);
    static kfunc talpa_change_page_attr_addr = (kfunc)TALPA_KFUNC_CHANGE_PAGE_ATTR_ADDR;

    if ( rw )
    {
        talpa_change_page_attr_addr(talpa_ka_to_cpa(addr), nr_pages, PAGE_KERNEL);
    }
    else
    {
        talpa_change_page_attr_addr(talpa_ka_to_cpa(addr), nr_pages, PAGE_KERNEL_RO);
    }
    #elif CONFIG_X86
    if ( rw )
    {
        change_page_attr(virt_to_page(addr), nr_pages, PAGE_KERNEL);
    }
    else
    {
        change_page_attr(virt_to_page(addr), nr_pages, PAGE_KERNEL_RO);
    }
    #endif

    global_flush_tlb();
  #endif

    return addr;
}
#endif /* defined(TALPA_RODATA_MAP_WRITABLE) else defined(TALPA_NEED_MANUAL_RODATA) */
#endif /* TALPA_SHADOW_MAP */

#ifdef TALPA_HIDDEN_SYSCALLS
static void **look_around(void **p, const unsigned int unique_syscalls[], const unsigned int num_unique_syscalls, const unsigned int zapped_syscalls[], const unsigned int num_zapped_syscalls, int symlookup)
{
    unsigned char* orig_addr = (unsigned char *)p;
    unsigned char* start_addr = orig_addr - sizeof(void *) * 2;
    unsigned char* end_addr = orig_addr + sizeof(void *) * 2;


    for ( ;start_addr < end_addr; start_addr++ )
    {
        unsigned int ok = 1;
        unsigned int i;


        for ( i = 0; i < 222; i++ )
        {
            if ( !looks_good((void *)start_addr + i) )
            {
                ok = 0;
                break;
            }
        }

        if ( ok && verify((void **)start_addr, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, symlookup) )
        {
            info("At offset %ld", (long int)(start_addr - orig_addr));
            return (void **)start_addr;
        }
    }

    return NULL;
}

static void **find_around(void **p, const unsigned int unique_syscalls[], const unsigned int num_unique_syscalls, const unsigned int zapped_syscalls[], const unsigned int num_zapped_syscalls, int symlookup)
{
    unsigned char* orig_addr = (unsigned char *)p;
    unsigned char* start_addr = orig_addr - sizeof(void *) * 2;
    unsigned char* end_addr = orig_addr + sizeof(void *) * 2;
    void **res;


    for ( ;start_addr < end_addr; start_addr++ )
    {
        res = talpa_find_syscall_table((void **)start_addr, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, symlookup);
        if ( res )
        {
            info("Found with offset %ld", (long int)(start_addr - orig_addr));
            return res;
        }
    }

    return NULL;
}

static int find_syscall_table(void)
{
    unsigned int num_unique_syscalls;
    unsigned int num_zapped_syscalls;

  #ifdef CONFIG_X86_64

    const unsigned int unique_syscalls[] = { __NR_read, __NR_dup, __NR_open, __NR_close, __NR_mmap, __NR_exit, __NR_kill };
    const unsigned int zapped_syscalls[] = { __NR_create_module, __NR_get_kernel_syms, __NR_security, __NR_get_thread_area, __NR_epoll_wait_old, __NR_vserver, 0 };

    #ifdef CONFIG_IA32_EMULATION

      #define __NR_open_ia32      5
      #define __NR_close_ia32     6
      #define __NR_uselib_ia32    86
      #define __NR_mount_ia32     21
      #define __NR_umount_ia32    22
      #define __NR_umount2_ia32   52
      #define __NR_break_ia32     17
      #define __NR_stty_ia32      31
      #define __NR_gtty_ia32      32
      #define __NR_ftime_ia32     35
      #define __NR_prof_ia32      44
      #define __NR_lock_ia32      53
      #define __NR_ulimit_ia32    58
      #define __NR_exit_ia32      1
      #define __NR_read_ia32      3
      #define __NR_write_ia32     4
      #define __NR_unlink_ia32    10

    const unsigned int unique_syscalls_ia32[] = { __NR_exit_ia32, __NR_mount_ia32, __NR_read_ia32, __NR_write_ia32, __NR_open_ia32, __NR_close_ia32, __NR_unlink_ia32 };
    const unsigned int zapped_syscalls_ia32[] = { __NR_break_ia32, __NR_stty_ia32, __NR_gtty_ia32, __NR_ftime_ia32, __NR_prof_ia32, __NR_lock_ia32, __NR_ulimit_ia32, 0 };
    const unsigned int num_unique_syscalls_ia32 = sizeof(unique_syscalls_ia32)/sizeof(unique_syscalls_ia32[0]);
    const unsigned int num_zapped_syscalls_ia32 = (sizeof(zapped_syscalls_ia32)/sizeof(zapped_syscalls_ia32[0])) - 1;

    if ( syscall32_table )
    {
        ia32_sys_call_table = (void **)syscall32_table;

        if ( verify(ia32_sys_call_table, unique_syscalls_ia32, num_unique_syscalls_ia32, zapped_syscalls_ia32, num_zapped_syscalls_ia32, 0) )
        {
            dbg("userspace specified ia32_sys_call_table at 0x%p", ia32_sys_call_table);
        }
        else if ( force )
        {
            dbg("userspace forced ia32_sys_call_table at 0x%p", ia32_sys_call_table);
        }
        else
        {
            dbg("not an ia32_sys_call_table at 0x%p", ia32_sys_call_table);
            /* Look around specified address before giving up. */
            ia32_sys_call_table = look_around(ia32_sys_call_table, unique_syscalls_ia32, num_unique_syscalls_ia32, zapped_syscalls_ia32, num_zapped_syscalls_ia32, 0);
            if ( !ia32_sys_call_table )
            {
                dbg("no ia32_sys_call_table around 0x%lx", syscall32_table);
            }
            syscall32_table = (unsigned long)ia32_sys_call_table;
        }
    }

    /* If valid address wasn't supplied to us we'll try to autodetect it */
    if ( !syscall32_table )
    {
        void ** startaddr = get_start_addr_ia32();

        if (startaddr == NULL)
        {
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
                err("The syscall32_table value is not valid, you will need to reboot your system");
            #else
                err("The syscall32_table value is not valid");
            #endif
            return -EFAULT;
        }

        ia32_sys_call_table = talpa_find_syscall_table(startaddr, unique_syscalls_ia32, num_unique_syscalls_ia32, zapped_syscalls_ia32, num_zapped_syscalls_ia32, 0);
        if ( !ia32_sys_call_table )
        {
            dbg("no ia32_sys_call_table found");
            /* Look around specified address before giving up. */
            ia32_sys_call_table = find_around(startaddr, unique_syscalls_ia32, num_unique_syscalls_ia32, zapped_syscalls_ia32, num_zapped_syscalls_ia32, 0);
            if ( !ia32_sys_call_table )
            {
                dbg("no ia32_sys_call_table found");
            }
        }
        syscall32_table = (unsigned long)ia32_sys_call_table;
    }

    if ( ia32_sys_call_table == NULL )
    {
        err("Cannot find IA32 emulation syscall table!");
        return -ESRCH;
    }

    dbg("IA32 syscall table at 0x%p", ia32_sys_call_table);
    #endif

  #elif CONFIG_X86
    const unsigned int unique_syscalls[] = { __NR_exit, __NR_mount, __NR_read, __NR_write, __NR_open, __NR_close, __NR_unlink };
    const unsigned int zapped_syscalls[] = { __NR_break, __NR_stty, __NR_gtty, __NR_ftime, __NR_prof, __NR_lock, __NR_ulimit, 0 };
  #endif
    num_unique_syscalls = sizeof(unique_syscalls)/sizeof(unique_syscalls[0]);
    num_zapped_syscalls = (sizeof(zapped_syscalls)/sizeof(zapped_syscalls[0])) - 1;

    if ( syscall_table )
    {
        sys_call_table = (void **)syscall_table;

        if ( verify(sys_call_table, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, 1) )
        {
            dbg("userspace specified sys_call_table at 0x%p", sys_call_table);
        }
        else if ( force )
        {
            dbg("userspace forced sys_call_table at 0x%p", sys_call_table);
        }
        else
        {
            dbg("not a sys_call_table at 0x%p", sys_call_table);
            /* Look around specified address before giving up. */
            sys_call_table = look_around(sys_call_table, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, 1);
            if ( !sys_call_table )
            {
                dbg("no sys_call_table around 0x%lx", syscall_table);
            }
            syscall_table = (unsigned long)sys_call_table;
        }
    }

    /* If valid address wasn't supplied to us we'll try to autodetect it */
    if ( !syscall_table )
    {
        void** startaddr = get_start_addr();

        if (startaddr == NULL)
        {
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
                err("The syscall_table value is not valid, you will need to reboot your system");
            #else
                err("The syscall_table value is not valid");
            #endif

            return -EFAULT;
        }

        sys_call_table = talpa_find_syscall_table(startaddr, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, 1);
        if ( !sys_call_table )
        {
            dbg("no sys_call_table found");
            /* Look around specified address before giving up. */
            sys_call_table = find_around(startaddr, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, 1);
            if ( !sys_call_table )
            {
                dbg("no sys_call_table found");
            }
        }
        syscall_table = (unsigned long)sys_call_table;
    }

    if ( sys_call_table == NULL )
    {
        err("Cannot find syscall table!");
        return -ESRCH;
    }

    dbg("Syscall table at 0x%p", sys_call_table);
    return 0;
}
#else
static int find_syscall_table(void)
{
    return 0;
}
#endif

static void save_originals(void)
{
#ifdef CONFIG_X86
    orig_open = sys_call_table[__NR_open];
    orig_close = sys_call_table[__NR_close];
  #ifdef TALPA_EXECVE_SUPPORT
    orig_execve = sys_call_table[__NR_execve];
  #endif
    orig_uselib = sys_call_table[__NR_uselib];
    orig_mount = sys_call_table[__NR_mount];
  #if defined CONFIG_X86_64
    orig_umount2 = sys_call_table[__NR_umount2];
    #ifdef CONFIG_IA32_EMULATION
    orig_open_32 = ia32_sys_call_table[__NR_open_ia32];
    orig_close_32 = ia32_sys_call_table[__NR_close_ia32];
      #ifdef CONFIG_IA32_AOUT
    orig_uselib_32 = ia32_sys_call_table[__NR_uselib_ia32];
      #endif
    orig_mount_32 = ia32_sys_call_table[__NR_mount_ia32];
    orig_umount_32 = ia32_sys_call_table[__NR_umount_ia32];
    orig_umount2_32 = ia32_sys_call_table[__NR_umount2_ia32];
    #endif
  #else
    orig_umount = sys_call_table[__NR_umount];
    orig_umount2 = sys_call_table[__NR_umount2];
  #endif
#else
  #error "Architecture currently not supported!"
#endif
}

#define patch_syscall(base, num, new) talpa_syscallhook_poke(&base[num], new)

static void patch_table(void)
{
    if ( strchr(hook_mask, 'o') )
    {
        patch_syscall(sys_call_table, __NR_open, talpa_open);
#ifdef CONFIG_IA32_EMULATION
        patch_syscall(ia32_sys_call_table, __NR_open_ia32, talpa_open);
#endif
    }

    if ( strchr(hook_mask, 'c') )
    {
        patch_syscall(sys_call_table, __NR_close, talpa_close);
#ifdef CONFIG_IA32_EMULATION
        patch_syscall(ia32_sys_call_table, __NR_close_ia32, talpa_close);
#endif
    }

    if ( strchr(hook_mask, 'l') )
    {
        patch_syscall(sys_call_table, __NR_uselib, talpa_uselib);
#if defined CONFIG_IA32_EMULATION && defined CONFIG_IA32_AOUT
        patch_syscall(ia32_sys_call_table, __NR_uselib_ia32, talpa_uselib);
#endif
    }

    if ( strchr(hook_mask, 'm') )
    {
        patch_syscall(sys_call_table, __NR_mount, talpa_mount);
#ifdef CONFIG_IA32_EMULATION
        patch_syscall(ia32_sys_call_table, __NR_mount_ia32, talpa_mount);
#endif
    }

    if ( strchr(hook_mask, 'u') )
    {
#if defined CONFIG_X86
 #if defined CONFIG_X86_64
        patch_syscall(sys_call_table, __NR_umount2, talpa_umount2);
 #else
        patch_syscall(sys_call_table, __NR_umount, talpa_umount);
        patch_syscall(sys_call_table, __NR_umount2, talpa_umount2);
 #endif
#endif
#ifdef CONFIG_IA32_EMULATION
        patch_syscall(ia32_sys_call_table, __NR_umount_ia32, talpa_umount);
        patch_syscall(ia32_sys_call_table, __NR_umount2_ia32, talpa_umount2);
#endif
    }

#ifdef TALPA_EXECVE_SUPPORT
    if ( strchr(hook_mask, 'e') )
    {
        patch_syscall(sys_call_table, __NR_execve, talpa_execve);
    }
#endif
}

static unsigned int check_table(void)
{
    unsigned int rc = 0;


    if ( strchr(hook_mask, 'o') )
    {
        if ( sys_call_table[__NR_open] != talpa_open &&
             sys_call_table[__NR_open] != orig_open)
        {
            warn("open() is patched by someone else!");
            rc = 1;
        }
#ifdef CONFIG_IA32_EMULATION
        if ( ia32_sys_call_table[__NR_open_ia32] != talpa_open &&
             ia32_sys_call_table[__NR_open_ia32] != orig_open_32)
        {
            warn("ia32_open() is patches by someone else!");
            rc = 1;
        }
#endif
    }

    if ( strchr(hook_mask, 'c') )
    {
        if ( sys_call_table[__NR_close] != talpa_close &&
             sys_call_table[__NR_close] != orig_close)
        {
            warn("close() is patched by someone else!");
            rc = 1;
        }
#ifdef CONFIG_IA32_EMULATION
        if ( ia32_sys_call_table[__NR_close_ia32] != talpa_close &&
             ia32_sys_call_table[__NR_close_ia32] != orig_close_32)
        {
            warn("ia32_close() is patched by someone else!");
            rc = 1;
        }
#endif
    }

    if ( strchr(hook_mask, 'l') )
    {
        if ( sys_call_table[__NR_uselib] != talpa_uselib &&
             sys_call_table[__NR_uselib] != orig_uselib)
        {
            warn("uselib() is patched by someone else!");
            rc = 1;
        }
#if defined CONFIG_IA32_EMULATION && defined CONFIG_IA32_AOUT
        if ( ia32_sys_call_table[__NR_uselib_ia32] != talpa_uselib &&
             ia32_sys_call_table[__NR_uselib_ia32] != orig_uselib_32)
        {
            warn("ia32_uselib() is patched by someone else!");
            rc = 1;
        }
#endif
    }

    if ( strchr(hook_mask, 'm') )
    {
        if ( sys_call_table[__NR_mount] != talpa_mount &&
             sys_call_table[__NR_mount] != orig_mount )
        {
            warn("mount() is patched by someone else!");
            rc = 1;
        }
#ifdef CONFIG_IA32_EMULATION
        if ( ia32_sys_call_table[__NR_mount_ia32] != talpa_mount &&
             ia32_sys_call_table[__NR_mount_ia32] != orig_mount_32)
        {
            warn("ia32_mount() is patched by someone else!");
            rc = 1;
        }
#endif
    }

    if ( strchr(hook_mask, 'u') )
    {
#if defined CONFIG_X86
 #if defined CONFIG_X86_64
        if ( sys_call_table[__NR_umount2] != talpa_umount2 &&
             sys_call_table[__NR_umount2] != orig_umount2)
        {
            warn("umount2() is patched by someone else!");
            rc = 1;
        }
 #else
        if ( sys_call_table[__NR_umount] != talpa_umount &&
             sys_call_table[__NR_umount] != orig_umount)
        {
            warn("umount() is patched by someone else!");
            rc = 1;
        }
        if ( sys_call_table[__NR_umount2] != talpa_umount2 &&
             sys_call_table[__NR_umount2] != orig_umount2)
        {
            warn("umount2() is patched by someone else!");
            rc = 1;
        }
 #endif
#endif
#ifdef CONFIG_IA32_EMULATION
        if ( ia32_sys_call_table[__NR_umount_ia32] != talpa_umount &&
             ia32_sys_call_table[__NR_umount_ia32] != orig_umount_32)
        {
            warn("ia32_umount() is patched by someone else!");
            rc = 1;
        }
        if ( ia32_sys_call_table[__NR_umount2_ia32] != talpa_umount2 &&
             ia32_sys_call_table[__NR_umount2_ia32] != orig_umount2_32)
        {
            warn("ia32_umount2() is patched by someone else!");
            rc = 1;
        }
#endif
    }

#ifdef TALPA_EXECVE_SUPPORT
    if ( strchr(hook_mask, 'e') )
    {
        if ( sys_call_table[__NR_execve] != talpa_execve &&
             sys_call_table[__NR_execve] != orig_execve)
        {
            warn("execve() is patched by someone else!");
            rc = 1;
        }
    }
#endif

    return rc;
}

static void restore_table(void)
{
#if defined CONFIG_X86
    patch_syscall(sys_call_table, __NR_open, orig_open);
    patch_syscall(sys_call_table, __NR_close, orig_close);
  #ifdef TALPA_EXECVE_SUPPORT
    patch_syscall(sys_call_table, __NR_execve, orig_execve);
  #endif
    patch_syscall(sys_call_table, __NR_uselib, orig_uselib);
    patch_syscall(sys_call_table, __NR_mount, orig_mount);
  #if defined CONFIG_X86_64
    patch_syscall(sys_call_table, __NR_umount2, orig_umount2);
    #ifdef CONFIG_IA32_EMULATION
    patch_syscall(ia32_sys_call_table, __NR_open_ia32, orig_open_32);
    patch_syscall(ia32_sys_call_table, __NR_close_ia32, orig_close_32);
      #ifdef CONFIG_IA32_AOUT
    patch_syscall(ia32_sys_call_table, __NR_uselib_ia32, orig_uselib_32);
      #endif
    patch_syscall(ia32_sys_call_table, __NR_mount_ia32, orig_mount_32);
    patch_syscall(ia32_sys_call_table, __NR_umount_ia32, orig_umount_32);
    patch_syscall(ia32_sys_call_table, __NR_umount2_ia32, orig_umount2_32);
    #endif
  #else
    patch_syscall(sys_call_table, __NR_umount, orig_umount);
    patch_syscall(sys_call_table, __NR_umount2, orig_umount2);
  #endif
#endif
}

/*
 * Module init and exit
 */

static int __init talpa_syscallhook_init(void)
{
    int ret;


#ifdef TALPA_HIDDEN_SYSCALLS
    lower_bound = (void*)((unsigned long)lower_bound & ~0xfffff);
    dbg("lower bound 0x%p", lower_bound);

    /* Relocate addresses (if needed) embedded at compile time. */
    syscall_table = (unsigned long)talpa_get_symbol("sys_call_table", (void *)syscall_table);
  #ifdef CONFIG_IA32_EMULATION
    syscall32_table = (unsigned long)talpa_get_symbol("ia32_sys_call_table", (void *)syscall32_table);
  #endif
#endif

#ifdef TALPA_NEED_MANUAL_RODATA
   rodata_start = (unsigned long)talpa_get_symbol("__start_rodata", (void *)rodata_start);
   rodata_end = (unsigned long)talpa_get_symbol("__end_rodata", (void *)rodata_end);
#endif

    ret = find_syscall_table();
    if ( ret < 0 )
    {
        return ret;
    }

    talpa_lock_kernel();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fsync_dev(0);
#endif
    save_originals();
    /* For shadow mapping this creates the mapping */
    ret = _talpa_syscallhook_modify_start();
    if (ret)
    {
        talpa_unlock_kernel();
        err("Failed to unprotect read-only memory!");
        return ret;
    }
    patch_table();
    /* For shadow mapping this is a noop */
    talpa_syscallhook_modify_finish();
    talpa_unlock_kernel();

    dbg("Hooked [%s]", hook_mask);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    inter_module_register("talpa_syscallhook_can_unload", THIS_MODULE, (const void *)talpa_syscallhook_can_unload);
    inter_module_register("__talpa_syscallhook_register", THIS_MODULE, (const void *)__talpa_syscallhook_register);
    inter_module_register("talpa_syscallhook_unregister", THIS_MODULE, (const void *)talpa_syscallhook_unregister);
    inter_module_register("talpa_syscallhook_modify_start", THIS_MODULE, (const void *)talpa_syscallhook_modify_start);
    inter_module_register("talpa_syscallhook_modify_finish", THIS_MODULE, (const void *)talpa_syscallhook_modify_finish);
#endif

    return 0;
}

static void __exit talpa_syscallhook_exit(void)
{
    int ret;


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    inter_module_unregister("talpa_syscallhook_can_unload");
    inter_module_unregister("__talpa_syscallhook_register");
    inter_module_unregister("talpa_syscallhook_unregister");
    inter_module_unregister("talpa_syscallhook_modify_start");
    inter_module_unregister("talpa_syscallhook_modify_finish");
#endif

    talpa_lock_kernel();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fsync_dev(0);
#endif

    /* We have to cater for the possibility that someone else
       has modified the syscall table after us. Therefore we
       will check for that and sleep until the situation resolves.
       There isn't really a perfect solution in these sorts of
       unsupported oprations so it is better to hang here than
       to cause system instability in any way.
       The best thing would be to leave this module loaded forever.
    */
    while ( check_table() != 0 )
    {
        talpa_unlock_kernel();
        __set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(HZ);
        talpa_lock_kernel();
    }
    do
    {
        /* For shadow mapping this is a noop */
        ret = talpa_syscallhook_modify_start();
        if (ret)
        {
            talpa_unlock_kernel();
            err("Failing to unprotect read-only memory!");
            __set_current_state(TASK_UNINTERRUPTIBLE);
            schedule_timeout(HZ);
            talpa_lock_kernel();
        }
    } while (ret); /* Unfortunate but we can't possibly exit if we failed to restore original pointers. */
    restore_table();
    /* With shadow mapping, this will actually free the shadow mapping */
    _talpa_syscallhook_modify_finish();
    talpa_unlock_kernel();

    /* Now wait for a last caller to exit */
    wait_event(unregister_wait, atomic_read(&usecnt) == 0);

    dbg("Unhooked");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

EXPORT_SYMBOL(talpa_syscallhook_can_unload);
EXPORT_SYMBOL(__talpa_syscallhook_register);
EXPORT_SYMBOL(talpa_syscallhook_unregister);
EXPORT_SYMBOL(talpa_syscallhook_modify_start);
EXPORT_SYMBOL(talpa_syscallhook_modify_finish);
EXPORT_SYMBOL(talpa_syscallhook_poke);

module_param(hook_mask, charp, 0400);
  #ifdef TALPA_HIDDEN_SYSCALLS
module_param(syscall_table, ulong, 0400);
    #ifdef CONFIG_IA32_EMULATION
module_param(syscall32_table, ulong, 0400);
    #endif
module_param(force, ulong, 0400);
  #endif
  #ifdef TALPA_NEED_MANUAL_RODATA
module_param(rodata_start, ulong, 0400);
module_param(rodata_end, ulong, 0400);
  #endif

#else

EXPORT_SYMBOL_NOVERS(talpa_syscallhook_can_unload);
EXPORT_SYMBOL_NOVERS(__talpa_syscallhook_register);
EXPORT_SYMBOL_NOVERS(talpa_syscallhook_unregister);
EXPORT_SYMBOL_NOVERS(talpa_syscallhook_modify_start);
EXPORT_SYMBOL_NOVERS(talpa_syscallhook_modify_finish);
EXPORT_SYMBOL_NOVERS(talpa_syscallhook_poke);

MODULE_PARM(hook_mask, "s");
  #ifdef TALPA_HIDDEN_SYSCALLS
MODULE_PARM(syscall_table, "l");
    #ifdef CONFIG_IA32_EMULATION
MODULE_PARM(syscall32_table, "l");
    #endif
MODULE_PARM(force, "l");
  #endif
  #ifdef TALPA_NEED_MANUAL_RODATA
MODULE_PARM(rodata_start, "l");
MODULE_PARM(rodata_end, "l");
  #endif

#endif /* >= 2.6.0 */

#ifdef TALPA_EXECVE_SUPPORT
MODULE_PARM_DESC(hook_mask, "list of system calls to hook where o=open, c=close, l=uselib, e=execve, m=mount and u=umount (default: oclemu)");
#else
MODULE_PARM_DESC(hook_mask, "list of system calls to hook where o=open, c=close, l=uselib, m=mount and u=umount (default: oclmu)");
#endif
#ifdef TALPA_HIDDEN_SYSCALLS
MODULE_PARM_DESC(syscall_table, "system call table address");
  #ifdef CONFIG_IA32_EMULATION
MODULE_PARM_DESC(syscall32_table, "ia32 emulation system call table address");
  #endif
MODULE_PARM_DESC(force, "ignore system call table verfication results");
#endif
#ifdef TALPA_NEED_MANUAL_RODATA
MODULE_PARM_DESC(rodata_start, "start of read-only data section");
MODULE_PARM_DESC(rodata_end, "end of read-only data section");
#endif

module_init(talpa_syscallhook_init);
module_exit(talpa_syscallhook_exit);

MODULE_DESCRIPTION("Hooks into the syscall table and provides hooking interface for one module.");
MODULE_AUTHOR("Sophos Limited");
MODULE_LICENSE("GPL");
#if defined TALPA_VERSION && defined MODULE_VERSION
MODULE_VERSION(TALPA_VERSION);
#endif


/*
 * End of talpa_syscallhook.c
 */

