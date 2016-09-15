#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dotruncatetest"
#endif

#include "autoconf.h"

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#include <linux/posix_types.h>

#ifndef __kernel_long_t
typedef long   __kernel_long_t;
#endif

#ifndef __kernel_ulong_t
typedef unsigned long   __kernel_ulong_t;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <linux/kconfig.h>
#endif

#include <linux/fs.h>

/* do_truncate(struct dentry*, loff_t, unsigned int, struct file*) */
int main()
{
    struct dentry *dentry = NULL;
    loff_t start = 0;
    struct file *filp = NULL;
    unsigned int time_attrs = 0;

    return do_truncate(dentry, start, time_attrs, filp);
}
