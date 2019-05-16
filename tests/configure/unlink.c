#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#unlinktest"
#endif

#include "autoconf.h"

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#include <linux/posix_types.h>
#endif

#ifdef HAVE_KCONFIG
#include <linux/kconfig.h>
#endif

#include <linux/fs.h>

int main()
{
    struct dentry *dentry = NULL;
    struct inode *inode = NULL;

    return vfs_unlink(inode, dentry);
}
