#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dpathtest"
#endif

#include "autoconf.h"
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#include <linux/posix_types.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <linux/kconfig.h>
#endif

#include <linux/fs.h>

int main()
{
    struct path *pathst = NULL;
    char *buffer = NULL;
    unsigned int buflen = 0;
    char *path = __d_path(pathst, pathst, buffer, buflen);

    return 0;
}
