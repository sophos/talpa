#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#kernelheaderstest"
#endif

#include "autoconf.h"

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#include <linux/posix_types.h>
#endif

int main()
{
    return 0;
}
