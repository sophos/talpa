#include "autoconf.h"

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <linux/kconfig.h>
#endif

#include <linux/uaccess.h>

int main()
{
    int val = 0;
    probe_kernel_write((void*)0,(void*)&val,sizeof(void*));
    return 0;
}
