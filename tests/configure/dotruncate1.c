#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dotruncatetest"
#endif

#include "autoconf.h"
#include <linux/fs.h>

/* do_truncate(struct dentry*, loff_t) */

int main()
{
    struct dentry *dentry = NULL;
    loff_t start = 0;

    return do_truncate(dentry, start);
}
