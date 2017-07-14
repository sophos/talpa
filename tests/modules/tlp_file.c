/*
 * tlp-fileinfo.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2017 Sophos Limited, Oxford, England.
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/errno.h>

#include "tlp-test.h"

#include "platform/uaccess.h"

#include "common/bool.h"
#define TALPA_SUBSYS "filetest"
#include "common/talpa.h"

#include "components/services/linux_filesystem_impl/linux_file.h"

static LinuxFile*   testfile;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
long talpa_ioctl(struct file *file, unsigned int cmd, unsigned long parm)
#else
int talpa_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long parm)
#endif
{
    int ret = -ENOTTY;

    struct talpa_open open;
    struct talpa_seek seek;
    struct talpa_read read;
    struct talpa_write write;
    void *buf;

    switch ( cmd )
    {
        case TALPA_TEST_FILE_OPEN:
            ret = copy_from_user(&open, (void *)parm, sizeof(struct talpa_open));
            if ( !ret )
            {
                ret = testfile->i_IFile.open(testfile, open.filename, open.flags, true);
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_FILE_CLOSE:
            ret = testfile->i_IFile.close(testfile);
            break;
        case TALPA_TEST_FILE_ISOPEN:
            ret = testfile->i_IFile.isOpen(testfile);
            break;
        case TALPA_TEST_FILE_LENGTH:
            ret = testfile->i_IFile.length(testfile);
            break;
        case TALPA_TEST_FILE_SEEK:
            ret = copy_from_user(&seek, (void *)parm, sizeof(struct talpa_seek));
            if ( !ret )
            {
                ret = testfile->i_IFile.seek(testfile, seek.offset, seek.mode);
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_FILE_READ:
            ret = copy_from_user(&read, (void *)parm, sizeof(struct talpa_read));
            if ( !ret )
            {
                buf = kmalloc(read.size, GFP_KERNEL);
                if ( buf )
                {
                    ret = testfile->i_IFile.read(testfile, buf, read.size);
                    if ( ret >= 0 )
                    {
                        ret = copy_to_user(read.data, buf, ret);
                    }
                    kfree(buf);
                }
                else
                {
                    ret = -ENOMEM;
                }
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_FILE_WRITE:
            ret = copy_from_user(&write, (void *)parm, sizeof(struct talpa_write));
            if ( !ret )
            {
                buf = kmalloc(write.size, GFP_KERNEL);
                if ( buf )
                {
                    ret = copy_from_user(buf, write.data, write.size);
                    if ( !ret )
                    {
                        ret = testfile->i_IFile.write(testfile, buf, write.size);
                    }
                    kfree(buf);
                }
                else
                {
                    ret = -ENOMEM;
                }
            }
            else
            {
                err("copy_from_user!");
            }
            break;
        case TALPA_TEST_FILE_TRUNCATE:
            ret = testfile->i_IFile.truncate(testfile, (loff_t)parm);
            break;
        case TALPA_TEST_FILE_UNLINK:
            ret = testfile->i_IFile.unlink(testfile);
            break;
    }

    return ret;
}

struct file_operations talpa_fops =
{
    owner:  THIS_MODULE,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
    unlocked_ioctl:  talpa_ioctl
#else
    ioctl:  talpa_ioctl
#endif
};

static int __init talpa_test_init(void)
{
    int ret;

    testfile = newLinuxFile();

    if ( !testfile )
    {
        err("Failed to create file object!");
        return -ENOMEM;
    }

    ret = register_chrdev(TALPA_MAJOR, TALPA_DEVICE, &talpa_fops);

    if ( ret )
    {
        testfile->delete(testfile);
        err("Failed to register TALPA Test character device!");
        return ret;
    }

    return 0;
}

static void __exit talpa_test_exit(void)
{
    int ret;

    testfile->delete(testfile);

    ret = talpa_unregister_chrdev(TALPA_MAJOR, TALPA_DEVICE);

    if ( ret )
    {
        err("Hmmmmmm... very strange things are happening!");
    }
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Limited");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Test Module");
MODULE_LICENSE("GPL");

module_init(talpa_test_init);
module_exit(talpa_test_exit);

