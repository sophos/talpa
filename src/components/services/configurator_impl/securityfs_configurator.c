/*
 * securityfs_configurator.h
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
#include <asm/errno.h>
#include <asm/uaccess.h>

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/security.h>

#include "common/bool.h"
#define TALPA_SUBSYS "securityfs"
#include "common/talpa.h"
#include "common/list.h"
#include "platform/alloc.h"
#include "configurator/pod_configuration_element.h"

#include "securityfs_configurator.h"

/*
 * Forward declare implementation methods.
 */
static int attach(void* self, EConfigurationGroup group, const IConfigurable* item);
static void detach(void* self, const IConfigurable* item);
static void deleteSecurityfsConfigurator(struct tag_SecurityfsConfigurator* object);

/*
 * Singleton object.
 */
static SecurityfsConfigurator GL_object =
    {
        {
            attach,
            detach,
            &GL_object,
            (void (*)(void*))deleteSecurityfsConfigurator
        },
        deleteSecurityfsConfigurator,
        TALPA_STATIC_MUTEX(GL_object.mSemaphore),
        NULL,
        TALPA_LIST_HEAD_INIT(GL_object.mGroups),
    };


#define this    ((SecurityfsConfigurator*)self)

/*
 * Object creation/destruction.
 */
SecurityfsConfigurator* newSecurityfsConfigurator(void)
{
    GL_object.mRoot = securityfs_create_dir("talpa", NULL);
    if ( IS_ERR(GL_object.mRoot) )
    {
        dbg("securityfs_create_dir failed: %ld", PTR_ERR(GL_object.mRoot));
        return NULL;
    }

    return &GL_object;
}

static void deleteSecurityfsConfigurator(struct tag_SecurityfsConfigurator* object)
{
    if ( object->mRoot )
    {
        securityfs_remove(object->mRoot);
    }

    return;
}

/*
 * Internal.
 */

static struct configurationGroup *getGroup(void* self, EConfigurationGroup id)
{
    struct configurationGroup  *group = NULL;
    struct configurationGroup  *gptr;
    char *name;


    talpa_mutex_lock(&this->mSemaphore);

    talpa_list_for_each_entry(gptr, &this->mGroups, head)
    {
        if ( gptr->id == id )
        {
            group = gptr;
            break;
        }
    }

    if ( group )
    {
        group->usecnt++;
        dbg("returning %d (%u) [0x%p]", group->id, group->usecnt, group->dentry);
        goto out;
    }

    switch (id)
    {
        case ECG_Interceptor:
            name = "interceptors";
            break;
        case ECG_InterceptProcessor:
            name = "intercept-processors";
            break;
        case ECG_InterceptFilter:
            name = "intercept-filters";
            break;
        case ECG_FilterInterfaces:
            name = "filter-interfaces";
            break;
        default:
            /* Fail on unknown group id */
            goto out;
    }

    group = talpa_alloc(sizeof(struct configurationGroup));
    if ( !group )
    {
        goto out;
    }

    group->usecnt = 1;
    group->id = id;
    group->dentry = securityfs_create_dir(name, this->mRoot);
    if ( IS_ERR(group->dentry) )
    {
        dbg("creation failed %ld", PTR_ERR(group->dentry));
        talpa_free(group);
        group = NULL;
        goto out;
    }
    TALPA_INIT_LIST_HEAD(&group->items);
    talpa_list_add(&group->head, &this->mGroups);
    dbg("added %d (%u) [0x%p]", group->id, group->usecnt, group->dentry);
out:
    talpa_mutex_unlock(&this->mSemaphore);
    return group;
}

static void putGroup(void* self, struct configurationGroup *group)
{
    talpa_mutex_lock(&this->mSemaphore);
    group->usecnt--;
    if ( group->usecnt == 0 )
    {
        talpa_list_del(&group->head);
        dbg("freeing %d (%u) [0x%p]", group->id, group->usecnt, group->dentry);
        securityfs_remove(group->dentry);
        talpa_free(group);
    }
    talpa_mutex_unlock(&this->mSemaphore);
}

/*
 * Filesystem implementation.
 */

static int securityfsOpen(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19) || defined TALPA_INODE_I_PRIVATE
    if ( inode->i_private )
    {
        file->private_data = inode->i_private;
    }
#else
    if ( inode->u.generic_ip )
    {
        file->private_data = inode->u.generic_ip;
    }
#endif

    return 0;
}

static ssize_t securityfsRead(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    struct configurationElement *element;
    IConfigurable *item;
    char* data;
    size_t len;
    size_t amountToCopy;
    size_t extraNewLine = 1;


    if ( !count )
    {
        return 0;
    }

    if ( !file )
    {
        dbg("Attempting to read from null file");
        return -EBADF;
    }

    element = (struct configurationElement *)file->private_data;
    if ( !element )
    {
        return -EBADF;
    }

    item = element->owner;
    if ( !item )
    {
        return -EBADF;
    }

    data = (char *)(item->get(item->object, element->name));
    if (data == NULL)
    {
        return -ENOMEM;
    }

    /* Too noisy since we are reading for queue length */
    //~ if ( strncmp(item->name(item->object), "VettingController", 17) != 0 )
    //~ {
        //~ dbg("reading %s/%s = %s", item->name(item->object), element->name, data);
    //~ }

    len = strlen(data) + extraNewLine; /* For the new line */
    amountToCopy = len - file->f_pos;

    if (amountToCopy <= 0)
    {
        return 0;
    }

    if ( amountToCopy > count )
    {
        /* User buffer is smaller than we have left, so copy from the data, and don't include
         * the virtual new-line */
        extraNewLine = 0;
        amountToCopy = count;
    }
    if ( amountToCopy - extraNewLine > 0 )
    {
        /*
         * Need to copy from the config data:
         * Copy from data, accounting for the virtual new line.
         */
        if ( copy_to_user(buf, data+file->f_pos, amountToCopy - extraNewLine) )
        {
            return -EFAULT;
        }
    }
    if ( extraNewLine > 0 )
    {
        if ( put_user('\n', buf + amountToCopy - extraNewLine) )
        {
            return -EFAULT;
        }
    }
    *ppos = file->f_pos + amountToCopy;

    return amountToCopy;
}

static ssize_t securityfsWrite(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    struct configurationElement *element;
    IConfigurable *item;
    char *data;
    size_t len;
    const char *p;
    char c;


    if ( !count )
    {
        return 0;
    }

    if ( file->f_pos )
    {
        return -EINVAL;
    }

    element = (struct configurationElement *)file->private_data;
    if ( !element )
    {
        return -EBADF;
    }

    item = element->owner;
    if ( !item )
    {
        return -EBADF;
    }

    if ( strnlen_user(buf, count) < 0 )
    {
        return -EFAULT;
    }
    len = 0;
    p = buf;
    while ( len < count )
    {
        __get_user(c, p++);
        if ( c == 0 || c == '\n' )
        {
            break;
        }
        len++;
    }
    if ( len > element->size )
    {
        len = element->size;
    }
    data = talpa_large_alloc(len + 1);
    if ( !data )
    {
        return -ENOMEM;
    }
    if ( copy_from_user(data, buf, len) )
    {
        return -EFAULT;
    }
    *ppos = len;
    if ( len == element->size )
    {
        len--;
    }
    data[len] = 0;
    dbg("setting %s/%s = %s", item->name(item->object), element->name, data);
    item->set(item->object, element->name, data);
    talpa_large_free(data);

    return count;
}

static struct file_operations securityfsOps = {
    .owner =    THIS_MODULE,
    .open =     securityfsOpen,
    .read =     securityfsRead,
    .write =    securityfsWrite,
};

/*
 * IConfigurator.
 */
static int attach(void* self, EConfigurationGroup id, const IConfigurable* item)
{
    int err = -ENOMEM;
    const PODConfigurationElement* cfgElement;
    int count;
    struct configurationGroup *group = NULL;
    struct configurationItem *cfgitem = NULL;
    struct configurationElement *element;
    mode_t mode;


    /* Determine how big the directory contents is */
    cfgElement = item->all(item->object);
    if ( !cfgElement )
    {
        err = -ENODATA;
        goto error;
    }
    for ( count = 0;  cfgElement->name != NULL; count++, cfgElement++ )
    {
        /* No action */
    }
    if ( count == 0 )
    {
        err = -ENODATA;
        goto error;
    }

    /* Get the parent group */
    group = getGroup(self, id);
    if ( !group )
    {
        goto error;
    }

    /* Allocate and initialise item */
    cfgitem = talpa_zalloc(sizeof(struct configurationItem));
    if ( !cfgitem )
    {
        dbg("item allocation failed");
        goto error;
    }

    cfgitem->dentry = securityfs_create_dir(item->name(item->object), group->dentry);
    if ( IS_ERR(cfgitem->dentry) )
    {
        err = PTR_ERR(cfgitem->dentry);
        dbg("creation of %s failed %d", item->name(item->object), err);
        goto error;
    }
    cfgitem->item = (IConfigurable *)item;
    cfgitem->count = count;

    /* Allocate and initialise elements */
    cfgitem->elements = talpa_zalloc(sizeof(struct configurationElement)*count);
    if ( !cfgitem->elements )
    {
        dbg("elements allocation failed");
        goto error;
    }

    for ( cfgElement = item->all(item->object), element = cfgitem->elements;
            cfgElement->name != NULL;
            cfgElement++, element++ )
    {
        element->owner = (IConfigurable *)item;
        element->name = cfgElement->name;
        element->size = cfgElement->maxvalue_sz;
        mode = S_IRUSR;
        if ( cfgElement->writable )
        {
            mode |= S_IWUSR;
        }
        if ( cfgElement->world_readable )
        {
            mode |= S_IRGRP | S_IROTH;
        }
        element->dentry = securityfs_create_file(element->name, mode, cfgitem->dentry, element, &securityfsOps);
        if ( IS_ERR(element->dentry) )
        {
            dbg("creation of %s failed %ld", cfgElement->name, PTR_ERR(element->dentry));
            goto error;
        }
    }

    /* Add item to the group */
    talpa_mutex_lock(&this->mSemaphore);
    talpa_list_add(&cfgitem->head, &group->items);
    talpa_mutex_unlock(&this->mSemaphore);

    return 0;

error:
    if ( cfgitem )
    {
        if ( cfgitem->elements )
        {
            for ( cfgElement = item->all(item->object), element = cfgitem->elements;
                    cfgElement->name != NULL;
                    cfgElement++, element++ )
            {
                if ( element->dentry && !IS_ERR(element->dentry) )
                {
                    dbg("removing %s", element->name);
                    securityfs_remove(element->dentry);
                }
            }

            talpa_free(cfgitem->elements);
        }

        if ( cfgitem->dentry && !IS_ERR(cfgitem->dentry) )
        {
            dbg("removing %s", item->name(item->object));
            securityfs_remove(cfgitem->dentry);
        }

        talpa_free(cfgitem);
    }

    if ( group )
    {
        putGroup(self, group);
    }

    return err;
}

static void detach(void* self, const IConfigurable* item)
{
    struct configurationGroup *gptr, *group = NULL;
    struct configurationItem *iptr, *cfgitem = NULL;
    struct configurationElement *element;
    unsigned int idx;


    talpa_mutex_lock(&this->mSemaphore);
    talpa_list_for_each_entry(gptr, &this->mGroups, head)
    {
        talpa_list_for_each_entry(iptr, &gptr->items, head)
        {
            if ( iptr->item == item )
            {
                group = gptr;
                cfgitem = iptr;
                break;
            }
        }
    }

    if ( !group || !cfgitem )
    {
        err("Incorrect configuration usage!");
        talpa_mutex_unlock(&this->mSemaphore);
        return;
    }

    for ( element = cfgitem->elements, idx = 0; idx < cfgitem->count; idx++, element++ )
    {
        dbg("removing %s", element->name);
        securityfs_remove(element->dentry);
    }

    talpa_free(cfgitem->elements);
    securityfs_remove(cfgitem->dentry);
    talpa_list_del(&cfgitem->head);
    talpa_free(cfgitem);
    talpa_mutex_unlock(&this->mSemaphore);

    putGroup(self, group);

    return;
}

/*
 * End of securityfs_configurator.c
 */
