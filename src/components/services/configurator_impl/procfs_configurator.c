/*
 * procfs_configurator.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004 Sophos Plc, Oxford, England.
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
#include <linux/sysctl.h>
#include <linux/fs.h>

#include "common/bool.h"
#define TALPA_SUBSYS "procfs"
#include "common/talpa.h"
#include "common/list.h"
#include "configurator/pod_configuration_element.h"

#include "procfs_configurator.h"

/*
 * Forward declare implementation methods.
 */
static int attach(void* self, EConfigurationGroup group, const IConfigurable* item);
static void detach(void* self, const IConfigurable* item);
static void deleteProcfsConfigurator(struct tag_ProcfsConfigurator* object);
static int ctlHandler(ctl_table* table, int* name, int nlen, void* oldvalue, size_t* oldlenptr, void* newvalue, size_t newlen, void** context);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
static int procHandler(ctl_table* table, int write, struct file* filp, void* buffer, size_t* lenp);
#else
static int procHandler(ctl_table* table, int write, struct file* filp, void* buffer, size_t* lenp, loff_t* ppos);
#endif

/*
 * SystCtl Table.
 */
#define CTL_TALPA       7700

/*
 * Singleton object.
 */
static ProcfsConfigurator GL_object =
    {
        {
            attach,
            detach,
            &GL_object,
            (void (*)(void*))deleteProcfsConfigurator
        },
        deleteProcfsConfigurator,
        false,
        TALPA_STATIC_MUTEX(GL_object.mSemaphore),
        LIST_HEAD_INIT(GL_object.mConfig),
        1
    };


#define this    ((ProcfsConfigurator*)self)

/*
 * Object creation/destruction.
 */
ProcfsConfigurator* newProcfsConfigurator(void)
{
    talpa_mutex_lock(&GL_object.mSemaphore);

    if ( GL_object.mInitialized )
    {
        talpa_mutex_unlock(&GL_object.mSemaphore);
        err("Duplicate initialization attempted!");
        return NULL;
    }

    GL_object.mInitialized = true;
    talpa_mutex_unlock(&GL_object.mSemaphore);

    return &GL_object;
}

static void deleteProcfsConfigurator(struct tag_ProcfsConfigurator* object)
{
    ConfiguredItem* item;
    struct list_head*   posptr;
    struct list_head*   nptr;


    talpa_mutex_lock(&object->mSemaphore);

    if ( !object->mInitialized )
    {
        talpa_mutex_unlock(&object->mSemaphore);
        err("Tried to delete before initializing!");
        return;
    }

    talpa_list_for_each_safe(posptr, nptr, &object->mConfig)
    {
        item = list_entry(posptr, ConfiguredItem, list);
        list_del(posptr);
        unregister_sysctl_table(item->exposedConfig);
        kfree(item->config);
        kfree(item);
    }

    talpa_mutex_unlock(&object->mSemaphore);

    return;
}


/*
 * IConfigurator.
 */
static int attach(void* self, EConfigurationGroup group, const IConfigurable* item)
{
    const PODConfigurationElement*  cfgElement;
    ConfiguredItem*                 configItem;
    ctl_table*                      element;
    ctl_table*                      elementSubItem;
    int                             count;
    int                             retCode;
    int                             mode;


    /*
     * Determine how big the directory contents is - we must have some contents to be able to configure it!!
     */
    cfgElement = item->all(item->object);
    if ( !cfgElement )
    {
        dbg("no elements pointer");
        return -ENODATA;
    }
    for (count = 0;  cfgElement->name != NULL; count++, cfgElement++)
    {
        //
        // No Action.
        //
    }
    if (count == 0)
    {
        dbg("no elements");
        return -ENODATA;
    }
    element = kmalloc(sizeof(ctl_table) * (6 + count + 1), GFP_KERNEL);
    if ( !element )
    {
        return -ENOMEM;
    }

    memset(element, 0, sizeof(ctl_table) * (6 + count + 1));
    element[0].ctl_name = CTL_TALPA;
    element[0].procname = "talpa";
    element[0].mode     = 0555;
    element[0].child    = &element[2];
    /* Element 1 is terminator */

    element[2].ctl_name = group;
    switch (group)
    {
        case ECG_Interceptor:
            element[2].procname = "interceptors";
            break;
        case ECG_InterceptProcessor:
            element[2].procname = "intercept-processors";
            break;
        case ECG_InterceptFilter:
            element[2].procname = "intercept-filters";
            break;
        case ECG_FilterInterfaces:
            element[2].procname = "filter-interfaces";
            break;
        default:
            /*
             * Must be a bug with the client if we get here!!!
             */
            retCode = -EINVAL;
            goto free_element;
    }
    element[2].mode     = 0555;
    element[2].child    = &element[4];
    /* Element 3 is the terminator */
    element[4].procname = item->name(item->object);
    element[4].mode     = 0555;
    element[4].child    = &element[6];
    element[4].extra1   = (void*)item;
    /* Element 5 is the terminator */

    /*
    * Assign the directory contents.
    */
    elementSubItem = &element[6];
    for (cfgElement = item->all(item->object), count = 1;
        cfgElement->name != NULL;
        elementSubItem++, cfgElement++, count++)
    {
        elementSubItem->ctl_name     = count;
        elementSubItem->procname     = cfgElement->name;
        elementSubItem->data         = cfgElement->value;
        elementSubItem->maxlen       = cfgElement->maxvalue_sz;
        mode = 0400;
        if ( cfgElement->writable )
        {
            mode |= 0200;
        }
        if ( cfgElement->world_readable )
        {
            mode |= 0044;
        }
        elementSubItem->mode         = mode;
        elementSubItem->proc_handler = procHandler;
        elementSubItem->strategy     = ctlHandler;
        elementSubItem->extra1       = (void*)item;
    }

    configItem = kmalloc(sizeof(ConfiguredItem), GFP_KERNEL);
    if ( !configItem )
    {
        retCode = -ENOMEM;
        goto free_element;
    }

    talpa_mutex_lock(&this->mSemaphore);

    element[4].ctl_name         = this->mElementId++;
    configItem->item            = (void*)item;
    configItem->config          = element;
    configItem->exposedConfig   = register_sysctl_table(configItem->config, 0);
    if ( !configItem->exposedConfig )
    {
        talpa_mutex_unlock(&this->mSemaphore);
        retCode = -EADV;
        goto free_configitem;
    }
    list_add_tail(&configItem->list, &(this->mConfig));
    talpa_mutex_unlock(&this->mSemaphore);

    return 0;

free_configitem:
    kfree(configItem);
free_element:
    kfree(element);
    return retCode;
}

static void detach(void* self, const IConfigurable* item)
{
    ConfiguredItem*   posptr;


    talpa_mutex_lock(&this->mSemaphore);
    talpa_list_for_each_entry(posptr, &this->mConfig, list)
    {
        if (posptr->item == item)
        {
            unregister_sysctl_table(posptr->exposedConfig);
            list_del(&posptr->list);
            kfree(posptr->config);
            kfree(posptr);
            break;
        }
    }
    talpa_mutex_unlock(&this->mSemaphore);
    return;
}

/*
 * Internal.
 */
static int ctlHandler(ctl_table* table, int* name, int nlen, void* oldvalue, size_t* oldlenptr, void* newvalue, size_t newlen, void** context)
{
    if (!table->data || !table->maxlen)
    {
        return -ENOTDIR;
    }

    if (oldvalue && oldlenptr)
    {
        size_t len;
        char* data;

        if ( get_user(len, oldlenptr) )
        {
            return -EFAULT;
        }

        data = (char *)((IConfigurable*)table->extra1)->get(((IConfigurable*)table->extra1)->object, table->procname);

        if ( len )
        {
            size_t l = strlen(data);
            if ( len > l )
            {
                len = l;
            }
            if ( copy_to_user(oldvalue, data, len) )
            {
                return -EFAULT;
            }
            if ( put_user(0, ((char *) oldvalue) + len) )
            {
                return -EFAULT;
            }
            if ( put_user(len, oldlenptr) )
            {
                return -EFAULT;
            }
        }
    }
    if (newvalue && newlen)
    {
        /*
         * For write we need to call our own set() methods on the object being configured.
         * We must protect it from the fact that the set is being invoked from userland.
         */
        size_t  len;
        char* cfgValue;


        len = newlen;
        if (len > table->maxlen)
        {
            len = table->maxlen;
        }
        cfgValue = kmalloc(len + 1, GFP_KERNEL);
        if ( !cfgValue )
        {
            return -ENOMEM;
        }
        if (copy_from_user(cfgValue, newvalue, len))
        {
            return -EFAULT;
        }
        if (len == table->maxlen)
        {
            len--;
        }
        cfgValue[len] = 0;
        ((IConfigurable*)table->extra1)->set(((IConfigurable*)table->extra1)->object, table->procname, cfgValue);
        kfree(cfgValue);
    }
    return 1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#define PPOS filp->f_pos
static int procHandler(ctl_table* table, int write, struct file* filp, void* buffer, size_t* lenp)
#else
#define PPOS *ppos
static int procHandler(ctl_table* table, int write, struct file* filp, void* buffer, size_t* lenp, loff_t* ppos)
#endif
{
    if (!table->data || !table->maxlen || !*lenp || (filp->f_pos && !write))
    {
        *lenp = 0;
        return 0;
    }
    if (write)
    {
        size_t  len;
        char*   p;
        char    c;
        char*   cfgValue;

        if ( strnlen_user(buffer, *lenp) < 0 )
        {
            return -EFAULT;
        }
        len = 0;
        p = buffer;
        while (len < *lenp)
        {
            __get_user(c, p++);
            if (c == 0 || c == '\n')
            {
                break;
            }
            len++;
        }
        if (len > table->maxlen)
        {
            len = table->maxlen;
        }
        cfgValue = kmalloc(len + 1, GFP_KERNEL);
        if ( !cfgValue )
        {
            return -ENOMEM;
        }
        if (copy_from_user(cfgValue, buffer, len))
        {
            return -EFAULT;
        }
        if (len == table->maxlen)
        {
            len--;
        }
        cfgValue[len] = 0;

        PPOS += *lenp;
        ((IConfigurable*)table->extra1)->set(((IConfigurable*)table->extra1)->object, table->procname, cfgValue);
        kfree(cfgValue);

        return 0;
    }
    else
    {
        char* data = (char *)((IConfigurable*)table->extra1)->get(((IConfigurable*)table->extra1)->object, table->procname);
        size_t len = strlen(data);
        if ( len > *lenp )
        {
            len = *lenp;
        }
        if ( len )
        {
            if ( copy_to_user(buffer, data, len) )
            {
                return -EFAULT;
            }
        }
        if ( len < *lenp )
        {
            if( put_user('\n', ((char *) buffer) + len) )
            {
                return -EFAULT;
            }
            len++;
        }
        *lenp = len;
        PPOS += len;
    }

    return 0;
}


/*
 * End of procfs_configurator.c
 */



