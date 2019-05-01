/*
 * procfs_configurator.h
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
#include <asm/errno.h>

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
#include "platforms/linux/alloc.h"
#include "platforms/linux/uaccess.h"

#include "procfs_configurator.h"

/*
 * Forward declare implementation methods.
 */
static int attach(void* self, EConfigurationGroup group, const IConfigurable* item);
static void detach(void* self, const IConfigurable* item);
static void deleteProcfsConfigurator(struct tag_ProcfsConfigurator* object);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
static int ctlHandler(ctl_table* table, void* oldvalue, size_t* oldlenptr, void* newvalue, size_t newlen);
  #elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static int ctlHandler(ctl_table* table, int* name, int nlen, void* oldvalue, size_t* oldlenptr, void* newvalue, size_t newlen);
  #else
static int ctlHandler(ctl_table* table, int* name, int nlen, void* oldvalue, size_t* oldlenptr, void* newvalue, size_t newlen, void** context);
  #endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
static int procHandler(ctl_table* table, int write, void __user * buffer, size_t* lenp, loff_t* ppos);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
static int procHandler(ctl_table* table, int write, struct file* filp, void __user * buffer, size_t* lenp, loff_t* ppos);
#else
static int procHandler(ctl_table* table, int write, struct file* filp, void __user * buffer, size_t* lenp);
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
        talpa_free(item->config);
        talpa_free(item);
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
    element = talpa_alloc(sizeof(ctl_table) * (6 + count + 1));
    if ( !element )
    {
        return -ENOMEM;
    }

    memset(element, 0, sizeof(ctl_table) * (6 + count + 1));
#ifdef TALPA_BINARY_SYSCTL
    element[0].ctl_name = CTL_TALPA;
#endif
    element[0].procname = "talpa";
    element[0].mode     = 0555;
    element[0].child    = &element[2];
    /* Element 1 is terminator */

#ifdef TALPA_BINARY_SYSCTL
    element[2].ctl_name = group;
#endif
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
    /* Element 5 is the terminator */

    /*
    * Assign the directory contents.
    */
    elementSubItem = &element[6];
    for (cfgElement = item->all(item->object), count = 1;
        cfgElement->name != NULL;
        elementSubItem++, cfgElement++, count++)
    {
#ifdef TALPA_BINARY_SYSCTL
        elementSubItem->ctl_name     = count;
#endif
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
        elementSubItem->strategy     = ctlHandler;
#endif
        elementSubItem->extra1       = (void*)item;
    }

    configItem = talpa_alloc(sizeof(ConfiguredItem));
    if ( !configItem )
    {
        retCode = -ENOMEM;
        goto free_element;
    }

    talpa_mutex_lock(&this->mSemaphore);

#ifdef TALPA_BINARY_SYSCTL
    element[4].ctl_name         = this->mElementId++;
#endif
    configItem->item            = (void*)item;
    configItem->config          = element;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
    configItem->exposedConfig   = register_sysctl_table(configItem->config);
#else
    configItem->exposedConfig   = register_sysctl_table(configItem->config, 0);
#endif
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
    talpa_free(configItem);
free_element:
    talpa_free(element);
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
            talpa_free(posptr->config);
            talpa_free(posptr);
            break;
        }
    }
    talpa_mutex_unlock(&this->mSemaphore);
    return;
}

/*
 * Internal.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
static int ctlHandler(ctl_table* table, void* oldvalue, size_t* oldlenptr, void* newvalue, size_t newlen)
  #elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static int ctlHandler(ctl_table* table, int* name, int nlen, void* oldvalue, size_t* oldlenptr, void* newvalue, size_t newlen)
  #else
static int ctlHandler(ctl_table* table, int* name, int nlen, void* oldvalue, size_t* oldlenptr, void* newvalue, size_t newlen, void** context)
  #endif
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
        if (data == NULL)
        {
            return -ENOMEM;
        }

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
        cfgValue = talpa_large_alloc(len + 1);
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
        talpa_large_free(cfgValue);
    }
    return 1;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define PPOS *ppos
static int procHandler(ctl_table* table, int write, void __user * buffer, size_t* lenp, loff_t* ppos)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
#define PPOS *ppos
static int procHandler(ctl_table* table, int write, struct file* filp, void __user * buffer, size_t* lenp, loff_t* ppos)
#else
#define PPOS filp->f_pos
static int procHandler(ctl_table* table, int write, struct file* filp, void __user * buffer, size_t* lenp)
#endif
{
    if (!table->data || !table->maxlen || !*lenp)
    {
        *lenp = 0;
        return 0;
    }
    if (write)
    {
        size_t  len;
        char __user *   p;
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
        cfgValue = talpa_large_alloc(len + 1);
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
        talpa_large_free(cfgValue);

        return 0;
    }
    else
    {
        char* data = (char *)((IConfigurable*)table->extra1)->get(((IConfigurable*)table->extra1)->object, table->procname);
        size_t len;
        size_t amountToCopy;
        size_t extraNewLine = 1;

        if (data == NULL)
        {
            return -ENOMEM;
        }

        len = strlen(data) + 1;         /* Size of the actual data + 1 for new-line */
        amountToCopy = len-PPOS;   /* Remaining data from the current position including virtual new-line */

        if (amountToCopy <= 0)
        {
            *lenp = 0;
            return 0;
        }

        if ( amountToCopy > *lenp )
        {
            extraNewLine = 0;
            amountToCopy = *lenp; /* Reduce amount to copy by buffer length */
        }
        if ( amountToCopy - extraNewLine > 0 )
        {
            if ( copy_to_user(buffer, data+PPOS, amountToCopy - extraNewLine) ) /* copy without virtual new-line */
            {
                return -EFAULT;
            }
        }
        if ( extraNewLine > 0 )
        {
            if( put_user('\n', ((char __user *) buffer) + amountToCopy - extraNewLine) )
            {
                return -EFAULT;
            }
        }
        *lenp = amountToCopy;
        PPOS += amountToCopy;
    }

    return 0;
}


/*
 * End of procfs_configurator.c
 */



