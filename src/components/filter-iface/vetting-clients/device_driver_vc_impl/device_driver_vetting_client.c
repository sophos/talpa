/*
 * device_driver_vetting_client.c
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

#define __NO_VERSION__
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/poll.h>
#include <linux/major.h>
#include <linux/miscdevice.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
  #ifdef CONFIG_X86_64
    #include <asm/ioctl32.h>
    #define REGISTER_COMPAT_IOCTL
  #endif
#else
  #if defined CONFIG_X86_64 && !defined HAVE_COMPAT_IOCTL && defined CONFIG_COMPAT
    #include <linux/ioctl32.h>
    #define REGISTER_COMPAT_IOCTL
  #endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
    int sophos_misc_deregister(struct miscdevice *misc)
    {
        return misc_deregister(misc);
    }
#else
    int sophos_misc_deregister(struct miscdevice *misc)
    {
        misc_deregister(misc);
        return 0;
    }
#endif

#define TALPA_SUBSYS "vcdevice"
#include "common/talpa.h"
#include "platform/alloc.h"
#include "device_driver_vetting_client.h"

/*
 * Forward declare implementation methods.
 */
static int ddvcOpen(struct inode* inode, struct file* file);
static int ddvcClose(struct inode* inode, struct file* file);
static ssize_t ddvcRead(struct file* file, char* buf, size_t len, loff_t* ppos);
static ssize_t ddvcWrite(struct file* file, const char* buf, size_t len, loff_t* ppos);
#ifdef HAVE_UNLOCKED_IOCTL
static long ddvcIoctl(struct file* file, unsigned int cmd, unsigned long arg);
#else
static int ddvcIoctl(struct inode* inode, struct file* file, unsigned int cmd, unsigned long arg);
#endif
static unsigned int ddvcPoll(struct file* file, struct poll_table_struct* polltbl);

static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void deleteDeviceDriverVettingClient(struct tag_DeviceDriverVettingClient* object);

/*
 * Constants
 */

#define DDVC_NAME   "talpa-vc"
#define DDVC_MINOR  MISC_DYNAMIC_MINOR

#define CFG_DEVICE          "device"
#define CFG_VALUE_DEVICE    "000,000"

/*
 * Singleton object
 */
static DeviceDriverVettingClient GL_object =
    {
        {
            configName,
            allConfig,
            config,
            setConfig,
            &GL_object,
            (void (*)(void*))deleteDeviceDriverVettingClient
        },
        deleteDeviceDriverVettingClient,
        NULL,
        {
            {GL_object.mConfigData.name, GL_object.mConfigData.value, DDVETTINGCLIENT_CFGDATASIZE, false, true },
            {NULL, NULL, 0, false, false }
        },
        { CFG_DEVICE, CFG_VALUE_DEVICE }

    };
#define this    ((DeviceDriverVettingClient*)self)

/*
 * DeviceDriver interface
 */
static struct file_operations ddvc_fops =
{
    owner:          THIS_MODULE,
    open:           ddvcOpen,
    release:        ddvcClose,
    read:           ddvcRead,
    write:          ddvcWrite,
#ifdef HAVE_UNLOCKED_IOCTL
    unlocked_ioctl: ddvcIoctl,
#ifdef HAVE_COMPAT_IOCTL
    compat_ioctl:   ddvcIoctl,
#endif
#else
    ioctl:          ddvcIoctl,
#endif
    poll:           ddvcPoll
};

static struct miscdevice ddvc_dev=
{
    DDVC_MINOR,
    DDVC_NAME,
    &ddvc_fops
};

/*
 * Object creation/destruction.
 */
DeviceDriverVettingClient* newDeviceDriverVettingClient(IVettingServer* server)
{
    int ret;


    if ( !server )
    {
        err("Vetting server not specified!");
        return NULL;
    }

    ret = misc_register(&ddvc_dev);

    if ( ret )
    {
        err("Failed to register misc device!");
        return NULL;
    }

    sprintf(GL_object.mConfigData.value, "%d,%d", MISC_MAJOR, ddvc_dev.minor);

#ifdef REGISTER_COMPAT_IOCTL
    ret = register_ioctl32_conversion(TLPVCIOC_REGISTER, NULL);
    if ( ret )
    {
        ret = 0;
        goto fail1;
    }
    ret = register_ioctl32_conversion(TLPVCIOC_DEREGISTER, NULL);
    if ( ret )
    {
        ret = 0;
        goto fail2;
    }
    ret = register_ioctl32_conversion(TLPVCIOC_SETWAITTIMEOUT, NULL);
    if ( ret )
    {
        ret = 0;
        goto fail3;
    }
    ret = register_ioctl32_conversion(TLPVCIOC_GETBUFFERSIZE, NULL);
    if ( ret )
    {
        ret = 0;
        goto fail4;
    }
#endif

    GL_object.mServer = server;

    return &GL_object;

#ifdef REGISTER_COMPAT_IOCTL
fail4:
    ret |= unregister_ioctl32_conversion(TLPVCIOC_SETWAITTIMEOUT);
fail3:
    ret |= unregister_ioctl32_conversion(TLPVCIOC_DEREGISTER);
fail2:
    ret |= unregister_ioctl32_conversion(TLPVCIOC_REGISTER);
fail1:
    ret |= sophos_misc_deregister(&ddvc_dev);
    err("Failed to register compatibility ioctl handler!");
    if ( ret )
    {
        alert("Failed to clean up after failure!");
    }

    return NULL;
#endif
}

static void deleteDeviceDriverVettingClient(struct tag_DeviceDriverVettingClient* object)
{
    if ( object->mServer )
    {
        int ret;

#ifdef REGISTER_COMPAT_IOCTL
        ret = unregister_ioctl32_conversion(TLPVCIOC_REGISTER);
        ret |= unregister_ioctl32_conversion(TLPVCIOC_DEREGISTER);
        ret |= unregister_ioctl32_conversion(TLPVCIOC_SETWAITTIMEOUT);
        ret |= unregister_ioctl32_conversion(TLPVCIOC_GETBUFFERSIZE);

        if ( ret )
        {
            err("Failed to un-register compatibility ioctl handler!");
        }
#endif

        ret = sophos_misc_deregister(&ddvc_dev);
        if ( ret )
        {
            err("Failed to unregister misc device in destructor!");
        }

        object->mServer = NULL;
    }
    else
    {
        err("Trying to delete non-initialized object!");
    }

    return;
}

#define DDVC_CHECK_SERVER(srv) \
do \
{ \
    if ( unlikely( !(srv) ) ) \
    { \
        dbg("Not registered with a server!"); \
        return -ENODEV; \
    } \
} while (0)

#define DDVC_CHECK_CLIENT(client) \
do \
{ \
    if ( unlikely( !(client) ) ) \
    { \
        dbg("No client context!"); \
        return -ENXIO; \
    } \
    dbg("client 0x%p [%u]", client, (unsigned int)client->id); \
    if ( unlikely( ((client)->process) != current ) ) \
    { \
        dbg("[%d] File descriptor sharing is not supported!", (unsigned int)client->id); \
        return -EBADFD; \
    } \
} while (0)

#define DDVC_CHECK_CLIENT_CLOSE(client) \
do \
{ \
    if ( unlikely( !(client) ) ) \
    { \
        dbg("No client context!"); \
        return -ENXIO; \
    } \
    dbg("client 0x%p [%u]", client, (unsigned int)client->id); \
} while (0)

#define DDVC_CHECK_CLIENT_REGISTERED(client) \
do \
{ \
    if ( unlikely( !atomic_read(&client->registered) ) ) \
    { \
        dbg("Client trying to operate without registering!"); \
        return -EIO; \
    } \
} while (0)

#define packet_to_code(response) \
({ \
    int __ret = -EINVAL; \
    if ( likely(   (response->type == TALPA_PKT_OK) \
                || (response->type == TALPA_PKT_STREAMDATA) \
                || (response->type == TALPA_PKT_FILEDETAIL) \
                || (response->type == TALPA_PKT_FILESYSTEMDETAIL) \
                || (response->type == TALPA_PKT_EXTVETDETAILONLY) \
                || (response->type == TALPA_PKT_EXTFILEDETAIL) \
                || (response->type == TALPA_PKT_EXTFILESYSTEMDETAIL )  ) ) \
    { \
        __ret = 0; \
    } \
    else \
    { \
        __ret = ((struct TalpaPacket_FAIL *)response)->errorCode; \
    } \
    __ret; \
})

/*
 * IDeviceFile
 */

static int ddvcOpen(struct inode* inode, struct file* file)
{
    IVettingServer* server = GL_object.mServer;
    VettingClient* client;
    struct DDVC_State* state;
    unsigned int mindatasize;
    unsigned int maxdatasize;


    DDVC_CHECK_SERVER(server);

    file->private_data = server->initializeClient(server->object);

    if ( !file->private_data )
    {
        return -ENOMEM;
    }

    client = (VettingClient *)file->private_data;
    state = talpa_alloc(sizeof(struct DDVC_State));

    if ( !state )
    {
        err("Cannot allocate internal state!");
        server->destroyClient(server->object, client);
        return -ENOMEM;
    }

    memset(state, 0, sizeof(struct DDVC_State));

    mindatasize = server->queryMinStreamPacket(server->object);
    maxdatasize = server->queryMaxStreamPacket(server->object);

    while ( maxdatasize >= mindatasize )
    {
        state->packet = talpa_alloc(maxdatasize);
        if ( state->packet )
        {
            break;
        }
        maxdatasize >>= 1;
    }

    /* Account for the posibility that max packet size is very small to begin with */
    if ( !state->packet )
    {
        state->packet = talpa_alloc(maxdatasize);
    }

    state->mininsize = server->queryMinPacketSize(server->object);
    state->maxinsize = maxdatasize;

    if ( !state->packet )
    {
        err("Cannot allocate internal receive packet!");
        talpa_free(state);
        server->destroyClient(server->object, client);
        return -ENOMEM;
    }

    dbg("allocated %u bytes for incoming packets", state->maxinsize);

    atomic_set(&state->reading, 0);
    state->stream.buf = state->stream.ptr = NULL;
    state->stream.total = state->stream.remain = 0;

    client->flags = file->f_flags;
    client->private = state;

    return 0;
}

static int ddvcClose(struct inode* inode, struct file* file)
{
    IVettingServer* server = GL_object.mServer;
    VettingClient* client = (VettingClient *)file->private_data;
    struct DDVC_State* state;


    DDVC_CHECK_SERVER(server);
    DDVC_CHECK_CLIENT_CLOSE(client);

    file->private_data = NULL;
    state = (struct DDVC_State *)client->private;

    server->destroyClient(server->object, client);
    talpa_free(state->packet);
    talpa_free(state);

    return 0;
}

static ssize_t ddvcRead(struct file* file, char* buf, size_t len, loff_t* ppos)
{
    IVettingServer* server = GL_object.mServer;
    VettingClient* client = (VettingClient *)file->private_data;
    struct DDVC_State* state;
    int ret = -EINVAL;
    unsigned int to_read;


    DDVC_CHECK_SERVER(server);
    DDVC_CHECK_CLIENT(client);
    DDVC_CHECK_CLIENT_REGISTERED(client);

    state = (struct DDVC_State*)client->private;

    if ( unlikely(!atomic_read(&state->reading)) )
    {
        struct TalpaProtocolHeader* response;

        /* We need to start new read. */
        dbg("read for a new, or extended vetting details, or stream data");

        client->flags = file->f_flags;
        response = server->obtainVettingDetails(server->object, client);
        ret = packet_to_code(response);

        if ( likely(!ret) )
        {
            state->stream.buf = state->stream.ptr = (unsigned char *)client->vettingDetails->packet;
            state->stream.total = state->stream.remain = sizeof(struct TalpaProtocolHeader) + client->vettingDetails->packet->payloadLength;
            atomic_set(&state->reading, 1);
            dbg("details 0x%p<%u/%u> obtained. buf = 0x%p, len = %u", client->vettingDetails, client->vettingDetails->vettingID, client->currentVettingID, state->stream.buf, state->stream.total);
        }
        else if ( ret == -ERESTARTSYS )
        {
            dbg("signal received");
            return -ERESTARTSYS;
        }
        else
        {
            dbg("failed to obtain = %d", ret);
            return ret;
        }
    }

    /* Continuing with previously established read */
    to_read = MIN(state->stream.remain, len);
    dbg("will read %u in this pass (remain %u, requested %u)", to_read, state->stream.remain, (unsigned int) len);

    if ( likely(to_read > 0) )
    {
        ret = copy_to_user(buf, state->stream.ptr, to_read);
        if ( unlikely(ret != 0) )
        {
            dbg("copy_to_user fault!");
            return ret;
        }

        state->stream.ptr += to_read;
        state->stream.remain -= to_read;
    }

    if ( !state->stream.remain )
    {
        dbg("end of packet reached");
        atomic_set(&state->reading, 0);
        server->releaseVettingDetails(server->object, client);
    }

    ret = to_read;

    return ret;
}

static ssize_t ddvcWrite(struct file* file, const char* buf, size_t len, loff_t* ppos)
{
    IVettingServer* server = GL_object.mServer;
    VettingClient* client = (VettingClient *)file->private_data;
    struct DDVC_State* state;
    int ret = -EINVAL;

    DDVC_CHECK_SERVER(server);
    DDVC_CHECK_CLIENT(client);
    DDVC_CHECK_CLIENT_REGISTERED(client);

    state = (struct DDVC_State*)client->private;

    if ( unlikely(atomic_read(&state->reading) == 1) )
    {
        dbg("Client %u should not attempt to respond if reading is in progress!", (unsigned int)client->id);
        return -EINPROGRESS;
    }

    /* Not a particulary smart validation test but still... */
    if ( unlikely((len > state->maxinsize) || (len < state->mininsize)) )
    {
        dbg("Client %u is trying to respond with wrong sized packet!", (unsigned int)client->id);
        return -EIO;
    }

    ret = copy_from_user(state->packet, buf, len);
    if ( likely(!ret) )
    {
        struct TalpaProtocolHeader* response = NULL;

        response = server->processPacket(server->object, client, state->packet);

        if ( likely(response != NULL) )
        {
            ret = packet_to_code(response);
        }

        /* Return actual bytes written on success in order
           to emulate standard write(2) behaviour */
        if ( likely(!ret) )
        {
            ret = len;
        }
    }

    return ret;
}

#ifdef HAVE_UNLOCKED_IOCTL
static long ddvcIoctl(struct file* file, unsigned int cmd, unsigned long arg)
{
    long ret = -ENOTTY;
#else
static int ddvcIoctl(struct inode* inode, struct file* file, unsigned int cmd, unsigned long arg)
{
    int ret = -ENOTTY;
#endif
    IVettingServer* server = GL_object.mServer;
    VettingClient* client = (VettingClient *)file->private_data;
    struct DDVC_State* state;
    struct TalpaProtocolHeader* response = NULL;


    DDVC_CHECK_SERVER(server);
    DDVC_CHECK_CLIENT(client);

    state = (struct DDVC_State*)client->private;

    switch ( cmd )
    {
        case TLPVCIOC_REGISTER:
            ret = copy_from_user(state->packet, (void *)arg, sizeof(struct TalpaPacket_Register));
            if ( !ret )
            {
                response = server->registerClient(server->object, client, (struct TalpaPacket_Register *)state->packet);
            }
            break;
        case TLPVCIOC_DEREGISTER:
            ret = copy_from_user(state->packet, (void *)arg, sizeof(struct TalpaPacket_Deregister));
            if ( !ret )
            {
                response = server->deregisterClient(server->object, client, (struct TalpaPacket_Deregister *)state->packet);
            }
            break;
        case TLPVCIOC_SETWAITTIMEOUT:
            ret = copy_from_user(state->packet, (void *)arg, sizeof(struct TalpaPacket_SetWaitTimeout));
            if ( !ret )
            {
                response = server->setWaitTimeout(server->object, client, (struct TalpaPacket_SetWaitTimeout *)state->packet);
            }
            break;
        case TLPVCIOC_GETBUFFERSIZE:
            ret = state->maxinsize;
            break;
    }

    if ( response )
    {
        ret = packet_to_code(response);
    }

    return ret;
}

static unsigned int ddvcPoll(struct file* file, struct poll_table_struct* polltbl)
{
    IVettingServer* server = GL_object.mServer;
    VettingClient* client = (VettingClient *)file->private_data;

    DDVC_CHECK_SERVER(server);
    if ( !(client) )
    {
        dbg("No client context!");
        return -ENXIO;
    }
    DDVC_CHECK_CLIENT_REGISTERED(client);

    poll_wait(file, &client->group->clientWaitQueue, polltbl);

    if ( server->peekVettingQueue(server->object, client) )
    {
        return POLLIN | POLLRDNORM;
    }

    return 0;
}


/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "DeviceDriverVettingClient";
}

static const PODConfigurationElement* allConfig(const void* self)
{
    return this->mConfig;
}

static const char* config(const void* self, const char* name)
{
    PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement->name != NULL; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Return what was found else a null pointer.
     */
    if ( cfgElement->name )
    {
        return cfgElement->value;
    }
    return 0;
}

static void  setConfig(void* self, const char* name, const char* value)
{
    dbg("No writeable parameters!");
    return;
}

/*
 * End of device_driver_vetting_client.c
 */

