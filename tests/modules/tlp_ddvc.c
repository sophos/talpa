/*
 * tlp-ddvc.c
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/errno.h>

#include "tlp-test.h"

#include "platform/uaccess.h"

#include "common/bool.h"
#define TALPA_SUBSYS "ddvctest"
#include "common/talpa.h"

#include "components/filter-iface/vetting-clients/device_driver_vc_impl/device_driver_vetting_client.h"

static DeviceDriverVettingClient*   mClient = NULL;


typedef struct tag_TestServer
{
    IVettingServer            i_IVettingServer;
    void                      (*delete)(struct tag_TestServer* object);
    VettingClient             mClient;
    VettingDetails            mDetails;
    struct TalpaPacket_FAIL   mPacket;
} TestServer;

static unsigned int queryMinPacketSize(const void* self);
static unsigned int queryMaxPacketSize(const void* self);
static unsigned int queryMinStreamPacket(const void* self);
static unsigned int queryMaxStreamPacket(const void* self);
static VettingClient* initializeClient(void* self);
static void destroyClient(void* self, VettingClient* client);
static struct TalpaProtocolHeader* registerClient(void* self, VettingClient* client, struct TalpaPacket_Register* packet);
static struct TalpaProtocolHeader* deregisterClient(void* self, VettingClient* client, struct TalpaPacket_Deregister* packet);
static struct TalpaProtocolHeader* processPacket(void* self, VettingClient* client, struct TalpaProtocolHeader* packet);
static struct TalpaProtocolHeader* setWaitTimeout(const void* self, VettingClient* client, struct TalpaPacket_SetWaitTimeout* packet);
static bool peekVettingQueue(const void* self, VettingClient* client);
static struct TalpaProtocolHeader* obtainVettingDetails(void* self, VettingClient* client);
static void releaseVettingDetails(const void* self, VettingClient* client);
static struct TalpaProtocolHeader* vettingResponse(void* self, VettingClient* client, struct TalpaPacket_VettingResponse* packet);
static struct TalpaProtocolHeader* streamLength(const void* self, VettingClient* client);
static struct TalpaProtocolHeader* streamSeek(void* self, VettingClient* client, struct TalpaPacket_StreamSeek* packet);
static struct TalpaProtocolHeader* streamRead(void* self, VettingClient* client, struct TalpaPacket_StreamRead* packet);
static struct TalpaProtocolHeader* streamWrite(void* self, VettingClient* client, struct TalpaPacket_StreamWrite* packet);
static struct TalpaProtocolHeader* streamReadAt(void* self, VettingClient* client, struct TalpaPacket_StreamReadAt* packet);
static struct TalpaProtocolHeader* streamWriteAt(void* self, VettingClient* client, struct TalpaPacket_StreamWriteAt* packet);
static struct TalpaProtocolHeader* streamUnlinkFile(void* self, VettingClient* client, struct TalpaPacket_StreamUnlinkFile* packet);
static struct TalpaProtocolHeader* streamTruncate(void* self, VettingClient* client, struct TalpaPacket_StreamTruncate* packet);

static void deleteTestServer(struct tag_TestServer* object);
static TestServer* newTestServer(void);

static TestServer GL_object =
{
    {
        queryMinPacketSize,
        queryMaxPacketSize,
        queryMinStreamPacket,
        queryMaxStreamPacket,
        initializeClient,
        destroyClient,
        registerClient,
        deregisterClient,
        processPacket,
        setWaitTimeout,
        peekVettingQueue,
        obtainVettingDetails,
        releaseVettingDetails,
        vettingResponse,
        streamLength,
        streamSeek,
        streamRead,
        streamWrite,
        streamReadAt,
        streamWriteAt,
        streamUnlinkFile,
        streamTruncate,
        &GL_object,
        (void (*)(void*))deleteTestServer
    },
    deleteTestServer,
    { },
};
#define this    ((TestServer*)self)

static void deleteTestServer(struct tag_TestServer* object)
{
    return;
}

static TestServer* newTestServer(void)
{
    return &GL_object;
}

static unsigned int queryMinPacketSize(const void* self)
{
    return sizeof(struct TalpaProtocolHeader);
}

static unsigned int queryMaxPacketSize(const void* self)
{
    return 256;
}

static unsigned int queryMinStreamPacket(const void* self)
{
    return 100;
}

static unsigned int queryMaxStreamPacket(const void* self)
{
    return 1000;
}

static VettingClient* initializeClient(void* self)
{
    info("initializeClient");

    atomic_set(&this->mClient.registered, 0);
    this->mClient.process = current;
    this->mClient.response.header.version = 2;

    return &this->mClient;
}

static void destroyClient(void* self, VettingClient* client)
{
    if ( client == &this->mClient )
    {
        info("destroyClient");
    }
}

#define pktreturn_ok \
{ \
    client->response.header.type = TALPA_PKT_OK; \
    client->response.header.payloadLength = 0; \
    return (struct TalpaProtocolHeader *)(&(client)->response); \
}

#define pktreturn_fail(code) \
{ \
    client->response.header.type = TALPA_PKT_FAIL; \
    client->response.header.payloadLength = 1; \
    client->response.errorCode = code; \
    return (struct TalpaProtocolHeader *)(&(client)->response); \
}

static struct TalpaProtocolHeader* registerClient(void* self, VettingClient* client, struct TalpaPacket_Register* packet)
{
    info("registerClient");

    atomic_set(&client->registered, 1);

    if ( client == &this->mClient )
    {
        pktreturn_ok;
    }

    pktreturn_fail(-EBADF);
}

static struct TalpaProtocolHeader* deregisterClient(void* self, VettingClient* client, struct TalpaPacket_Deregister* packet)
{
    info("deregisterClient");

    atomic_set(&client->registered, 0);

    if ( client == &this->mClient )
    {
        pktreturn_ok;
    }

    pktreturn_fail(-EBADF);
}

static struct TalpaProtocolHeader* processPacket(void* self, VettingClient* client, struct TalpaProtocolHeader* packet)
{
    return NULL;
}

static struct TalpaProtocolHeader* setWaitTimeout(const void* self, VettingClient* client, struct TalpaPacket_SetWaitTimeout* packet)
{
    info("setWaitTimeout");

    if ( client == &this->mClient )
    {
        pktreturn_ok;
    }

    pktreturn_fail(-EBADF);
}

static bool peekVettingQueue(const void* self, VettingClient* client)
{
    if ( client == &this->mClient )
    {
        info("peekVettingQueue");
    }

    return true;
}

static struct TalpaProtocolHeader* obtainVettingDetails(void* self, VettingClient* client)
{
    if ( client != &this->mClient )
    {
        pktreturn_fail(-EBADF);
    }

    info("obtainVettingDetails");

    client->vettingDetails = &this->mDetails;
    this->mDetails.packet = (struct TalpaProtocolHeader *)&this->mPacket;
    this->mPacket.header.type = TALPA_PKT_FAIL;
    this->mPacket.header.payloadLength = sizeof(this->mPacket.errorCode);
    this->mPacket.errorCode = 0;

    pktreturn_ok;
}

static void releaseVettingDetails(const void* self, VettingClient* client)
{
    if ( client != &this->mClient )
    {
        info("releaseVettingDetails");
    }

    return;
}

static struct TalpaProtocolHeader* vettingResponse(void* self, VettingClient* client, struct TalpaPacket_VettingResponse* packet)
{
    info("vettingResponse");

    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamLength(const void* self, VettingClient* client)
{
    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamSeek(void* self, VettingClient* client, struct TalpaPacket_StreamSeek* packet)
{
    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamRead(void* self, VettingClient* client, struct TalpaPacket_StreamRead* packet)
{
    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamWrite(void* self, VettingClient* client, struct TalpaPacket_StreamWrite* packet)
{
    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamReadAt(void* self, VettingClient* client, struct TalpaPacket_StreamReadAt* packet)
{
    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamWriteAt(void* self, VettingClient* client, struct TalpaPacket_StreamWriteAt* packet)
{
    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamUnlinkFile(void* self, VettingClient* client, struct TalpaPacket_StreamUnlinkFile* packet)
{
    pktreturn_ok;
}

static struct TalpaProtocolHeader* streamTruncate(void* self, VettingClient* client, struct TalpaPacket_StreamTruncate* packet)
{
    pktreturn_ok;
}

static int __init talpa_test_init(void)
{
    /* Create a new client */
    mClient = newDeviceDriverVettingClient(&newTestServer()->i_IVettingServer);
    if (mClient == 0)
    {
        err("Failed to create client!");
        return -ENOMEM;
    }

    return 0;
}

static void __exit talpa_test_exit(void)
{
    mClient->delete(mClient);
    deleteTestServer(&GL_object);
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

