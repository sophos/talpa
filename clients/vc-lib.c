/*
 * TALPA test program
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>
#include <malloc.h>

#include "vc.h"


char *get_talpa_vcdevice(void);

int vc_init(unsigned int group, unsigned int timeout_ms)
{
    int talpafd;
    int rc;
    struct TalpaPacket_Register reg;
    struct TalpaPacket_SetWaitTimeout tout;
    char *devname;


    devname = get_talpa_vcdevice();
    if ( !devname )
    {
        return -1;
    }

    talpafd = open(devname, O_RDWR);
    free(devname);
    if ( talpafd < 0 )
    {
        return -1;
    }

    reg.header.version = TALPA_PROTOCOL_VERSION;
    reg.group = group;
    tout.header.version = TALPA_PROTOCOL_VERSION;
    tout.timeout_ms = timeout_ms;

    rc = ioctl(talpafd, TLPVCIOC_REGISTER, &reg);
    if ( rc < 0 )
    {
        close(talpafd);
        return -1;
    }

    rc = ioctl(talpafd, TLPVCIOC_SETWAITTIMEOUT, &tout);
    if ( rc < 0 )
    {
        close(talpafd);
        return -1;
    }

    return talpafd;
}

int vc_exit(int handle)
{
    struct TalpaPacket_Deregister dereg;

    dereg.header.version = TALPA_PROTOCOL_VERSION;

    ioctl(handle, TLPVCIOC_DEREGISTER, &dereg);

    return close(handle);
}

struct TalpaPacket_VettingDetails* vc_get(int handle)
{
    struct TalpaProtocolHeader head;
    struct TalpaPacket_VettingDetails *packet;
    int rc;

    rc = read(handle, &head, sizeof(head));
    if ( rc < 0 )
    {
        return NULL;
    }

    packet = (struct TalpaPacket_VettingDetails *)malloc(sizeof(head) + head.payloadLength);

    if ( !packet )
    {
        return NULL;
    }

    rc = read(handle, ((char *)packet) + sizeof(head), head.payloadLength);

    if ( rc < 0 )
    {
        free(packet);
        return NULL;
    }

    memcpy(packet, &head, sizeof(head));

    return packet;
}

struct TalpaPacket_VettingDetails* vc_poll(int handle, unsigned int ms)
{
    struct TalpaProtocolHeader head;
    struct TalpaPacket_VettingDetails *packet = NULL;
    int rc;
    struct pollfd pfd;
    int oldflags, flags;

    oldflags = fcntl(handle, F_GETFL);
    flags = oldflags | O_NONBLOCK;
    fcntl(handle, F_SETFL, flags);

    pfd.fd = handle;
    pfd.events = POLLIN;
    pfd.revents = 0;

    rc = poll(&pfd, 1, ms);

    if ( rc < 1 )
    {
        goto out;
    }

    rc = read(handle, &head, sizeof(head));
    if ( rc < 0 )
    {
        goto out;
    }

    packet = (struct TalpaPacket_VettingDetails *)malloc(sizeof(head) + head.payloadLength);

    if ( !packet )
    {
        goto out;
    }

    rc = read(handle, ((char *)packet) + sizeof(head), head.payloadLength);

    if ( rc < 0 )
    {
        free(packet);
        packet = NULL;
        goto out;
    }

    memcpy(packet, &head, sizeof(head));

    out:
    fcntl(handle, F_SETFL, oldflags);
    return packet;
}

void vc_release(int handle, struct TalpaPacket_VettingDetails* packet)
{
    (void) handle; /* we're not using handle */

    free(packet);
    return;
}

int vc_respond(int handle, struct TalpaPacket_VettingDetails* packet, ETalpaProtocolResponse response)
{
    struct TalpaPacket_VettingResponse resp;
    int rc;

    resp.header.type = TALPA_PKT_VETRESPONSE;
    resp.header.version = TALPA_PROTOCOL_VERSION;
    resp.response = response;
    resp.vettingID = packet->vettingID;

    rc = write(handle, &resp, sizeof(resp));

    return rc;
}

int vc_stream_length(int handle)
{
    struct TalpaPacket_StreamLength req;
    struct TalpaPacket_StreamData packet;

    int rc;


    req.header.type = TALPA_PKT_STREAMLENGTH;
    req.header.version = TALPA_PROTOCOL_VERSION;

    rc = write(handle, &req, sizeof(req));
    if ( rc < 0 )
    {
        return -1;
    }

    rc = read(handle, &packet, sizeof(struct TalpaPacket_StreamData));
    if ( rc < 0 )
    {
        return -1;
    }

    return packet.size;
}

int vc_stream_seek(int handle, unsigned int offset, int mode)
{
    struct TalpaPacket_StreamSeek req;
    int rc;

    req.header.type = TALPA_PKT_STREAMSEEK;
    req.header.version = TALPA_PROTOCOL_VERSION;
    req.offset = offset;
    req.mode = mode;

    rc = write(handle, &req, sizeof(req));

    return rc;
}

int vc_stream_read(int handle, void *buffer, size_t size)
{
    struct TalpaPacket_StreamRead req;
    int rc;
    struct TalpaPacket_StreamData packet;


    req.header.type = TALPA_PKT_STREAMREAD;
    req.header.version = TALPA_PROTOCOL_VERSION;
    req.size = size;

    rc = write(handle, &req, sizeof(req));
    if ( rc < 0 )
    {
        return -1;
    }

    rc = read(handle, &packet, sizeof(struct TalpaPacket_StreamData));
    if ( rc < 0 )
    {
        return -1;
    }

    if ( !packet.size )
    {
        return 0;
    }

    rc = read(handle, buffer, packet.size);

    if ( rc < 0 )
    {
        return -1;
    }

    return rc;
}

int vc_stream_write(int handle, void *buffer, size_t size)
{
    struct TalpaPacket_StreamWrite *req = (struct TalpaPacket_StreamWrite *)malloc(sizeof(struct TalpaPacket_StreamWrite) + size);
    struct TalpaPacket_StreamData packet;
    int rc;


    if ( !req )
    {
        return -1;
    }

    req->header.type = TALPA_PKT_STREAMWRITE;
    req->header.version = TALPA_PROTOCOL_VERSION;
    req->size = size;
    memcpy((unsigned char *)req + sizeof(struct TalpaPacket_StreamWrite), buffer, size);

    rc = write(handle, req, sizeof(struct TalpaPacket_StreamWrite) + size);
    free(req);
    if ( rc < 0 )
    {
        return -1;
    }

    rc = read(handle, &packet, sizeof(struct TalpaPacket_StreamData));
    if ( rc < 0 )
    {
        return -1;
    }

    return packet.size;
}

int vc_stream_unlink_file(int handle)
{
    struct TalpaPacket_StreamUnlinkFile req;
    int rc;

    req.header.type = TALPA_PKT_STREAMUNLINKFILE;
    req.header.version = TALPA_PROTOCOL_VERSION;

    rc = write(handle, &req, sizeof(req));

    return rc;
}

int vc_stream_truncate(int handle, unsigned int length)
{
    struct TalpaPacket_StreamTruncate req;
    int rc;

    req.header.type = TALPA_PKT_STREAMTRUNCATE;
    req.header.version = TALPA_PROTOCOL_VERSION;
    req.length = length;

    rc = write(handle, &req, sizeof(req));

    return rc;
}

unsigned int vc_scan_stream(int handle)
{
    int rc;
    char buf[4096];
    unsigned int total = 0;

    do
    {
        rc = vc_stream_read(handle, buf, sizeof(buf));
        if ( rc > 0 )
        {
            total += rc;
        }
    } while ( (rc == sizeof(buf)) && (total < (sizeof(buf)*16)) );

    return total;
}


