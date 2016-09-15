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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>

#include "pe.h"

char *get_talpa_pedevice(void);


int pe_init(void)
{
    int rc;
    int fd;
    char *devname;


    devname = get_talpa_pedevice();
    if ( !devname )
    {
        return -1;
    }

    fd = open(devname, O_RDWR);
    free(devname);
    if ( fd < 0 )
    {
        return -1;
    }

    rc = ioctl(fd, TLPPEIOC_ACTIVE);
    if ( rc < 0 )
    {
        close(fd);
        return -1;
    }

    rc = ioctl(fd, TLPPEIOC_IDLE);
    if ( rc < 0 )
    {
        close(fd);
        return -1;
    }

    return fd;
}

int pe_exit(int handle)
{
    return close(handle);
}

int pe_active(int handle)
{
    return ioctl(handle, TLPPEIOC_ACTIVE);
}

int pe_idle(int handle)
{
    return ioctl(handle, TLPPEIOC_IDLE);
}
