/*
 * TALPA test program
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>

#include "tlp-test.h"
#include "modules/tlp-test.h"
#include "src/ifaces/intercept_filters/eintercept_action.h"


int main(int argc, char *argv[])
{
    char dev[1024];
    char target[1024];
    char fs[1024];
    int operation;
    int fd;
    int ret;
    struct talpa_filesystem tfs;


    if ( argc == 5 )
    {
        strncpy(dev,argv[1],sizeof(dev));
        strncpy(target,argv[2],sizeof(target));
        strncpy(fs,argv[3],sizeof(fs));
        operation = atoi(argv[4]);
    }
    else
    {
        strcpy(dev,"/dev/sda1");
        strcpy(target,"/mnt");
        strcpy(fs,"ext2");
        operation = 4;
    }

    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    ret = ioctl(fd, TALPA_TEST_STDINT_PURGEFILTERS );

    if ( ret )
    {
        fprintf(stderr,"IOCTL error %d!\n", errno);
        close(fd);
        return 1;
    }

    ret = ioctl(fd, TALPA_TEST_STDINT_EVALFILTER, EIA_Allow );

    if ( ret )
    {
        fprintf(stderr,"IOCTL error %d!\n", errno);
        close(fd);
        return 1;
    }

    ret = ioctl(fd, TALPA_TEST_STDINT_ALLOWFILTER, EIA_Error );

    if ( ret )
    {
        fprintf(stderr,"IOCTL error %d!\n", errno);
        close(fd);
        return 1;
    }

    tfs.operation = operation;
    strcpy(tfs.dev,dev);
    strcpy(tfs.target,target);
    strcpy(tfs.type,fs);

    ret = ioctl(fd,TALPA_TEST_FILESYSTEMINFO,&tfs);

    if ( (unsigned int)ret != -(0xdeadbeef) )
    {
        fprintf(stderr,"Test error %d!\n", errno);
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}

