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


int main(int argc, char *argv[])
{
    char dev[1024];
    char target[1024];
    char fs[1024];
    int operation;
    int fd;
    struct talpa_filesystem tfs;
    int ret;
    struct stat fstat;
    int major;
    int minor;


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

    tfs.operation = operation;
    strcpy(tfs.dev,dev);
    strcpy(tfs.target,target);
    strcpy(tfs.type,fs);

    ret = ioctl(fd,TALPA_TEST_FILESYSTEMINFO,&tfs);

    if ( ret < 0 )
    {
        fprintf(stderr,"IOCTL error!\n");
        close(fd);
        return 1;
    }

    ret = stat(dev, &fstat);
    if ( ret < 0 )
    {
            fprintf(stderr,"Stat of %s failed (%d)!\n", dev, errno);
        close(fd);
        return 77;
    }

    major = major(fstat.st_rdev);
    minor = minor(fstat.st_rdev);

    if ( operation != tfs.operation )
    {
        fprintf(stderr,"Operation mismatch! %d != %d\n",operation, tfs.operation);
        close(fd);
        return 1;
    }

    if ( major != tfs.major )
    {
        fprintf(stderr,"Major mismatch! %d != %d\n",major, tfs.major);
        close(fd);
        return 1;
    }

    if ( minor != tfs.minor )
    {
        fprintf(stderr,"Minor mismatch! %d != %d\n",minor, tfs.minor);
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}

