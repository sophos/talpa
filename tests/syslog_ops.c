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
    char file[1024];
    char dev[1024];
    char target[1024];
    char fs[1024];
    int foperation;
    int fsoperation;
    int fd;
    struct talpa_file tf;
    int ret;
    struct talpa_filesystem tfs;


    if ( argc == 7 )
    {
        strncpy(file,argv[1],sizeof(file));
        strncpy(dev,argv[2],sizeof(dev));
        strncpy(target,argv[3],sizeof(target));
        strncpy(fs,argv[4],sizeof(fs));
        foperation = atoi(argv[5]);
        fsoperation = atoi(argv[6]);
    }
    else
    {
        strcpy(file,"/bin/bash");
        strcpy(dev,"/dev/sda1");
        strcpy(target,"/mnt");
        strcpy(fs,"ext2");
        foperation = 1;
        fsoperation = 4;
    }

    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    tf.operation = foperation;
    strcpy(tf.name,file);

    ret = ioctl(fd,TALPA_TEST_FILEINFO,&tf);

    if ( ret < 0 )
    {
        fprintf(stderr,"File IOCTL error!\n");
        close(fd);
        return 1;
    }

    tfs.operation = fsoperation;
    strcpy(tfs.dev,dev);
    strcpy(tfs.target,target);
    strcpy(tfs.type,fs);

    ret = ioctl(fd,TALPA_TEST_FILESYSTEMINFO,&tfs);

    if ( ret < 0 )
    {
        fprintf(stderr,"Filesystem IOCTL error!\n");
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}

