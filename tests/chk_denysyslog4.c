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
#include <sys/time.h>
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
    char match[1024];
    int operation;
    int action;
    int fd;
    int ret;
    struct talpa_filesystem tfs;


    if ( argc == 4 )
    {
        strncpy(match,argv[1],sizeof(match));
        operation = atoi(argv[2]);
        action = atoi(argv[3]);
    }

    if ( open_log() < 0 )
    {
        fprintf(stderr,"Failed to open syslog!\n");
        return 1;
    }

    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_SET_EVAL_CODE, action);

    if ( ret < 0 )
    {
        fprintf(stderr,"SetPath IOCTL error!\n");
        close(fd);
        return 1;
    }

    tfs.operation = operation;
    strcpy(tfs.dev,"/dev/sda1");
    strcpy(tfs.target,"/mnt");
    strcpy(tfs.type,"ext2");


    ret = ioctl(fd,TALPA_TEST_FILESYSTEMINFO,&tfs);

    if ( ret < 0 )
    {
        fprintf(stderr,"File IOCTL error!\n");
        close(fd);
        return 1;
    }

    if ( !search_log(5, match) )
    {
        fprintf(stderr,"Bad output - not critical! [%d,%d]\n", operation, action);
        close(fd);
        return 77;
    }

    close_log();
    close(fd);

    return 0;
}

