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
    char path[1024];
    unsigned int action;
    int fd;
    int ret;
    struct talpa_filesystem tfs;


    if ( argc == 3 )
    {
        strncpy(path,argv[1],sizeof(path));
        action = atoi(argv[2]);
    }
    else
    {
        strcpy(path,"/mnt");
        action = EIA_Next;
    }

    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    strcpy(tfs.dev, "/dev/sda1");
    strcpy(tfs.target, path);
    strcpy(tfs.type, "ext2");
    tfs.operation = 4;

    ret = ioctl(fd,TALPA_TEST_FILESYSTEMINFO,&tfs);

    if ( ret < 0 )
    {
        fprintf(stderr,"Filesystem IOCTL error!\n");
        close(fd);
        return 1;
    }
    else if ( ret != action )
    {
        fprintf(stderr, "Action mismatch %d != %d!\n", ret, action);
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}

