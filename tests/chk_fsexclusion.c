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
    char file[1024];
    char fs[1024];
    unsigned int action;
    int fd;
    int ret;
    struct talpa_file tf;


    if ( argc == 4 )
    {
        strncpy(file,argv[1],sizeof(file));
        strncpy(fs,argv[2],sizeof(fs));
        action = atoi(argv[3]);
    }
    else
    {
        strcpy(file,"/sbin/init");
        strcpy(fs,"ext2");
        action = EIA_Next;
    }

    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    strcpy(tf.name,file);
    strcpy(tf.fstype,fs);

    ret = ioctl(fd,TALPA_TEST_FILEINFO,&tf);

    if ( ret < 0 )
    {
        fprintf(stderr,"File IOCTL error!\n");
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

