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
    int fd;
    int ret;
    struct talpa_open to;
    struct talpa_read tr;
    char buf[4096];
    unsigned int len;
    struct stat st;
    int rfd;
    char buf2[4096];


    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    strcpy(to.filename,"/bin/bash");
    to.flags = O_RDONLY;
    to.mode = S_IRUSR | S_IWUSR;

    ret = ioctl(fd,TALPA_TEST_FILE_OPEN, &to);

    if ( ret < 0 )
    {
        fprintf(stderr,"Open error!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILE_ISOPEN);

    if ( ret <= 0 )
    {
        fprintf(stderr,"isOpen error!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILE_LENGTH);

    if ( ret < 0 )
    {
        fprintf(stderr,"length ioctl error!\n");
        close(fd);
        return 1;
    }

    len = ret;

    ret = stat(to.filename, &st);
    if ( ret < 0 )
    {
        fprintf(stderr,"Stat error!\n");
        close(fd);
        return 1;
    }

    if ( len != st.st_size )
    {
        fprintf(stderr,"Length mismatch!\n");
        close(fd);
        return 1;
    }

    tr.data = buf;
    tr.size = sizeof(buf);

    ret = ioctl(fd,TALPA_TEST_FILE_READ, &tr);

    if ( ret < 0 )
    {
        fprintf(stderr,"Read error!\n");
        close(fd);
        return 1;
    }

    rfd = open(to.filename, to.flags, to.mode);

    if ( rfd < 0 )
    {
        fprintf(stderr,"libc open error!\n");
        close(fd);
        return 0;
    }

    ret = read(rfd, buf2, sizeof(buf2));

    if ( ret < 0 )
    {
        fprintf(stderr,"libc read error!\n");
        close(fd);
        return 0;
    }

    if ( memcmp(buf, buf2, sizeof(buf)) )
    {
        fprintf(stderr,"Data mismatch!\n");
        close(rfd);
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILE_CLOSE);

    if ( ret < 0 )
    {
        fprintf(stderr,"Close error!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILE_ISOPEN);

    if ( ret > 0 )
    {
        fprintf(stderr,"isOpen error - file open after close!\n");
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}

