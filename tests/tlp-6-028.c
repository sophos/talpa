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
    struct talpa_write tw;
    char buf[4096];
    unsigned int len;

    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    strcpy(to.filename,"/tmp/talpa-file-object-test-file");
    to.flags = O_WRONLY;
    to.mode = S_IRUSR | S_IWUSR;

    ret = open(to.filename, to.flags | O_TRUNC | O_CREAT, to.mode);

    if ( ret < 0 )
    {
        fprintf(stderr,"Create error!\n");
        close(fd);
        return 1;
    }

    close(ret);

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

    len = ret;
    strcpy(buf, "talpa-file-object-test-string");
    len = strlen(buf) + 1;

    tw.data = buf;
    tw.size = len;

    ret = ioctl(fd,TALPA_TEST_FILE_WRITE, &tw);

    if ( ret < 0 )
    {
        fprintf(stderr,"Write error!\n");
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

    to.flags = O_WRONLY;
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

    ret = ioctl(fd,TALPA_TEST_FILE_TRUNCATE, 0);

    if ( ret < 0 )
    {
        fprintf(stderr,"Truncate error!\n");
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

    to.flags = O_WRONLY;
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

    if ( ret != 0 )
    {
        fprintf(stderr,"length error!\n");
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

    close(fd);

    return 0;
}

