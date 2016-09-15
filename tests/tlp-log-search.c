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
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/select.h>

static int syslog_fd;


int open_log(void)
{
    int error;
    errno = 0;
    syslog_fd = open("/var/log/messages", O_RDONLY | O_NONBLOCK);
    error = errno;


    if ( syslog_fd < 0 && error == ENOENT)
    {
        syslog_fd = open("/var/log/kern.log", O_RDONLY | O_NONBLOCK);
        error = errno;
    }

    if ( syslog_fd < 0 )
    {
        fprintf(stderr,"Failed to open syslog %d %s\n",error, strerror(error));
    }

    return syslog_fd;
}

int close_log(void)
{
    return close(syslog_fd);
}

int search_log(time_t timeout, const char* match)
{
    char line[10000];
    int pos = 0;
    int ret;
    time_t start;
    fd_set set;
    struct timeval tv;

    ret = lseek(syslog_fd,-1000,SEEK_END);

    if ( ret < 0 )
    {
        return ret;
    }

    start = time(NULL);
    do
    {
        FD_ZERO(&set);
        FD_SET(syslog_fd, &set);
        tv.tv_usec = 0;
        tv.tv_sec = 1;
        ret = select(syslog_fd+1, &set, NULL, NULL, &tv);
        while ( ret > 0 )
        {
            ret = read(syslog_fd,&line[pos],1);
            if ( ret <= 0 )
            {
                break;
            }
            if ( line[pos] == '\n' )
            {
                line[pos] = 0x00;
                pos = 0;
                if ( strstr(line, match) )
                {
                    return 1;
                }
                continue;
            }
            pos++;
            if ( pos >= sizeof(line) )
            {
                pos = 0;
            }
        }
    } while ( (time(NULL) - start) < timeout );

    return 0;
}

