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


#include <config.h>
#include <configure/autoconf.h>

#include <unistd.h>
#include <sys/mount.h>
#include <linux/unistd.h>
#include <syscall.h>
#include <malloc.h>

#include "tlp-test.h"
#include "modules/tlp-test.h"

void dump_env(char *env, unsigned int size)
{
    unsigned int len;

    do
    {
        len = strlen(env) + 1;
        size -= len;
        printf("%s\n", env);
        env += len;
    } while ( size );
}

int main(int argc, char *argv[])
{
    int fd;
    struct talpa_thread thread;
    int ret;
    char env[100000];
    int efd;
    int envsize;
    char sb[1000];
    int sfd;
    unsigned long tty;


#ifndef SYS_gettid
    exit(77);
#endif

    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    thread.env = (unsigned char *)malloc(100000);
    if ( !thread.env )
    {
        fprintf(stderr,"malloc error!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_THREADINFO,&thread);

    if ( ret < 0 )
    {
        fprintf(stderr,"IOCTL error!\n");
        close(fd);
        return 1;
    }

    if ( getpid() != thread.pid )
    {
        fprintf(stderr,"PID mismatch! %d != %d\n",getpid(), thread.pid);
        close(fd);
        return 1;
    }

#ifdef SYS_gettid
    if ( syscall(SYS_gettid) != thread.tid )
    {
        fprintf(stderr,"TID mismatch! %d != %d\n", (int)syscall(SYS_gettid), thread.tid);
        close(fd);
        return 1;
    }
#endif

    efd = open("/proc/self/environ", O_RDONLY);
    envsize = read(efd,env,sizeof(env));
    close(efd);

    /* procfs doesn't give us the full environment, so we must work around it */
    if ( (envsize > (2*1024)) && (envsize < thread.envsize) )
    {
        thread.envsize = envsize;
    }

    if ( envsize != thread.envsize )
    {
        fprintf(stderr, "Env size mismatch %d != %d\n", envsize, (int)thread.envsize);
        close(fd);
        return 1;
    }

    if ( memcmp(env, thread.env, envsize-1) )
    {
        fprintf(stderr, "Env content mismatch!\n");
        close(fd);
         dump_env(env,envsize);
         dump_env((char*) thread.env, thread.envsize);
        return 1;
    }

    sfd = open("/proc/self/stat",O_RDONLY);
    read(sfd,sb,sizeof(sb));
    close(sfd);
    sscanf(sb, "%*u %*s %*s %*u %*u %*u %lu", &tty);

    if ( tty != thread.tty )
    {
        fprintf(stderr, "Controlling TTY mismatch %ld != %ld\n", tty, thread.tty);
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}

