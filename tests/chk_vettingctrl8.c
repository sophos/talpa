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
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sched.h>

#include "../include/talpa-vettingclient.h"
#include "../src/ifaces/intercept_filters/eintercept_action.h"
#include "../clients/vc.h"


static int run = 1;

void sigusrhandler(int p)
{
    return;
}

void siginthandler(int p)
{
    run = 0;
}

int main(int argc, char *argv[])
{
    const time_t runtime = 5;
    unsigned int group;
    char file[100];
    int scanner;
    int opener;
    int status;
    time_t start;
    int rc;
    int ret = 0;


    if ( argc > 1 )
    {
        group = atoi(argv[1]);
        strcpy(file, argv[2]);
    }
    else
    {
        group = 0;
        strcpy(file, "/test/file");
    }

    scanner = fork();

    if ( !scanner )
    {
        const unsigned int tout = 2;
        int talpa;
        struct TalpaPacket_VettingDetails* details;
        struct TalpaPacketFragment_FileDetails* file;


        if ( (talpa = vc_init(group, tout*1000)) < 0 )
        {
            fprintf(stderr, "Failed to initialize!\n");
            return -1;
        }

        /* Process interceptions for ever */
        for (;;)
        {
            details = vc_get(talpa);

            if ( details )
            {
                if ( details->header.type & TALPA_PKT_FILEDETAIL )
                {
                    file = vc_file_frag(details);
                    if ( S_ISREG(file->mode) )
                    {
                        vc_scan_stream(talpa);
                    }
                }

                if ( details->responseReqd )
                {
                    vc_respond(talpa, details, TALPA_ALLOW);
                }
            }
        }

        fprintf(stderr, "Scanner exiting!\n");
        /* We do not normally exit */
        return -1;
    }
    else if ( scanner < 0 )
    {
        fprintf(stderr, "Fork 1 failed!\n");
        return -1;
    }

    opener = fork();

    if ( !opener )
    {
        int fd;
        unsigned int count = 0;
        unsigned int err = 0;


        /* Catch SIGUSR which will be sent by out parent */
        signal(SIGUSR1, sigusrhandler);
        signal(SIGINT, siginthandler);

        /* Open file for ever */
        while ( run )
        {
            count++;
            fd = open(file, O_RDONLY);
            if ( fd > 0 )
            {
                close(fd);
            }
            else
            {
                err++;
            }
        }

        /* One in how many opens failed? */
        return (err>0)?(count/err):0;
    }
    else if ( opener < 0 )
    {
        fprintf(stderr, "Fork 2 failed!\n");
        return -1;
    }

    /* Wait for things to settle */
    sleep(1);

    start = time(NULL);
    while ( (time(NULL) - start) < runtime )
    {
        /* Check if children are alive */
        rc = waitpid(scanner, &status, WNOHANG);
        if ( rc && (WIFEXITED(status) || WIFSIGNALED(status)) )
        {
            fprintf(stderr, "Scanner error (%d, %d, %d)!\n", rc, WIFEXITED(status), WIFSIGNALED(status));
            ret = -10;
            break;
        }
        rc = waitpid(opener, &status, WNOHANG);
        if ( rc && (WIFEXITED(status) || WIFSIGNALED(status)) )
        {
            fprintf(stderr, "Opener error (%d, %d, %d)!\n", rc, WIFEXITED(status), WIFSIGNALED(status));
            ret = -20;
            break;
        }

        /* Send a signal to opener */
        kill(opener, SIGUSR1);

        /* Yield CPU so that children have a chance to run */
        sched_yield();
    }

    /* Stop testing */
    kill(scanner, SIGKILL);
    kill(opener, SIGINT);

    waitpid(scanner, &status, 0);
    waitpid(opener, &status, 0);

    return ret;
}

