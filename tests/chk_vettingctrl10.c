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
#include <sys/time.h>

#include "../include/talpa-vettingclient.h"
#include "../src/ifaces/intercept_filters/eintercept_action.h"
#include "../clients/vc.h"


void sigalarm(int sig)
{
    return;
}

int main(int argc, char *argv[])
{
    unsigned int group;
    const unsigned int tout = 2;
    char file[100];
    int talpa;
    int rc;
    struct TalpaPacket_VettingDetails* details;
    int status;


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

    if ( (talpa = vc_init(group, tout*1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        /* Set-up an itimer which will interrupt the open below */
        struct itimerval it = { {1, 0}, {1, 0} };


        if ( signal(SIGALRM, sigalarm) < 0 )
        {
            return -1;
        }

        if ( setitimer(ITIMER_REAL, &it, NULL) < 0 )
        {
            return -2;
        }

        if ( open(file, O_RDONLY) < 0 )
        {
            return -3;
        }

        return 0;
    }
    else if ( rc < 0 )
    {
        fprintf(stderr, "Fork failed!\n");
        return -1;
    }

    /* Sleep for two seconds to allow for timer to interrupt the opener */
    sleep(2);

    details = vc_get(talpa);

    if ( !details )
    {
        fprintf(stderr, "Nothing caught!\n");
        vc_exit(talpa);
        wait(NULL);
        return -1;
    }

    if ( vc_respond(talpa, details, TALPA_ALLOW) < 0 )
    {
        fprintf(stderr, "Respond error!\n");
        vc_exit(talpa);
        wait(NULL);
        return -1;
    }

    wait(&status);

    if ( !WIFEXITED(status) )
    {
        fprintf(stderr, "Child error!\n");
        vc_exit(talpa);
        return -1;
    }

    if ( WEXITSTATUS(status) )
    {
        fprintf(stderr, "Child reported an error (%d)!\n", WEXITSTATUS(status));
        vc_exit(talpa);
        return -1;
    }

    vc_exit(talpa);

    return 0;
}

