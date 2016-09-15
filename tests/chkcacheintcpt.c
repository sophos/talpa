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
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>

#include "../include/talpa-vettingclient.h"
#include "../src/ifaces/intercept_filters/eintercept_action.h"
#include "../clients/vc.h"


int main(int argc, char *argv[])
{
    char *tmpfile;
    int talpa;
    int rc;
    struct TalpaPacket_VettingDetails* details;
    int status;


    if ( argc == 2 )
    {
        tmpfile = argv[1];
    }
    else
    {
        fprintf(stderr, "Bad usage!\n");
        return 1;
    }

    if ( (talpa = vc_init(0, 2000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        int fd;

        fd = open(tmpfile, O_RDWR | O_CREAT | O_EXCL, 0);
        if (fd < 0) {
            perror("Open failed");
            return 1;
        }

        close(fd);

        return 0;
    }
    else if ( rc < 0 )
    {
        fprintf(stderr, "Fork failed!\n");
        return -1;
    }

    details = vc_get(talpa);

    if ( !details )
    {
        fprintf(stderr, "No interception!\n");
        vc_exit(talpa);
        wait(NULL);
        return -1;
    }
    else
    {
        if ( vc_stream_length(talpa) < 0 )
        {
            fprintf(stderr, "No file stream!\n");
            vc_respond(talpa, details, TALPA_ALLOW);
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
        fprintf(stderr, "Child failed!\n");
        vc_exit(talpa);
        return -1;
    }

    vc_exit(talpa);

    return 0;
}

