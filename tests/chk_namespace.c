/*
 * TALPA test program
 *
 * Copyright (C) 2004-2017 Sophos Limited, Oxford, England.
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

/* for unshare */
#define _GNU_SOURCE

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
#include <sched.h>

#include "../include/talpa-vettingclient.h"
#include "../src/ifaces/intercept_filters/eintercept_action.h"
#include "../clients/vc.h"


int main(int argc, char *argv[])
{
    unsigned int group;
    const unsigned int tout = 2;
    char dir[100];
    char file[100];
    char file_path[100];
    int dirlen;
    int talpa;
    int rc;
    struct TalpaPacket_VettingDetails* details;
    struct TalpaPacketFragment_FileDetails* fdetails;
    char* fname;
    int status;



    if ( argc > 2 )
    {
        group = atoi(argv[1]);
        strcpy(dir, argv[2]);
        strcpy(file, argv[3]);
    }
    else
    {
        group = 0;
        strcpy(dir, "/test");
        strcpy(file, "file");
    }

    strcpy(file_path, dir);
    strcat(file_path, "/");
    strcat(file_path, file);
    strcat(file_path, " (namespace)");

    dirlen = 0;

    if ( (talpa = vc_init(group, tout*1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        int fd;
        int ret = 0;

        ret = unshare(CLONE_NEWNS);
        if( ret < 0 )
        {
            fprintf(stderr, "unshare failed!\n");
            return -1;
        }

        ret = chdir(dir);
        if( ret < 0 )
        {
            fprintf(stderr, "chdir failed!\n");
            return -2;
        }

        fd = open(file, O_RDONLY);
        if ( fd <= 0 )
        {
            fprintf(stderr, "open failed!\n");
            return -3;
        }

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

    fdetails = vc_file_frag(details);
    fname = vc_file_name(fdetails);

    if ( strcmp(fname, file_path) != 0 )
    {
        fprintf(stderr, "String mismatch %s != %s!\n", fname, file_path);
        vc_exit(talpa);
        return -1;
    }

    if ( details->rootdir_len != dirlen )
    {
        fprintf(stderr, "dir_len mismatch %d != %d!\n",  details->rootdir_len, dirlen);
        vc_exit(talpa);
        return -1;
    }

    if ( !WIFEXITED(status) )
    {
        fprintf(stderr, "Child error!\n");
        vc_exit(talpa);
        return -1;
    }

    if ( WEXITSTATUS(status) )
    {
        fprintf(stderr, "Child exec failed!\n");
        vc_exit(talpa);
        return -1;
    }

    vc_exit(talpa);

    return 0;
}
