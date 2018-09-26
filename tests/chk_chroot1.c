/*
 * TALPA test program
 *
 * Copyright (C) 2004-2018 Sophos Limited, Oxford, England.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../include/talpa-vettingclient.h"
#include "../clients/vc.h"


int main(int argc, char *argv[])
{
    unsigned int group;
    const unsigned int tout = 2;
    char dir[100];
    char file[100];
    int talpa;
    char *test = "write-test";
    int test_len = strlen(test);
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
        strcpy(file, "/file");
    }

    if ( (talpa = vc_init(group, tout*1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        int fd;

        fd = open(file, O_CREAT | O_WRONLY | O_TRUNC );
        if ( fd < 0 )
        {
            fprintf(stderr, "Child open failed!\n");
            return -1;
        }

        if ( chdir(dir) != 0 )
        {
            fprintf(stderr, "Child chdir failed!\n");
            return -1;
        }

        if ( chroot(dir) != 0 )
        {
            fprintf(stderr, "Child chroot failed!\n");
            return -1;
        }

        if ( write(fd, test, test_len) != test_len )
        {
            fprintf(stderr, "Child write failed!\n");
            return -1;
        }

        if ( close(fd) != 0 )
        {
            fprintf(stderr, "Child close failed!\n");
            return -1;
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

    if ( fdetails->operation != TALPA_CLOSE )
    {
        fprintf(stderr, "Didn't get TALPA_CLOSE operation: %d != %d!\n", fdetails->operation, TALPA_CLOSE );
        vc_exit(talpa);
        return -1;
    }

    fname = vc_file_name(fdetails);

    if ( strcmp(fname, file) != 0 )
    {
        fprintf(stderr, "String mismatch %s != %s!\n", fname, file);
        vc_exit(talpa);
        return -1;
    }

    if ( details->rootdir_len != 0 )
    {
        fprintf(stderr, "dir_len not zero: %d!\n",  details->rootdir_len);
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
