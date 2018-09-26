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
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../include/talpa-vettingclient.h"
#include "../clients/vc.h"


int main(int argc, char *argv[])
{
    const unsigned int tout = 2;
    char source[100];
    char source_path[100];
    char target[100];
    char type[100];
    int talpa;
    int rc;
    struct TalpaPacket_VettingDetails* details;
    int status;
    struct TalpaPacketFragment_FilesystemDetails* fsdetails;
    char* fsdev;


    if ( argc == 5 )
    {
        strcpy(source, argv[1]);
        strcpy(target, argv[2]);
        strcpy(type, argv[3]);
        strcpy(source_path, argv[4]);
    }
    else if ( argc == 4 )
    {
        strcpy(source, argv[1]);
        strcpy(target, argv[2]);
        strcpy(type, argv[3]);
        strcpy(source_path, source);
    }
    else
    {
        strcpy(source, "/dev/loop0");
        strcpy(target, "/tmp/mnt");
        strcpy(type, "ext2");
        strcpy(source_path, source);
    }

    if ( (talpa = vc_init(0, tout*1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        if ( mount( source, target, type, 0, NULL) )
        {
            fprintf(stderr, "(child) Mount failed!\n");
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

    fsdetails = vc_filesystem_frag(details);

    if ( fsdetails->operation != TALPA_MOUNT )
    {
        fprintf(stderr, "Didn't get TALPA_MOUNT operation: %d != %d!\n", fsdetails->operation, TALPA_MOUNT );
        vc_exit(talpa);
        return -1;
    }

    fsdev = vc_filesystem_dev(fsdetails);

    if ( strcmp(fsdev, source_path) )
    {
        fprintf(stderr, "String mismatch %s != %s!\n", fsdev, source_path);
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
    umount2(target, 0);

    return 0;
}

