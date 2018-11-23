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
    char dir[100];
    char source[100];
    char target[100];
    char type[100];
    char source_path[100];
    char target_path[100];
    int dirlen;
    int talpa;
    int rc;
    struct TalpaPacket_VettingDetails* details;
    int status;
    struct TalpaPacketFragment_FilesystemDetails* fsdetails;
    char* fsdev;


    if ( argc == 5 )
    {
        strcpy(dir, argv[1]);
        strcpy(source, argv[2]);
        strcpy(target, argv[3]);
        strcpy(type, argv[4]);
    }
    else
    {
        strcpy(dir, "/tmp");
        strcpy(source, "/dev");
        strcpy(target, "/mnt");
        strcpy(type, "ext2");
    }

    strcpy(source_path, dir);
    strcat(source_path, source);

    strcpy(target_path, dir);
    strcat(target_path, target);

    dirlen = strlen(dir);

    if ( mount( source_path, target_path, type, 0, NULL) )
    {
        fprintf(stderr, "Mount failed!\n");
        return -1;
    }


    if ( (talpa = vc_init(0, tout*1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        if ( chdir(dir) != 0 )
        {
            fprintf(stderr, "(child) chdir failed!\n");
            return -1;
        }

        if ( chroot(dir) != 0 )
        {
            fprintf(stderr, "(child) chroot failed!\n");
            return -1;
        }

        if ( umount2(target, 0) )
        {
            fprintf(stderr, "(child) Umount failed!\n");
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

    if ( details->header.type != TALPA_PKT_FILESYSTEMDETAIL )
    {
        fprintf(stderr, "Didn't get TALPA_PKT_FILESYSTEMDETAIL type: %x != %x!\n",
            details->header.type, TALPA_PKT_FILESYSTEMDETAIL );
        vc_exit(talpa);
        return -1;
    }

    fsdetails = vc_filesystem_frag(details);

    if ( fsdetails->operation != TALPA_UMOUNT )
    {
        fprintf(stderr, "Didn't get TALPA_UMOUNT operation: %d != %d!\n",
            fsdetails->operation, TALPA_UMOUNT );
        vc_exit(talpa);
        return -1;
    }

    fsdev = vc_filesystem_dev(fsdetails);

    if ( strcmp(fsdev, source_path) )
    {
        fprintf(stderr, "String mismatch %s != %s!\n", fsdev, source);
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

