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
#include "../clients/pe.h"


int main(int argc, char *argv[])
{
    char path[100];
    int pe;
    int rc;
    int fd;
    char file[200];
    char *test = "vc-stream-test";
    int test_len = strlen(test);
    int talpa;
    struct TalpaPacket_VettingDetails* details;
    int slen;
    char buf[test_len];
    struct TalpaPacketFragment_FileDetails* fdetails;
    int status;


    if ( argc == 2 )
    {
        strcpy(path, argv[1]);
    }
    else
    {
        strcpy(path, "/tmp/");
    }

    if ( (pe = pe_init()) < 0 )
    {
        fprintf(stderr, "Failed to initialize process exclusion!\n");
        return -1;
    }

    strcpy(file, path);
    strcat(file, "/vc-stream-test");

    pe_active(pe);
    fd = open(file, O_CREAT | O_WRONLY | O_TRUNC);

    if ( fd < 0 )
    {
        fprintf(stderr, "Failed to create test file!\n");
        return -1;
    }

    rc = write(fd, test, test_len);

    if ( rc != test_len )
    {
        fprintf(stderr, "Failed to write test file!\n");
        return -1;
    }

    close(fd);
    pe_idle(pe);

    if ( (talpa = vc_init(0, 1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize vetting client!\n");
        unlink(file);
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        fd = open(file, O_RDONLY);

        if ( fd < 0 )
        {
            fprintf(stderr, "(child) Failed to read test file!\n");
            return -1;
        }

        close(fd);

        return 0;
    }
    else if ( rc < 0 )
    {
        fprintf(stderr, "Fork failed!\n");
        unlink(file);
        return -1;
    }

    details = vc_get(talpa);

    if ( !details )
    {
        fprintf(stderr, "Nothing caught!\n");
        vc_exit(talpa);
        wait(NULL);
        unlink(file);
        return -1;
    }

    fdetails = vc_file_frag(details);
    (void) fdetails;

    slen = vc_stream_read(talpa, buf, test_len);

    if ( slen != test_len )
    {
        fprintf(stderr, "Length mismatch %d != %d!\n", slen, test_len);
        vc_exit(talpa);
        wait(NULL);
        unlink(file);
        return -1;
    }

    if ( memcmp(test, buf, test_len) )
    {
        fprintf(stderr, "Content mismatch!\n");
        vc_exit(talpa);
        wait(NULL);
        unlink(file);
        return -1;
    }

    slen = vc_stream_seek(talpa, 0, 0);

    if ( slen < 0 )
    {
        fprintf(stderr, "Seek error %d!\n", slen);
        vc_exit(talpa);
        wait(NULL);
        unlink(file);
        return -1;
    }

    slen = vc_stream_read(talpa, buf, test_len);

    if ( slen != test_len )
    {
        fprintf(stderr, "Length2 mismatch %d != %d!\n", slen, test_len);
        vc_exit(talpa);
        wait(NULL);
        unlink(file);
        return -1;
    }

    if ( memcmp(test, buf, test_len) )
    {
        fprintf(stderr, "Content2 mismatch!\n");
        vc_exit(talpa);
        wait(NULL);
        unlink(file);
        return -1;
    }

    if ( vc_respond(talpa, details, TALPA_ALLOW) < 0 )
    {
        fprintf(stderr, "Respond error!\n");
        vc_exit(talpa);
        wait(NULL);
        unlink(file);
        return -1;
    }

    wait(&status);

    if ( !WIFEXITED(status) )
    {
        fprintf(stderr, "Child error!\n");
        vc_exit(talpa);
        unlink(file);
        return -1;
    }

    if ( WEXITSTATUS(status) )
    {
        fprintf(stderr, "Child exec failed!\n");
        vc_exit(talpa);
        unlink(file);
        return -1;
    }

    pe_exit(pe);
    vc_exit(talpa);
    unlink(file);

    return 0;
}

