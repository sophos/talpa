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

#include "../clients/vc.h"
#include "../clients/pe.h"

pthread_mutex_t pelock = PTHREAD_MUTEX_INITIALIZER;
int threadready = 0;
pthread_cond_t peready = PTHREAD_COND_INITIALIZER;
int threadexit = 0;
pthread_cond_t peexit = PTHREAD_COND_INITIALIZER;

void* pe_thread(void* param)
{
    int pe;

    if (  (pe = pe_init()) < 0 )
    {
        fprintf(stderr, "Failed to initialize PE!\n");
        return (void*)-1;
    }

    pe_active(pe);

    /* Signal readiness. */
    pthread_mutex_lock(&pelock);
    threadready = 1;
    pthread_cond_signal(&peready);
    pthread_mutex_unlock(&pelock);

    /* Loop until killed maintaining active process exclusion. */
    pthread_mutex_lock(&pelock);
    while ( !threadexit )
    {
        pthread_cond_wait(&peexit, &pelock);
    }
    pthread_mutex_unlock(&pelock);

    /* Cleanup */
    pe_idle(pe);
    pe_exit(pe);

    return NULL;
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
        fprintf(stderr, "Failed to initialize VC!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        int fd;
        int rc;
        pthread_t thread;
        void *tret;

        rc = pthread_create(&thread, NULL, pe_thread, NULL);
        if ( rc )
        {
            printf("Spawning thread failed (%d)!\n", errno);
            return -2;
        }

        /* Wait for the thread to initialise. */
        pthread_mutex_lock(&pelock);
        while ( !threadready )
        {
            pthread_cond_wait(&peready, &pelock);
        }
        pthread_mutex_unlock(&pelock);

        /* Now open a file which should not be intercepted. */
        fd = open(file, O_RDONLY);
        if ( fd < 0 )
        {
            return -1;
        }

        /* Signal thread to exit. */
        pthread_mutex_lock(&pelock);
        threadexit = 1;
        pthread_cond_signal(&peexit);
        pthread_mutex_unlock(&pelock);
        pthread_join(thread, &tret);

        if ( tret )
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

    details = vc_get(talpa);

    if ( details )
    {
        fprintf(stderr, "Unexpected caught!\n");
        vc_respond(talpa, details, TALPA_DENY);
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
        fprintf(stderr, "Child open failed!\n");
        vc_exit(talpa);
        return -1;
    }

    vc_exit(talpa);

    return 0;
}

