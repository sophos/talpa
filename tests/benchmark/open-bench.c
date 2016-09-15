/*
 * TALPA test program
 *
 * TALPA Filesystem Interceptor
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/times.h>

int main(int argc, char *argv[])
{
    char *file = "/bin/ls";
    unsigned int loops = 1000000;
    char *arg;
    unsigned int pos = 1;
    struct tms times1, times2;
    struct timeval tv1, tv2;
    long cps;
    int forks = 1;
    int children = 0;
    pid_t child;
    struct timespec ts;

    cps = sysconf(_SC_CLK_TCK);

    for ( ; argc > 1 ; pos++, argc-- )
    {
        arg = argv[pos];
        if ( !strncmp(arg, "-f", 2) )
        {
            arg += 2;
            file = arg;
        }
        else if ( !strncmp(arg, "-l", 2) )
        {
            arg += 2;
            loops = atol(arg);
        }
        else if ( !strncmp(arg, "-o", 2) )
        {
            arg += 2;
            forks = atoi(arg);
        }
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 200000000;

    while ( forks-- )
    {
        child = fork();

        if ( child == 0 )
        {
            nanosleep(&ts, NULL);
            gettimeofday(&tv1, NULL);
            times(&times1);
            while ( loops-- )
            {
                close(open(file, O_RDONLY));
            }
            times(&times2);
            gettimeofday(&tv2, NULL);

            times2.tms_utime -= times1.tms_utime;
            times2.tms_stime -= times1.tms_stime;

            tv2.tv_sec -= tv1.tv_sec;
            tv2.tv_usec -= tv1.tv_usec;

            printf("%.3f-[%.3f/%.3f]\n", (float)tv2.tv_sec + (float)tv2.tv_usec/1000000.0, (float)times2.tms_utime / (float)cps, (float)times2.tms_stime / (float)cps);

            return 0;
        }
        else if ( child > 0 )
        {
            children++;
        }

    }

    while ( children-- )
    {
        wait(NULL);
    }

    return 0;
}
