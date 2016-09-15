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
#include <sys/mount.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "../include/talpa-vettingclient.h"
#include "../src/ifaces/intercept_filters/eintercept_action.h"
#include "../clients/vc.h"


int main(int argc, char *argv[])
{
    unsigned int group;
    const unsigned int tout = 2;
    int talpa;
    struct TalpaPacket_VettingDetails* details;
    time_t start;
    time_t end;

    if ( argc == 2 )
        group = atoi(argv[1]);
    else
        group = 0;

    if ( (talpa = vc_init(group, tout*1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    start = time(NULL);
    while ( time(NULL) == start );
    start = time(NULL);
    details = vc_get(talpa);
    end = time(NULL);

    if ( details )
    {
        fprintf(stderr, "Unexpected interception!\n");
        vc_exit(talpa);
        return -1;
    }

    if ( ! ((tout-1) <= abs(end-start) && abs(end-start) <= (tout+1)) )
    {
        fprintf(stderr, "Timeout error (%d (%d))!\n", abs(end-start), tout);
        vc_exit(talpa);
        return -1;
    }

    vc_exit(talpa);

    return 0;
}

