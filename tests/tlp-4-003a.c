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

#include "../src/ifaces/intercept_filters/eintercept_action.h"
#include "../clients/vc.h"


int main(int argc, char *argv[])
{
    unsigned int group = 0;
    const unsigned int tout = 5;
    int talpa;
    struct TalpaPacket_VettingDetails* details;

    if ( argc > 1 )
    {
        group = atoi(argv[1]);
    }

    if ( (talpa = vc_init(group, tout*1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize VC!\n");
        return -1;
    }

    details = vc_get(talpa);

    if ( details )
    {
        vc_respond(talpa, details, TALPA_DENY);
    }

    vc_exit(talpa);

    return 0;
}

