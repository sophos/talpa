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

#include "../clients/pe.h"


int main(int argc, char *argv[])
{
    char file[100];
    int pe;
    int fd;
    int rc;

    if ( argc > 1 )
    {
        strcpy(file, argv[1]);
    }
    else
    {
        strcpy(file, "/test/file");
    }

    if (  (pe = pe_init()) < 0 )
    {
        fprintf(stderr, "Failed to initialize PE!\n");
        return -1;
    }

    pe_active(pe);

    rc = system("./tlp-4-003a.sh");
    if ( rc < 0 )
    {
        return -1;
    }

    fd = open(file, O_RDONLY);

    rc = system("./tlp-4-003b.sh");

    if ( fd < 0 )
    {
        fprintf(stderr, "Open failed %d!\n", errno);
        return -1;
    }

    return 0;
}

