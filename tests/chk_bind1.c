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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/mount.h>

#include "tlp-test.h"


int main(int argc, char *argv[])
{
    const char* src;
    const char* dst;

    if (argc > 2)
    {
        src = argv[1];
        dst = argv[2];
    }
    else
    {
        fprintf(stderr, "Bad usage!\n");
        return 1;
    }

    if ( mount(src, dst, NULL, MS_BIND, "") )
    {
        fprintf(stderr, "Failed to mount: errno=%d\n", errno);
        return 1;
    }

    return 0;
}

