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

#include <sys/mount.h>

#include "tlp-test.h"

int main(int argc, char *argv[])
{
    char source[1024];
    char target[1024];
    char filesystem[1024];
    int runs;

    if ( argc == 5 )
    {
        strncpy(source,argv[1],sizeof(source));
        strncpy(target,argv[2],sizeof(target));
        strncpy(filesystem,argv[3],sizeof(filesystem));
        runs = atoi(argv[4]);
    }
    else
    {
        return 3;
    }

    for ( ; runs > 0; runs-- )
    {
        testi(4, mount(source, target, filesystem, 0, 0));
        testi(5, umount(target));
    }

    return 0;
}
