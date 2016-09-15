/*
 * TALPA test program
 *
 * Copyright (C) 2004-2014 Sophos Limited, Oxford, England.
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

#include <errno.h>
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
    int ret;
    const char* mntpnt;

    if (argc > 1)
    {
        mntpnt = argv[1];
    }
    else
    {
        mntpnt = "/fakeproc";
    }


    ret = mkdir(mntpnt, 0700);
    if (ret != 0 && errno != EEXIST)
    {
        return 77;
    }

    if (ret == 0)
    {
        if ( mount(NULL,mntpnt,"proc",0,"") )
        {
            fprintf(stderr,"Failed to mount proc errno=%d\n",errno);
            if (rmdir(mntpnt) != 0)
            {
                /* May have mounted after all */
                umount(mntpnt);
                rmdir(mntpnt);
            }
            return 1;
        }
        umount(mntpnt);
        rmdir(mntpnt);
    }

    return 0;
}

