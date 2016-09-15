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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>


static char *detect_talpa_root(void)
{
    static const char securityfs[] = "/sys/kernel/security/talpa";
    static const char procfs[] = "/proc/sys/talpa";
    static char *root;
    int ret;
    struct stat statbuf;


    if ( root )
        return root;

    ret = stat(securityfs, &statbuf);
    if ( !ret && S_ISCHR(statbuf.st_mode) ) {
        root = (char *)securityfs;
    } else {
        ret = stat(procfs, &statbuf);
        if ( !ret && S_ISCHR(statbuf.st_mode) )
            root = (char *)procfs;
    }

    return root;
}

static char *get_talpa_device(const char *miscname, const char *container)
{
    FILE *f;
    int n;
    unsigned int major, minor;
    int found = 0;
    char devname[256];
    int ret;
    struct stat statbuf;
    char sflvar[256];
    char *talpafs;
    int retry = 2;


    /* See if our driver is listed in procfs */
    f = fopen("/proc/misc", "r");
    if ( f ) {
        do {
            n = fscanf(f, "%u %255s\n", &minor, devname);
            if ( (n == 2) && !strcmp(miscname, devname) ) {
                found = 1;
                break;
            }
        } while ( n != EOF );
        fclose(f);
    }

    strcpy(devname, "/dev/");
    strcat(devname, miscname);

    /* Check if it's valid or recreate */
    while ( found && retry ) {
        ret = stat(devname, &statbuf);
        if ( !ret && S_ISCHR(statbuf.st_mode) && (major(statbuf.st_rdev) == 10) && (minor(statbuf.st_rdev) == minor) ) {
                return strdup(devname);
        } else {
            /* Remove old if it exists */
            if ( !ret )
                ret = unlink(devname);
            else
                ret = 0;
            /* Create new device node */
            if ( !ret ) {
                ret = mknod(devname, S_IFCHR, makedev(10, minor));
                if ( !ret ) {
                    return strdup(devname);
                } else {
                    /* mknod failed - could be a race condition with udev so retry. */
                    retry--;
                }
            } else {
                /* Unlink failed - strange, maybe no permissions? */
                break;
            }
        }
    }

    /* It was listed but it cannot be reached in /dev for some reason */
    if ( found )
        return NULL;

    /* Not listed in procfs so we will try to get it directly from Talpa */
    talpafs = detect_talpa_root();
    if ( !talpafs )
        return NULL;

    strcpy(sflvar, talpafs);
    strcat(sflvar, container);
    found = 0;
    f = fopen(sflvar, "r");
    if ( f ) {
        do {
            n = fscanf(f, "%u,%u\n", &major, &minor);
            if ( n == 2 ) {
                found = 1;
                break;
            }
        } while ( n != EOF );
        fclose(f);
    }

    /* Create the device node */
    if ( found ) {
        ret = mknod(devname, S_IFCHR, makedev(major, minor));
        if ( !ret ) {
            return strdup(devname);
        }
    }

    return NULL;
}

char *get_talpa_vcdevice(void)
{
    return get_talpa_device("talpa-vc", "/filter-interfaces/DeviceDriverVettingClient/device");
}

char *get_talpa_pedevice(void)
{
    return get_talpa_device("talpa-pe", "/filter-interfaces/DeviceDriverProcessExclusion/device");
}
