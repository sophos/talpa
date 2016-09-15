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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>

#ifdef HAVE_LINUXMAGIC
#include <linux/magic.h>
#endif

#ifdef HAVE_UAPILINUXMAGIC
#include <uapi/linux/magic.h>
#endif
#include <sys/vfs.h>

#include "tlp-test.h"
#include "modules/tlp-test.h"


int main(int argc, char *argv[])
{
    char file[1024];
    int operation;
    int fd;
    struct talpa_file tf;
    int ret;
    int major;
    int minor;
    int filefd;
    int ignoreMajorMinor = 0;
    struct stat pathStat;


    if ( argc == 3 )
    {
        strncpy(file,argv[1],sizeof(file));
        operation = atoi(argv[2]);
    }
    else
    {
        strcpy(file,"/bin/bash");
        operation = 1;
    }

    ret = stat(file, &pathStat);
    if (ret != 0)
    {
        fprintf(stderr,"Target file doesn't exist (stat == %d) (errno == %d)!\n",ret,errno);
        return 2;
    }

#ifdef BTRFS_SUPER_MAGIC
    {
        struct statfs statfsBuf;

        ret = statfs(file,&statfsBuf);
        if (ret == 0)
        {
            if (statfsBuf.f_type == BTRFS_SUPER_MAGIC)
            {
                ignoreMajorMinor = 1;
            }
        }
    }
#endif

    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    tf.operation = operation;
    strcpy(tf.name,file);

    ret = ioctl(fd,TALPA_TEST_FILEINFO,&tf);

    if ( ret < 0 )
    {
        fprintf(stderr,"IOCTL error!\n");
        close(fd);
        return 1;
    }

    if ( strcmp(file,tf.name) )
    {
        struct stat newpathStat;
        int newstatRes;

        newstatRes = stat(tf.name, &newpathStat);

        if (newstatRes == 0 && pathStat.st_ino == newpathStat.st_ino)
        {
            /* actually the same file even though the paths don't match */
            fprintf(stderr,"Filename mismatch! %s != %s, but actually the same file inode\n",file, tf.name);
        }
        else
        {
            fprintf(stderr,"Filename mismatch! %s != %s\n",file, tf.name);
            close(fd);
            return 1;
        }
    }

    if ( operation != tf.operation )
    {
        fprintf(stderr,"Operation mismatch! %d != %d\n",operation, tf.operation);
        close(fd);
        return 1;
    }


    if (!ignoreMajorMinor)
    {
        struct stat fstat;

        ret = stat(file, &fstat);
        if ( ret < 0 )
        {
            fprintf(stderr,"Stat of %s failed (%d)!\n", file, errno);
            close(fd);
            return 1;
        }

        major = major(fstat.st_dev);
        minor = minor(fstat.st_dev);

        if ( major != tf.major )
        {
            fprintf(stderr,"Major mismatch! %d != %d\n",major, tf.major);
            close(fd);
            return 1;
        }

        if ( minor != tf.minor )
        {
            fprintf(stderr,"Minor mismatch! %d != %d\n",minor, tf.minor);
            close(fd);
            return 1;
        }
    }

    filefd = open(file,O_RDONLY);

    if ( filefd < 0 )
    {
        fprintf(stderr,"Open of %s failed (%d)!\n",file,errno);
        close(fd);
        return 1;
    }

    tf.fd = filefd;
    ret = ioctl(fd,TALPA_TEST_FILEINFOFD,&tf);

    if ( ret < 0 )
    {
        fprintf(stderr,"FD IOCTL error!\n");
        close(fd);
        return 1;
    }

    close(filefd);

    if ( strcmp(file,tf.name) )
    {
        struct stat newpathStat;
        int newstatRes;

        newstatRes = stat(tf.name, &newpathStat);

        if (newstatRes == 0 && pathStat.st_ino == newpathStat.st_ino)
        {
            /* actually the same file even though the paths don't match */
            fprintf(stderr,"FD Filename mismatch! %s != %s, but actually the same file inode\n",file, tf.name);
        }
        else
        {
            fprintf(stderr,"FD Filename mismatch! %s != %s\n",file, tf.name);
            close(fd);
            return 1;
        }
    }

    if ( operation != tf.operation )
    {
        fprintf(stderr,"FD Operation mismatch! %d != %d\n",operation, tf.operation);
        close(fd);
        return 1;
    }

    if (!ignoreMajorMinor)
    {
        if ( major != tf.major )
        {
            fprintf(stderr,"FD Major mismatch! %d != %d\n",major, tf.major);
            close(fd);
            return 1;
        }

        if ( minor != tf.minor )
        {
            fprintf(stderr,"FD Minor mismatch! %d != %d\n",minor, tf.minor);
            close(fd);
            return 1;
        }
    }

    close(fd);

    return 0;
}

