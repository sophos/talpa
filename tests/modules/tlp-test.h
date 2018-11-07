/*
 * tlp-test.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2018 Sophos Limited, Oxford, England.
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
#ifndef TLPTEST_H
#define TLPTEST_H

#define TALPA_MAJOR 60
#define TALPA_DEVICE "talpa-test"


struct talpa_file
{
    int     fd;
    char    name[256];
    int     operation;
    int     flags;
    int     mode;
    int     major;
    int     minor;
    char    fstype[256];
};

struct talpa_filesystem
{
    char    dev[256];
    char    target[256];
    char    type[256];
    int     operation;
    int     major;
    int     minor;
};

struct talpa_personality
{
    uid_t   uid;
    uid_t   euid;
    gid_t   gid;
    gid_t   egid;
};

struct talpa_thread
{
    pid_t   pid;
    pid_t   tid;
    unsigned long tty;
    unsigned long envsize;
    unsigned char* env;
};

struct talpa_open
{
    char            filename[256];
    unsigned int    flags;
    unsigned int    mode;
};

struct talpa_seek
{
    loff_t  offset;
    int     mode;
};

struct talpa_read
{
    void*   data;
    size_t  size;
};

struct talpa_write
{
    void*   data;
    size_t  size;
};

struct talpa_cacheobj
{
    char        class[256];
    uint32_t    keyH;
    uint32_t    keyL;
};

#define TALPA_TEST_FILEINFO             _IOWR( 0xff,     0,      struct talpa_file* )
#define TALPA_TEST_FILEINFOFD           _IOWR( 0xff,     1,      struct talpa_file* )
#define TALPA_TEST_FILESYSTEMINFO       _IOWR( 0xff,     2,      struct talpa_filesystem* )
#define TALPA_TEST_PERSONALITY          _IOR ( 0xff,     3,      struct talpa_personality* )
#define TALPA_TEST_STDINT_EVALFILTER    _IOW ( 0xff,     4,      EInterceptAction )
#define TALPA_TEST_STDINT_ALLOWFILTER   _IOW ( 0xff,     5,      EInterceptAction )
#define TALPA_TEST_STDINT_DENYFILTER    _IOW ( 0xff,     6,      EInterceptAction )
#define TALPA_TEST_STDINT_PURGEFILTERS  _IO  ( 0xff,     7 )
#define TALPA_TEST_INCL_SETPATH         _IOW ( 0xff,     8,      char* )
#define TALPA_TEST_SET_EVAL_CODE        _IOW ( 0xff,     9,      EInterceptAction )
#define TALPA_TEST_THREADINFO           _IOWR( 0xff,    10,      struct talpa_thread* )
#define TALPA_TEST_CACHE_EVAL           _IOWR( 0xff,    11,      struct talpa_file* )
#define TALPA_TEST_CACHE_ALLOW          _IOWR( 0xff,    12,      struct talpa_file* )
#define TALPA_TEST_CACHE_DENY           _IOWR( 0xff,    13,      struct talpa_file* )
#define TALPA_TEST_CACHE_EXTALLOW       _IOWR( 0xff,    14,      struct talpa_file* )
#define TALPA_TEST_CACHE_EXTDENY        _IOWR( 0xff,    15,      struct talpa_file* )
#define TALPA_TEST_DEGRMODE_TIMEOUTS    _IOW ( 0xff,    16,      unsigned int )
#define TALPA_TEST_FILE_OPEN            _IOW ( 0xff,    17,      struct talpa_open* )
#define TALPA_TEST_FILE_CLOSE           _IO  ( 0xff,    18 )
#define TALPA_TEST_FILE_ISOPEN          _IO  ( 0xff,    19 )
#define TALPA_TEST_FILE_LENGTH          _IO  ( 0xff,    20 )
#define TALPA_TEST_FILE_SEEK            _IOW ( 0xff,    21,     struct talpa_seek* )
#define TALPA_TEST_FILE_READ            _IOWR( 0xff,    22,     struct talpa_read* )
#define TALPA_TEST_FILE_WRITE           _IOW ( 0xff,    23,     struct talpa_write* )
#define TALPA_TEST_FILE_TRUNCATE        _IOW ( 0xff,    24,     off_t )
#define TALPA_TEST_FILE_UNLINK          _IO  ( 0xff,    25 )
#define TALPA_TEST_CACHE_FIND           _IOW ( 0xff,    26,     struct talpa_cacheobj* )
#define TALPA_TEST_CACHE_ADD            _IOW ( 0xff,    27,     struct talpa_cacheobj* )
#define TALPA_TEST_CACHE_CLEAR          _IOW ( 0xff,    28,     struct talpa_cacheobj* )
#define TALPA_TEST_CACHE_CONFIG         _IOW ( 0xff,    29,     char* )
#define TALPA_TEST_CACHE_PURGE          _IO  ( 0xff,    30 )
#define TALPA_TEST_SET_ERROR_CODE       _IOW ( 0xff,    31,     int )


#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>

/* see if the kernel was built with retpoline (TALPA_HAS_RETPOLINE) and whether
 * we can build our modules to match (RETPOLINE). */
#ifdef TALPA_HAS_RETPOLINE
/* RETPOLINE is defined by the kernel Makefile only if gcc has the required options */
# ifndef RETPOLINE
#  error "CONFIG_RETPOLINE=y, but not supported by the compiler. Toolchain update required."
# endif
#endif

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
static inline int talpa_unregister_chrdev(unsigned int major, const char *name)
{
    unregister_chrdev(major, name);

    return 0;
}
  #else
static inline int talpa_unregister_chrdev(unsigned int major, const char *name)
{
    return unregister_chrdev(major, name);
}
  #endif
#endif

#endif
