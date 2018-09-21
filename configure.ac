#
# configure.ac
#
# TALPA Filesystem Interceptor
#
# Copyright (C) 2004-2018 Sophos Plc
#
# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License Version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not,
# write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#

AC_INIT(talpa, 0.9.95)
AC_CONFIG_AUX_DIR(config)
AC_COPYRIGHT(Copyright (c) 2004-2018 Sophos Plc)

AM_INIT_AUTOMAKE([1.9 tar-ustar dist-zip dist-bzip2])
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

#
# Programs.
#
AC_PROG_CC
AM_PROG_CC_C_O
AC_CHECK_TOOL(MODULELINKER, ld, :)
AC_PROG_EGREP
AC_PROG_LN_S

AC_PATH_PROG(CAT, cat)
test -x "${CAT}" || AC_MSG_ERROR([Please install cat before configuring])

AC_PATH_PROG(CUT, cut)
test -x "${CUT}" || AC_MSG_ERROR([Please install cut before configuring])

AC_PATH_PROG(SED, sed)
test -x "${SED}" || AC_MSG_ERROR([Please install sed before configuring])

AC_PATH_PROG(UNAME, uname)
test -x "${UNAME}" || AC_MSG_ERROR([Please install uname before configuring])

AC_PATH_PROG(RM, rm)
test -x "${RM}" || AC_MSG_ERROR([Please install rm before configuring])

AC_PATH_PROG(XARGS, xargs)
test -x "${XARGS}" || AC_MSG_ERROR([Please install xargs before configuring])


#
# Options.
#
AC_PREFIX_DEFAULT(/opt/talpa)

compile_flags=

AC_ARG_ENABLE(talpa-build,
            [  --disable-talpa-build          configure building of talpa [[build]]],
            [talpabuild=$enableval],
            [talpabuild=yes])

AC_ARG_WITH(kernel,
            [  --with-kernel=DIR                    specify the kernel that should be built against],
            [ AC_SUBST(kerneldir,[$withval])
              AC_SUBST(sourcedir,[$withval]) ],
            [ kernver=`${UNAME} -r`
              AC_SUBST(kerneldir,[/lib/modules/${kernver}/build])
              AC_SUBST(sourcedir,[/lib/modules/${kernver}/source]) ])

AC_ARG_WITH(symvers,
            [  --with-symvers=FILE                  specify the kernel Module.symvers that should be built against],
            [ AC_SUBST(symvers,[$withval]) ],
            [ AC_SUBST(symvers,[${kerneldir}/Module.symvers]) ])

AC_ARG_WITH(kernel-include,
            [  --with-kernel-include=DIR:DIR        specify the include path for kernel header files that should be built against],
            [ AC_SUBST(kernelhdrspath,[$withval]) ])

AC_ARG_ENABLE(debug,
              [  --enable-debug                 enable debugging code],
              [ if test "$enableval" = "yes"; then
                    AC_SUBST(debug,"-DDEBUG -g")
                fi])

AC_ARG_ENABLE(assertions,
              [  --enable-assertions            turn on assertions],
              [ if test "$enableval" = "yes"; then
                    AC_SUBST(assert,"-DASSERT")
                fi])

AC_ARG_WITH(system-map,
              [  --with-system-map                    location of the System.map file [[autodetected]]],
              [ system_map=$withval
                auto_system_map=no ],
              [ auto_system_map=yes ])

AC_ARG_ENABLE(hidden-syscall-table,
                [  --enable-hidden-syscall-table  enable hunting for a hidden syscall table [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(hidden,"-DTALPA_HIDDEN_SYSCALLS")
                    fi
                    auto_hidden=no
                ],
                [   auto_hidden=yes ])

AC_ARG_ENABLE(new-parent,
                [  --enable-new-parent            enable support for 2.6 style task_struct on some patched 2.4 kernels [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(newparent,"-DTALPA_HAS_NEW_PARENT")
                    fi
                    auto_parent=no
                ],
                [   auto_parent=yes])

AC_ARG_ENABLE(dpath,
                [  --enable-dpath                 For example Fedora FC5 exports __d_path which is unusual for 2.6 kernels [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(dpath,"-DTALPA_HAS_DPATH")
                    fi
                    auto_dpath=no
                ],
                [   auto_dpath=yes])

AC_ARG_ENABLE(path-lookup,
                [  --enable-path-lookup           some kernels older than 2.4.25 have backported a change which exports path_lookup [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(pathlookup,"-DTALPA_HAS_PATH_LOOKUP")
                    fi
                    auto_pathlookup=no
                ],
                [   auto_pathlookup=yes])

AC_ARG_ENABLE(task-new-tty,
                [  --enable-task-new-tty          SuSE Enterprise Server 9 2.6.5 kernel has a task_struct from later kernels [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(tasknewtty,"-DTALPA_HAS_TASK_NEW_TTY")
                    fi
                    auto_tasknewtty=no
                ],
                [   auto_tasknewtty=yes])

AC_ARG_ENABLE(backported-rcu,
                [  --enable-backported-rcu        Fedora FC4 2.6.11 has rcpudate.h backported from vanilla 2.6.12 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(rcubackport,"-DTALPA_HAS_BACKPORTED_RCU")
                    fi
                    auto_rcubackport=no
                ],
                [   auto_rcubackport=yes])

AC_ARG_ENABLE(backported-mutexes,
                [  --enable-backported-mutexes    Fedora FC5 2.6.15 has mutexes backported from vanilla 2.6.16 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(mutexes,"-DTALPA_HAS_MUTEXES")
                    fi
                    auto_mutexbackport=no
                ],
                [   auto_mutexbackport=yes])

AC_ARG_ENABLE(inode_mutexes,
                [  --enable-inode_mutexes         Later RedHat Enterprise 4 kernels have backported mutexes without the inode changes [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(inodemutex,"-DTALPA_INODE_USES_MUTEXES")
                    fi
                    auto_inodemutex=no
                ],
                [   auto_inodemutex=yes])

AC_ARG_ENABLE(inode_iprivate,
                [  --enable-inode_iprivate        RedHat Enterprise 5 kernels have this field backported [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(inodeiprivate,"-DTALPA_INODE_I_PRIVATE")
                    fi
                    auto_inodeiprivate=no
                ],
                [   auto_inodeiprivate=yes])

AC_ARG_ENABLE(backported-signal,
                [  --enable-backported-signal     Fedora FC4 2.6.11 has the task_struct->signal backported from vanilla 2.6.12 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(signalbackport,"-DTALPA_HAS_BACKPORTED_SIGNAL")
                    fi
                    auto_signalbackport=no
                ],
                [   auto_signalbackport=yes])

AC_ARG_ENABLE(backported-jiffies,
                [  --enable-backported-jiffies    Updated SLES9 kernel can have features backported from newer versions [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(jiffiesbackport,"-DTALPA_HAS_BACKPORTED_JIFFIES")
                    fi
                    auto_jiffiesbackport=no
                ],
                [   auto_jiffiesbackport=yes])

AC_ARG_ENABLE(backported-filldir,
                [  --enable-backported-filldir    More recent filldir_t callbacks pass u64 for inode number [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(filldirbackport,"-DTALPA_HAS_BACKPORTED_FILLDIR")
                    fi
                    auto_filldirbackport=no
                ],
                [   auto_filldirbackport=yes])

AC_ARG_ENABLE(no-tasklist-lock,
                [  --enable-no-tasklist-lock      Starting with vanilla 2.6.18 tasklist_lock is no longer exported [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(notasklistlock,"-DTALPA_NO_TASKLIST_LOCK")
                    fi
                    auto_notasklistlock=no
                ],
                [   auto_notasklistlock=yes])

AC_ARG_ENABLE(backported-mountrcu,
                [  --enable-backported-mountrcu  Updated RHEL 7 can have an RCU in the mount struct [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(mountrcubackport,"-DTALPA_HAS_BACKPORTED_MOUNTRCU")
                    fi
                    auto_mountrcubackport=no
                ],
                [   auto_mountrcubackport=yes])

AC_ARG_ENABLE(lsm,
                [  --enable-lsm                   try to build LSM dependent modules [[autodetected]]],
                [   auto_lsm=no
                    AC_SUBST(lsm,$enableval) ],
                [   auto_lsm=yes])

AC_ARG_ENABLE(lsm-keys,
                [  --enable-lsm-keys              LSM implementation has keys support [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsmkeys,"-DTALPA_HAS_LSM_KEYS")
                    fi
                    auto_lsmkeys=no
                ],
                [   auto_lsmkeys=yes])

AC_ARG_ENABLE(lsm-2614,
                [  --enable-lsm-2614              for example Turbolinux Server 10 x64 2.6.13 kernels have LSM backported from 2.6.14 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsm2614,"-DTALPA_HAS_2614_LSM")
                    fi
                    auto_lsm2614=no
                ],
                [   auto_lsm2614=yes])

AC_ARG_ENABLE(lsm-2610,
                [  --enable-lsm-2610              for example RHAS 4.0 2.6.9 kernel has LSM backported from 2.6.10 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsm2610,"-DTALPA_HAS_2610_LSM")
                    fi
                    auto_lsm2610=no
                ],
                [   auto_lsm2610=yes])

AC_ARG_ENABLE(lsm-266,
                [  --enable-lsm-266               for example Fedora Core 2 2.6.5 kernel has LSM backported from 2.6.6 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsm266,"-DTALPA_HAS_266_LSM")
                    fi
                    auto_lsm266=no
                ],
                [   auto_lsm266=yes])

AC_ARG_ENABLE(lsm-265,
                [  --enable-lsm-265               for example SuSE-s 9.1 2.6.4 kernel has LSM backported from 2.6.5 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsm265,"-DTALPA_HAS_265_LSM")
                    fi
                    auto_lsm265=no
                ],
                [   auto_lsm265=yes])

AC_ARG_WITH(test-interceptor,
            [  --with-test-interceptor=INTERCEPTOR  specify interceptor to use for testing (lsm,syscall,vfshook) [[default]]],
            [testinterceptor=$withval],
            [testinterceptor=default])

AC_ARG_ENABLE(hrtimers,
              [  --enable-hrtimers              are hrtimers exported [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(hrtimers,"-DTALPA_HAS_HRTIMERS")
                    fi
                    auto_hrtimers=no
                ],
                [   auto_hrtimers=yes])

AC_ARG_ENABLE(hookdops,
              [  --enable-hookdops              hook d_ops [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(hookdops,"-DTALPA_CONFIG_HOOK_DOPS")
                    fi
                    auto_hookdops=no
                ],
                [   auto_hookdops=yes])

AC_ARG_ENABLE(x-workaround,
              [  --disable-x-workaround         disable X server workaround where open(2) fails with -EINTR because itimers are not honoured [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(xhack,"-DTALPA_HAS_XHACK")
                    fi
                    auto_xhack=no
                ],
                [   auto_xhack=yes
                    AC_SUBST(xhack,"-DTALPA_HAS_XHACK")

                ])

AC_ARG_ENABLE(struct-filename,
              [  --enable-struct-filename         putname and getname deal with struct filename rather than char* [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(structfilename,"-DTALPA_HAS_STRUCT_FILENAME")
                    fi
                    auto_struct_filename=no
                ],
                [   auto_struct_filename=yes
                ])

AC_ARG_WITH(stacker,
              [  --with-stacker                       should additional and unsupported LSM stacking module be built [[no]]],
              [ buildstacker=$withval
                if test "$withval" = "yes"; then
                    AM_CONDITIONAL(BUILDSTACKER, test 1 -eq 1)
                else
                    AM_CONDITIONAL(BUILDSTACKER, test 0 -eq 1)
                fi ],
              [ buildstacker=no
                AM_CONDITIONAL(BUILDSTACKER, test 0 -eq 1)
              ])

AC_ARG_WITH(symbolver,
              [  --with-symbolver                     should symbol verifier module be built [[no]]],
              [ buildsymbolver=$withval
                if test "$withval" = "yes"; then
                    AM_CONDITIONAL(BUILDSYMBOLVER, test 1 -eq 1)
                else
                    AM_CONDITIONAL(BUILDSYMBOLVER, test 0 -eq 1)
                fi ],
              [ buildsymbolver=no
                AM_CONDITIONAL(BUILDSYMBOLVER, test 0 -eq 1)
              ])

AC_ARG_ENABLE(same-file,
              [  --enable-same-file             should file being intercepted be directly used for stream interface operations or a new copy opened [[disabled]]],
              [ if test $enableval = "yes"; then
                    AC_SUBST(samefile, "-DTALPA_SAME_FILE")
                else
                    AC_SUBST(samefile, "")
                fi ],
              [ AC_SUBST(samefile, "") ])

AC_ARG_ENABLE(securityfs,
                [  --enable-securityfs            use securityfs for the configuration system [[autodetected]]],
                [   auto_securityfs=no
                    if test "$enableval" = "yes"; then
                        AC_SUBST(securityfs, "-DTALPA_HAS_SECURITYFS")
                        AC_SUBST(buildsecurityfs, "yes")
                        AM_CONDITIONAL(BUILDSECURITYFS, test 1 -eq 1)
                    else
                        AC_SUBST(buildsecurityfs, "no")
                        AM_CONDITIONAL(BUILDSECURITYFS, test 0 -eq 1)
                    fi ],
                [   auto_securityfs=yes])

AC_ARG_ENABLE(loadtest,
                [  --enable-loadtest            Run load tests [[no]]],
                [   loadtests="$enableval"
                    if test "$enableval" = "yes"; then
                        AM_CONDITIONAL(LOADTEST, test 1 -eq 1)
                    else
                        AM_CONDITIONAL(LOADTEST, test 0 -eq 1)
                    fi ],
                [   auto_securityfs=yes
                    AM_CONDITIONAL(LOADTEST, test 0 -eq 1)  ])

AC_ARG_WITH(legacy-configurator,
                [  --without-legacy-configurator        keep procfs configuration system when securityfs is in use [[enabled]]],
                [ wantdualfs="$withval" ],
                [ wantdualfs="yes"])

AC_ARG_ENABLE(test-warnings-errors,
                [  --disable-test-warnings-errors disable warnings as errors when compiling configure test programs [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        auto_warnings=force
                    else
                        auto_warnings=
                    fi ],
                [   auto_warnings=yes])

CFLAGS=

#
# Talpa version
#
AC_MSG_CHECKING([for Talpa version])
AC_MSG_RESULT(AC_PACKAGE_VERSION)

#
# Should we build?
#
if test "$talpabuild" = "yes"; then

#
# Setup our search macros.
#

# TALPA_LOCATE_FILE(name, path, [action-if-found], [action-if-not-found])
#--------------------------------------------------------------------------
AC_DEFUN([TALPA_LOCATE_FILE],
[
file_found="false"
for searchdir in `echo $2 | ${SED} 's/:/ /g'`
  do
    if test -f $searchdir/$1; then
        file_found="true"
        TALPA_FILE_LOCATION=$searchdir
        break
    fi
  done
if test "$file_found" = "false"; then
    TALPA_FILE_LOCATION=
    checkString=`sed -e 's/"/\\"/g' <<++++
$4
++++`
    if test "$checkString" != ""; then
        eval "$checkString"
    fi
 else
    checkString=`sed -e 's/"/\\"/g' <<++++
$3
++++`
    if test "checkString" != ""; then
        eval "$checkString"
    fi
fi])

# TALPA_LOCATE_HEADER(name, path, [action-if-found], [action-if-not-found], [quiet])
#--------------------------------------------------------------------------
AC_DEFUN([TALPA_LOCATE_HEADER],
[
if test "$5" = ""; then
    AC_MSG_CHECKING([for $1])
fi
hdr_found="false"
for hdrdir in `echo $2 | ${SED} 's/:/ /g'`
  do
    if test -f $hdrdir/$1; then
        hdr_found="true"
        TALPA_HEADER_LOCATION=$hdrdir
        break
    fi
  done
if test "$hdr_found" = "false"; then
    checkString=`sed -e 's/"/\\"/g' <<++++
$4
++++`
    if test "$checkString" != ""; then
        eval "$checkString"
    else
        TALPA_HEADER_LOCATION=
        checkString=`sed -e 's/"/\\"/g' <<++++
$5
++++`
        if test "$checkString" = ""; then
            AC_MSG_ERROR(cannot proceed without the required header file)
        else
            AC_MSG_ERROR(Unable to find $1. Cannot proceed.)
        fi
    fi
 else
    checkString=`sed -e 's/"/\\"/g' <<++++
$3
++++`
    if test "$checkString" != ""; then
        eval "$checkString"
    else
        checkString=`sed -e 's/"/\\"/g' <<++++
$5
++++`
        if test "$checkString" = ""; then
            AC_MSG_RESULT(yes)
        fi
    fi
fi])

# TALPA_INCLUDE_PATH(path)
#--------------------------------------------------------------------------
AC_DEFUN([TALPA_INCLUDE_PATH],
[-I`echo $1 | ${SED} 's/:/ -I/g'`])

#
# Autodetect platform we are running on.
#
AC_MSG_CHECKING([for operating system])
platform=`${UNAME} -s`
if test "$platform" = "GNU/Linux" -o "$platform" = "Linux"; then
    if test -L ${srcdir}/src/ifaces/platform -o -d ${srcdir}/src/ifaces/platform; then
        ${RM} -rf ${srcdir}/src/ifaces/platform
    fi
    (cd ${srcdir}/src/ifaces && ${LN_S} platforms/linux platform)
    if test $? -ne 0; then
        AC_MSG_ERROR([setup failed])
    fi
    AC_MSG_RESULT([${platform}])
else
    AC_MSG_ERROR([failed])
fi

#
# Kernel headers autodetection
#
function append_path
{
    local full=$1
    local path=$2


    if test "$full" = ""; then
        echo "$path"
    else
        echo "$full:$path"
    fi
}

function check_headers_layout
{
    local type=$1

    kernelhdrspath=
    AC_MSG_CHECKING([for kernel headers layout])
    if test "$type" = "xen"; then
        if test -d "${kerneldir}/include2/asm/mach-xen"; then
            kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/include2/asm/mach-xen"`
        fi
        if test -d "${kerneldir}/include/asm/mach-xen"; then
            kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/include/asm/mach-xen"`
        fi
        if test -d "${kerneldir}/arch/x86/include/asm/mach-xen"; then
            kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/arch/x86/include/asm/mach-xen"`
        fi
        if test -d "${sourcedir}/include/asm/mach-xen"; then
            kernelhdrspath=`append_path "${kernelhdrspath}" "${sourcedir}/include/asm/mach-xen"`
        fi
        if test -d "${sourcedir}/arch/x86/include/asm/mach-xen"; then
            kernelhdrspath=`append_path "${kernelhdrspath}" "${sourcedir}/arch/x86/include/asm/mach-xen"`
        fi
    fi
    kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/include"`
    if test -d "${kerneldir}/arch/x86/include/asm"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/arch/x86/include"`
    fi
    if test -d "${kerneldir}/arch/x86/include/generated"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/arch/x86/include/generated"`
    fi
    if test -d "${kerneldir}/include2"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/include2"`
        if test -d "${kerneldir}/include2/asm/mach-default"; then
            kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/include2/asm/mach-default"`
        fi
    fi
    if test -d "${sourcedir}"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${sourcedir}/include"`
        if test -d "${sourcedir}/arch/x86/include/asm"; then
            kernelhdrspath=`append_path "${kernelhdrspath}" "${sourcedir}/arch/x86/include"`
        fi
    fi
    if test -d "${kerneldir}/include/asm/mach-default"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/include/asm/mach-default"`
    fi
    if test -d "${kerneldir}/arch/x86/include/asm/mach-default"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/arch/x86/include/asm/mach-default"`
    fi
    if test -d "${sourcedir}/include/asm/mach-default"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${sourcedir}/include/asm/mach-default"`
    fi
    if test -d "${sourcedir}/arch/x86/include/asm/mach-default"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${sourcedir}/arch/x86/include/asm/mach-default"`
    fi
    if test -d "${kerneldir}/include/generated/uapi"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/include/generated/uapi"`
    fi
    if test -d "${kerneldir}/include/uapi"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${kerneldir}/include/uapi"`
    fi

    # Support for possibly broken Debian 7.11 3.16.0-0.bpo.4-amd64 backport.
    if test -d "${sourcedir}/include/uapi"; then
        kernelhdrspath=`append_path "${kernelhdrspath}" "${sourcedir}/include/uapi"`
    fi
    AC_MSG_RESULT([$kernelhdrspath])
}

if test "$kernelhdrspath" = ""; then
    auto_headers=yes
    check_headers_layout basic
fi

#
# Headers.
#
TALPA_LOCATE_HEADER(linux/version.h, $kernelhdrspath)


TALPA_LOCATE_HEADER(linux/magic.h, $kernelhdrspath, linuxmagicfound=yes, linuxmagicfound=no)
AC_MSG_RESULT([$linuxmagicfound - $TALPA_HEADER_LOCATION])
if test "$linuxmagicfound" = "yes" ; then
    linuxmagicinclude="-I$TALPA_HEADER_LOCATION"
    AC_DEFINE([HAVE_LINUXMAGIC],1,[Defined when we have linux/magic.h])
else
    linuxmagicinclude=""
fi
AC_SUBST(linuxmagicinclude, "$linuxmagicinclude")

TALPA_LOCATE_HEADER(uapi/linux/magic.h, $kernelhdrspath, linuxuapimagicfound=yes, linuxuapimagicfound=no)
AC_MSG_RESULT([$linuxuapimagicfound - $TALPA_HEADER_LOCATION])
if test "$linuxuapimagicfound" = "yes" ; then
    linuxuapimagicinclude="-I$TALPA_HEADER_LOCATION"
    AC_DEFINE([HAVE_UAPILINUXMAGIC],1,[Defined when we have uapi/linux/magic.h])
else
    linuxuapimagicinclude=""
fi
AC_SUBST(linuxuapimagicinclude, "$linuxuapimagicinclude")


# Check for uidgid.h type
TALPA_LOCATE_HEADER(linux/uidgid.h, $kernelhdrspath, linuxuidgidfound=yes, linuxuidgidfound=no)
AC_MSG_RESULT([for uidgid strict type checking header])
if test "$linuxuidgidfound" = "yes" ; then
    AC_DEFINE([HAVE_LINUXUIDGID],1,[Defined when we have linux/uidgid.h])
    linuxuidgid="-DHAVE_LINUXUIDGID"
else
    linuxuidgid=""
fi

TALPA_LOCATE_HEADER(linux/compiler.h, $kernelhdrspath, linuxcompilerfound=yes, linuxcompilerfound=no)
AC_MSG_RESULT([$linuxcompilerfound - $TALPA_HEADER_LOCATION])
if test "$linuxcompilerfound" = "yes" ; then
    linuxcompilerinclude="-I$TALPA_HEADER_LOCATION"
    AC_DEFINE([HAVE_LINUXCOMPILER],1,[Defined when we have linux/compiler.h])
else
    linuxcompilerinclude=""
fi
AC_SUBST(linuxcompilerinclude, "$linuxcompilerinclude")

TALPA_LOCATE_HEADER(uapi/asm/unistd.h, $kernelhdrspath, uapiunistdfound=yes, uapiunistdfound=no)
AC_MSG_RESULT([$uapiunistdfound - $TALPA_HEADER_LOCATION])
if test "$uapiunistdfound" = "yes" ; then
    uapiunistdinclude="-I$TALPA_HEADER_LOCATION"
    AC_DEFINE([HAVE_UAPIUNISTD],1,[Defined when we have uapi/asm/unistd.h])
else
    uapiunistdinclude=""
fi
AC_SUBST(uapiunistdinclude, "$uapiunistdinclude")

TALPA_LOCATE_HEADER(asm/unistd_64_x32.h, $kernelhdrspath, unistd64x32found=yes, unistd64x32found=no)
AC_MSG_RESULT([$unistd64x32found - $TALPA_HEADER_LOCATION])
if test "$unistd64x32found" = "yes" ; then
    unistd64x32include="-I$TALPA_HEADER_LOCATION"
    AC_DEFINE([HAVE_UNISTD64x32],1,[Defined when we have asm/unistd_64_x32.h])
else
    unistd64x32include=""
fi
AC_SUBST(unistd64x32include, "$unistd64x32include")

AC_MSG_CHECKING([for kernel configuration])
TALPA_LOCATE_HEADER(generated/autoconf.h, $kernelhdrspath, autoconffound=yes, autoconffound=no, [quiet])
if test "$autoconffound" = "yes"; then
    autoconf_h=generated/autoconf.h
    autoconf_h_path=$TALPA_HEADER_LOCATION/generated/autoconf.h
    autoconf_h_include="-I${TALPA_HEADER_LOCATION}"
    utsrelease_h=generated/utsrelease.h
    ccgenerateduts="-DGENERATED_UTS_RELEASE"
else
    TALPA_LOCATE_HEADER(linux/autoconf.h, $kernelhdrspath, autoconffound=yes, autoconffound=no, [quiet])
    if test "$autoconffound" = "yes"; then
        autoconf_h=linux/autoconf.h
        autoconf_h_path=$TALPA_HEADER_LOCATION/linux/autoconf.h
        autoconf_h_include="-I${TALPA_HEADER_LOCATION}"
        utsrelease_h=linux/utsrelease.h
    else
        AC_MSG_ERROR([autoconf.h not found])
    fi
fi
AC_SUBST(autoconf_h_include,"$autoconf_h_include")

if test ! -d tests/configure; then
    mkdir -p tests/configure
fi

cat <<EOF >tests/configure/autoconf.h
#ifndef TALPA_AUTOCONF_H
#define TALPA_AUTOCONF_H
#include <$autoconf_h>
#endif
EOF
kernccflags="-pipe -D__KERNEL__"
tmp=`${EGREP} "CONFIG_X86.*_XEN " $autoconf_h_path 2>/dev/null | ${CUT} -d ' ' -f 3`
if test "$tmp" = "1"; then
    xen=1
    tmp=`${EGREP} "CONFIG_XEN_INTERFACE_VERSION " $autoconf_h_path 2>/dev/null | ${CUT} -d ' ' -f 3`
    if test "$tmp" != ""; then
        kernccflags="${kernccflags} -D__XEN_INTERFACE_VERSION__=${tmp}"
    fi
fi
AC_MSG_RESULT([done])

if test "$xen" = "1"; then
    if test "$auto_headers" = "yes"; then
        check_headers_layout xen
    fi
fi

# Test if and how we can compile test programs
AC_MSG_CHECKING([for compilation environment])
if test "$auto_warnings" = "yes"; then
    if ! ${CC} ${kernccflags} -Werror TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/kernelheaders.c -o /dev/null 1>/dev/null 2>&1; then
        if ! ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/kernelheaders.c -o /dev/null; then
            echo ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/kernelheaders.c -o /dev/null
            AC_MSG_ERROR([unable to compile test programs])
        else
            AC_MSG_RESULT([warnings as errors turned off])
        fi
    else
        AC_MSG_RESULT([ok])
        kernccflags="${kernccflags} -Werror"
    fi
elif test "$auto_warnings" = "force"; then
    AC_MSG_RESULT([forced ok])
    kernccflags="${kernccflags} -Werror"
else
    AC_MSG_RESULT([forced no warnings as errors])
fi

AC_MSG_CHECKING([for kernel architecture])
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/kernarch.c -o tests/configure/kernarch
kern_arch=`tests/configure/kernarch`
AC_MSG_RESULT([${kern_arch}])
${RM} -f tests/configure/kernarch
if test "$kern_arch" = "unsupported"; then
    AC_MSG_ERROR([kernel architecture not supported])
fi

AC_MSG_CHECKING([for kernel version code])
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/kernversion.c -o tests/configure/kernversion
kern_version_code=`tests/configure/kernversion`
AC_MSG_RESULT([${kern_version_code}])
${RM} -f tests/configure/kernversion
## 2.6.0  == 132608
## 2.6.5  == 132613
## 2.6.15 == 132623     0x02060f
## 2.6.18 == 132626     0x020612    0x12==18
## 2.6.21 == 132629     0x020615
## 2.6.24 (Ubuntu 8.04)
## 2.6.25 == 132633     0x020619
## 2.6.36 == 132644     0x020624    0x24==36
## 3.0.0  == 196608     0x030000
## 3.3.0  == 197376     0x030300
## 3.5.0  == 197888     0x030500
## 3.7.0  == 198400     0x030700
## 3.11.0 == 199424     0x030b00
## 3.11.10== 199434     0x030b0a (Ubuntu 12.04.4)
## 3.12.0 == 199680
## 3.13.0 == 199936     0x030d00

AC_MSG_CHECKING([for kernel version string])
TALPA_LOCATE_HEADER($utsrelease_h, $kernelhdrspath, cckernrelease="-DSEPARATE_UTS_RELEASE", /bin/true, [quiet])
${CC} ${kernccflags} ${cckernrelease} ${ccgenerateduts} -Itests/configure TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernrelease.c -o tests/configure/kernrelease
kern_uts_release=`tests/configure/kernrelease`
AC_MSG_RESULT([${kern_uts_release}])
${RM} -f tests/configure/kernrelease

AC_MSG_CHECKING([for RHEL release code])
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/rhel_release.c -o tests/configure/rhel_release  1>/dev/null 2>&1
if test $? -eq 0; then
    rhel_release=yes
    rhel_release_code=`tests/configure/rhel_release`
    AC_MSG_RESULT([${rhel_release_code}])
else
    rhel_release=no
    AC_MSG_RESULT([not found])
fi
${RM} -f tests/configure/rhel_release
## 7.4 == 1796  0x0704

## 3.0.0+
if test $((kern_version_code)) -ge 196608 ; then
    kernccflags="${kernccflags} -Os"
fi

## 2.6.20+
AM_CONDITIONAL(TESTNAMESPACES, test $((kern_version_code)) -ge 132628)

## 2.6.0+
AM_CONDITIONAL(KBUILD26, test $((kern_version_code)) -ge 132608)
# Set these to true for time being
AM_CONDITIONAL(TESTXWORKAROUND, test 1 -eq 1)

# Select interceptor to use for testing
case $testinterceptor in
    default)
        AC_SUBST(interceptor_module,vfshook)
        AC_SUBST(interceptor_name,VFSHookInterceptor)
        ;;
    best)
        ## Kernel 2.6.0+
        if test $((kern_version_code)) -ge 132608; then
            AC_SUBST(interceptor_module,lsm)
            AC_SUBST(interceptor_name,LSMInterceptor)
        else
            AC_SUBST(interceptor_module,vfshook)
            AC_SUBST(interceptor_name,VFSHookInterceptor)
        fi
        ;;
    syscall)
        AC_SUBST(interceptor_module,syscall)
        AC_SUBST(interceptor_name,SyscallInterceptor)
        ;;
    lsm)
        AC_SUBST(interceptor_module,lsm)
        AC_SUBST(interceptor_name,LSMInterceptor)
        ;;
    vfshook)
        AC_SUBST(interceptor_module,vfshook)
        AC_SUBST(interceptor_name,VFSHookInterceptor)
        ;;
    *)
        AC_MSG_ERROR(Unknown interceptor)
        ;;
esac


# On 2.6.36 we use unused PF_ALIGNWARN task flag
if test $((kern_version_code)) -eq 132644; then
    AC_MSG_CHECKING([for unused task flag])
    AC_SUBST(freetaskflag, "-DPF_TALPA_INTERNAL=0x1")
    AC_MSG_RESULT([0x1 (2.6.36)])
else
    TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
    AC_MSG_CHECKING([for unused task flag])
    ${RM} -f ffzb_local.c ffzb_local
    if ! ${EGREP} "#define PF_" $TALPA_HEADER_LOCATION/linux/sched.h > ffzb_local.c; then
        AC_MSG_ERROR([grep error])
    fi
    echo "#define PF_TALPA_ALL \\" >> ffzb_local.c
    for taskflag in `${EGREP} "#define PF_" $TALPA_HEADER_LOCATION/linux/sched.h | ${CUT} -f1 | ${CUT} -d' ' -f2`; do
        echo $taskflag \| \\ >> ffzb_local.c
    done
    echo "0x0" >> ffzb_local.c
    if ! ${CAT} ${srcdir}/tests/configure/ffzb.c >> ffzb_local.c; then
        AC_MSG_ERROR([cat error])
    fi
    if ! ${CC} ffzb_local.c -o ffzb_local 2>&1; then
        AC_MSG_ERROR([compiler failure])
    fi
    free_flag=`./ffzb_local`
    rc=$?
    if test $rc -eq 0 && test -n $free_flag; then
        AC_MSG_RESULT([$free_flag])
        AC_SUBST(freetaskflag, "-DPF_TALPA_INTERNAL=$free_flag")
    elif test $rc -eq 2; then
        AC_MSG_ERROR([find error])
    else
        AC_MSG_ERROR([none free ($rc)])
    fi
fi

AM_CONDITIONAL(M32_BUILD, test 1 -eq 0)
AM_CONDITIONAL(MX32_BUILD, test 1 -eq 0)
march=`${UNAME} -m`
if test "$march" = "x86_64"; then
    # Check for compatibility targets
    AC_MSG_CHECKING([for -m32 build])
    if ${CC} -m32 ${srcdir}/tests/configure/mount.c -o mount_32 1>/dev/null 2>&1; then
        ./mount_32
        if test $rc -eq 0; then
            AC_MSG_RESULT([works])
            AM_CONDITIONAL(M32_BUILD, test 1 -eq 1)
        else
            AC_MSG_RESULT([cannot execute])
        fi
    else
        AC_MSG_RESULT([cannot compile])
    fi
    AC_MSG_CHECKING([for -mx32 build])
    if ${CC} -mx32 ${srcdir}/tests/configure/mount.c -o mount_x32 1>/dev/null 2>&1; then
        ./mount_x32
        if test $rc -eq 0; then
            AC_MSG_RESULT([works])
            AM_CONDITIONAL(MX32_BUILD, test 1 -eq 1)
        else
            AC_MSG_RESULT([cannot execute])
        fi
    else
        AC_MSG_RESULT([cannot compile])
    fi
fi

# Try to find the System.map file
AC_MSG_CHECKING([for System.map])
if test "$auto_system_map" = "yes"; then
    system_map="/boot/System.map-${kern_uts_release}"
fi
if test ! -f "$system_map"; then
    AC_MSG_ERROR([$system_map not found])
    system_map=""
else
    AC_MSG_RESULT([$system_map])
fi

# Check for printk address
AC_MSG_CHECKING([for printk address])
tmp=`${EGREP} " printk\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
if test "$tmp" != ""; then
    AC_MSG_RESULT([0x$tmp])
    AC_SUBST(printkaddr, "-DTALPA_PRINTK_ADDR=0x${tmp}UL")
else
    AC_MSG_ERROR([not found])
fi

# Check for do_truncate address
AC_MSG_CHECKING([for do_truncate address])
tmp=`${EGREP} " do_truncate\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
if test "$tmp" != ""; then
    AC_MSG_RESULT([0x$tmp])
    AC_SUBST(dotruncateaddr, "-DTALPA_DOTRUNCATE_ADDR=0x${tmp}UL")
else
    AC_MSG_ERROR([not found])
fi

# Check for do_truncate type
TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath)
AC_MSG_CHECKING([for do_truncate type])
let hitcnt=0
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dotruncate1.c  -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_1")
    AC_MSG_RESULT([type 1])
fi
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dotruncate2.c  -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_2")
    AC_MSG_RESULT([type 2])
fi
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dotruncate3.c  -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_3")
    AC_MSG_RESULT([type 3])
fi
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dotruncaterh4.c  -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_RH4")
    AC_MSG_RESULT([type rh4])
fi
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dotruncatesuse103.c  -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_SUSE103")
    AC_MSG_RESULT([type suse103])
fi
if test $hitcnt -eq 0 ; then
    AC_MSG_ERROR([unknown])
fi
if test $hitcnt -gt 1 ; then
    AC_MSG_ERROR([ambiguous])
fi

# Check for vfs_unlink type
TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath)
AC_MSG_CHECKING([for vfs_unlink type])
let hitcnt=0
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/unlink_delegate.c 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(vfsunlink, "-DTALPA_VFSUNLINK_DELEGATE")
    AC_MSG_RESULT([with inode])
fi
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/unlink.c 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(vfsunlink, "-DTALPA_VFSUNLINK_STANDARD")
    AC_MSG_RESULT([standard])
fi
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/unlinksuse103.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(vfsunlink, "-DTALPA_VFSUNLINK_SUSE103")
    AC_MSG_RESULT([suse103])
fi
${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/unlinkvserver.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=$hitcnt+1
    AC_SUBST(vfsunlink, "-DTALPA_VFSUNLINK_VSERVER")
    AC_MSG_RESULT([vserver])
fi
if test $hitcnt -eq 0 ; then
    AC_MSG_ERROR([unknown])
fi
if test $hitcnt -gt 1 ; then
    AC_MSG_ERROR([ambiguous])
fi

# Check for vfs_readdir (only for kernels older than 3.11.0)
if test $((kern_version_code)) -lt 199424; then
    TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath)
    AC_MSG_CHECKING([for vfs_readdir])
    ${EGREP} vfs_readdir $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
    if test $? -eq 0; then
        AC_SUBST(vfsreaddir, "-DTALPA_VFSREADDIR")
        AC_MSG_RESULT([present])
    else
        AC_MSG_RESULT([not present])
    fi
fi

# Check for snprintf only for kernels older than 2.4.10
if test $((kern_version_code)) -lt 132106; then
    TALPA_LOCATE_HEADER(linux/kernel.h, $kernelhdrspath)
    AC_MSG_CHECKING([for snprintf])
    ${EGREP} snprintf $TALPA_HEADER_LOCATION/linux/kernel.h >/dev/null 2>&1
    if test $? -eq 0; then
        AC_MSG_RESULT([present])
        AC_SUBST(snprintf,"-DTALPA_HAS_SNPRINTF")
    else
        AC_MSG_RESULT([not present])
    fi
fi
TALPA_LOCATE_HEADER(linux/string.h, $kernelhdrspath)
AC_MSG_CHECKING([for strndup_user])
${EGREP} strndup_user $TALPA_HEADER_LOCATION/linux/string.h >/dev/null 2>&1
if test $? -eq 0; then
    AC_MSG_RESULT([present])
    AC_SUBST(strdupuser,"-DTALPA_HAS_STRNDUP_USER")
else
    AC_MSG_RESULT([not present])
fi

# Check for tasklist_lock export
if test "$auto_notasklistlock" = "yes"; then
    AC_MSG_CHECKING([for tasklist_lock export])
    ## 2.6.0+
    if test $((kern_version_code)) -ge 132608; then
        ## 2.6.18+
        if test $((kern_version_code)) -ge 132626; then
            AC_SUBST(notasklistlock,"-DTALPA_NO_TASKLIST_LOCK")
            AC_MSG_RESULT([not available])
        elif test -f $kerneldir/kernel/fork.c; then
            ${EGREP} EXPORT_SYMBOL\\\(tasklist_lock\\\)\; $kerneldir/kernel/fork.c >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([available])
            else
                AC_SUBST(notasklistlock,"-DTALPA_NO_TASKLIST_LOCK")
                AC_MSG_RESULT([not available])
            fi
        elif test -f $sourcedir/kernel/fork.c; then
            ${EGREP} EXPORT_SYMBOL\\\(tasklist_lock\\\)\; $sourcedir/kernel/fork.c >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([available])
            else
                AC_SUBST(notasklistlock,"-DTALPA_NO_TASKLIST_LOCK")
                AC_MSG_RESULT([not available])
            fi
        else
            AC_MSG_RESULT([unknown, assuming available])
        fi
    else
        AC_MSG_RESULT([available (2.4)])
    fi
fi

# Find tasklist_lock address if not exported
if test "$notasklistlock" != ""; then
    AC_MSG_CHECKING([for tasklist_lock address])
    tasklist_lock_addr=`${EGREP} " tasklist_lock\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
    if test "$tasklist_lock_addr" != ""; then
        AC_MSG_RESULT([0x$tasklist_lock_addr])
        AC_SUBST(notasklistlock, "$notasklistlock -DTALPA_TASKLIST_LOCK_ADDR=0x${tasklist_lock_addr}UL")
    else
        AC_MSG_ERROR([not found])
    fi
fi

TALPA_LOCATE_HEADER(linux/uaccess.h, $kernelhdrspath, uaccessfound=yes, uaccessfound=no)
echo $uaccessfound
if test $uaccessfound == "yes"
then
    AC_MSG_CHECKING([for probe_kernel_read])
    ${EGREP} probe_kernel_read $TALPA_HEADER_LOCATION/linux/uaccess.h >/dev/null 2>&1
    if test $? -eq 0
    then
        AC_MSG_RESULT([present])
        AC_SUBST(probe_kernel_read,"-DTALPA_HAS_PROBE_KERNEL_READ")
    else
        AC_MSG_RESULT([not present])
    fi
fi

function find_syscall_table
{
    sys_call_table=`${EGREP} " sys_call_table\$" "$1" 2>/dev/null | ${CUT} -d ' ' -f 1`
    if test "$sys_call_table" = ""; then
        return 1
    fi

    march=`${UNAME} -m`
    if test "$march" = "x86_64"; then
        sys_call_table32=`${EGREP} " ia32_sys_call_table\$" "$1" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test "$sys_call_table32" = ""; then
            return 1
        fi

        # If passed through environment do nothing since makefile will handle that
        if test "$TALPA_SYSCALL_TABLE" = "" -a "$TALPA_SYSCALL32_TABLE" = ""; then
            FIND_SYSCALL_TABLE_RESULT="-DTALPA_SYSCALL_TABLE=0x${sys_call_table}UL -DTALPA_SYSCALL32_TABLE=0x${sys_call_table32}UL"
            return 0
        fi

        return 1
    fi

    if test "$TALPA_SYSCALL_TABLE" = ""; then
        FIND_SYSCALL_TABLE_RESULT="-DTALPA_SYSCALL_TABLE=0x${sys_call_table}UL"
        return 0
    fi

    return 1
}

AC_MSG_CHECKING([for appropriate build system])
# 2.6.0+
if test $((kern_version_code)) -ge 132608; then
    AC_MSG_RESULT([2.6 build system detected])
    AC_SUBST(ko,ko)
    AC_SUBST(talpaversion, "-DTALPA_VERSION=\\\\\"${PACKAGE_VERSION}\\\\\"")
    # Test whether kbuild uses M= or SUBDIRS=, 2.6.8 was the first kernel to use M=
    AM_CONDITIONAL(KBUILDUSEM, test $((kern_version_code)) -ge 132616)

    AC_SUBST(hidden,"-DTALPA_HIDDEN_SYSCALLS")
    if find_syscall_table "$system_map"; then
        AC_SUBST(hidden,"${hidden} ${FIND_SYSCALL_TABLE_RESULT}")
    fi

    DCACHE_SOURCE_FILE="$kerneldir/fs/dcache.c"
    test -f "$DCACHE_SOURCE_FILE" || DCACHE_SOURCE_FILE="$sourcedir/fs/dcache.c"
    test -f "$DCACHE_SOURCE_FILE" || DCACHE_SOURCE_FILE=""

    CALLING_REAL_DPATH=0

    # Check for exported __d_path and prototype availablity
    if test "$auto_dpath" = "yes"; then
        TALPA_LOCATE_HEADER(linux/dcache.h, $kernelhdrspath)
        AC_MSG_CHECKING([for __d_path prototype])
        if ${EGREP} "extern.*__d_path" $TALPA_HEADER_LOCATION/linux/dcache.h >/dev/null 2>&1; then
            AC_MSG_RESULT([available])
            AC_MSG_CHECKING([for exported __d_path])
            if test -f "$DCACHE_SOURCE_FILE"; then
                ${EGREP} EXPORT_SYMBOL\\\(__d_path\\\)\; "$DCACHE_SOURCE_FILE" >/dev/null 2>&1
                if test $? -ne 0; then
                    AC_MSG_RESULT([hidden])
                else
                    AC_SUBST(dpath,"-DTALPA_HAS_DPATH -DTALPA_HAS_DPATH_EXPORT")
                    AC_MSG_RESULT([exported])
                    CALLING_REAL_DPATH=1
                fi
            else
                AC_MSG_RESULT([undetectable])
            fi
        else
            AC_MSG_RESULT([not available])
        fi
    fi

    TALPA_LOCATE_HEADER(linux/dcache.h, $kernelhdrspath)
    AC_MSG_CHECKING([for 2.6.38 style locking])
    if ${EGREP} "seqcount_t d_seq;" $TALPA_HEADER_LOCATION/linux/dcache.h >/dev/null 2>&1; then
        AC_MSG_RESULT([post 2.6.38 style locking])
        HOLD_DCACHE_LOCK_WHILE_CALLING_D_PATH=0
    else
        AC_MSG_RESULT([pre 2.6.38 style locking])
        ## Determine if we should take the dcache_lock outside the __d_path function
        AC_MSG_CHECKING([for taking dcache_lock outside __d_path])
        if test -f "$DCACHE_SOURCE_FILE" ; then
            ${EGREP} -1 "spin_lock\(&vfsmount_lock\);" "$DCACHE_SOURCE_FILE" | ${EGREP} "spin_lock\(&dcache_lock\);" >/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([take lock])
                HOLD_DCACHE_LOCK_WHILE_CALLING_D_PATH=1
            else
                AC_MSG_RESULT([don't take lock]) ## '
                HOLD_DCACHE_LOCK_WHILE_CALLING_D_PATH=0
            fi
        else
            AC_MSG_RESULT([undetectable: assume take lock])
            HOLD_DCACHE_LOCK_WHILE_CALLING_D_PATH=1
        fi
    fi

    if test $HOLD_DCACHE_LOCK_WHILE_CALLING_D_PATH -eq 1 ; then
        AC_SUBST(dpath, "$dpath -DHOLD_DCACHE_LOCK_WHILE_CALLING_D_PATH")
    else
        ## We're not going to hold the lock - so we'd better be calling the real __d_path

        if test "$CALLING_REAL_DPATH" -eq 0 ; then
            AC_MSG_CHECKING([for __d_path address])
            d_path_addr=`${EGREP} " __d_path\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
            if test "$d_path_addr" != ""; then
                CALLING_REAL_DPATH=1
                AC_MSG_RESULT([0x$d_path_addr])
                AC_SUBST(dpath, "$dpath -DTALPA_HAS_DPATH -DTALPA_HAS_DPATH_ADDR -DTALPA_DPATH_ADDR=0x${d_path_addr}UL")
            else
                AC_MSG_ERROR([not found])
            fi
        fi
    fi


    # If __d_path is exported determine it's prototype
    if test "$CALLING_REAL_DPATH" -eq 1 ; then
        TALPA_LOCATE_HEADER(linux/dcache.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
        AC_MSG_CHECKING([for __d_path type])
        let hitcnt=0
        ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dpath.c -o /dev/null 1>/dev/null 2>&1
        if test $? -eq 0; then
            let hitcnt=$hitcnt+1
            AC_SUBST(dpath, "$dpath -DTALPA_DPATH_STANDARD")
            AC_MSG_RESULT([standard])
        fi
        ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dpathpath.c -o /dev/null 1>/dev/null 2>&1
        if test $? -eq 0; then
            let hitcnt=$hitcnt+1
            AC_SUBST(dpath, "$dpath -DTALPA_DPATH_PATH")
            AC_MSG_RESULT([struct path])
        fi
        ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dpathsuse103.c -o /dev/null 1>/dev/null 2>&1
        if test $? -eq 0; then
            let hitcnt=$hitcnt+1
            AC_SUBST(dpath, "$dpath -DTALPA_DPATH_SUSE103")
            AC_MSG_RESULT([suse103])
        fi
        ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/dpathsles11.c -o /dev/null 1>/dev/null 2>&1
        if test $? -eq 0; then
            let hitcnt=$hitcnt+1
            AC_SUBST(dpath, "$dpath -DTALPA_DPATH_SLES11")
            AC_MSG_RESULT([sles11])
        fi
        if test $hitcnt -eq 0 ; then
            AC_MSG_ERROR([unknown])
        fi
        if test $hitcnt -gt 1 ; then
            AC_MSG_ERROR([ambiguous])
        fi
    fi

    AC_MSG_CHECKING([for vfsmount and br lock])
    vfsmount_lock_lock=`${EGREP} "[[VDd]] vfsmount_lock_lock\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
    lg_local_lock=`${EGREP} " lg_local_lock\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
    mount_lock=`${EGREP} " mount_lock\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`

    if test x"$vfsmount_lock_lock" != x""  && test "$lg_local_lock" == ""  ; then
        AC_MSG_RESULT([vfsmount lock is BRLOCK])
        AC_SUBST(vfsmntlock, "-DTALPA_USE_VFSMOUNT_LOCK -DTALPA_VFSMOUNT_LOCK_BRLOCK")
    elif test x"$vfsmount_lock_lock" != x""  && test "$lg_local_lock" != ""  ; then
        AC_MSG_RESULT([vfsmount lock is LG_BRLOCK])
        AC_SUBST(vfsmntlock, "-DTALPA_USE_VFSMOUNT_LOCK -DTALPA_VFSMOUNT_LG_BRLOCK")
    elif test x"$mount_lock" != x"" ; then
        AC_MSG_RESULT([vfsmount lock is mount_lock seqlock])
        AC_SUBST(vfsmntlock, "-DTALPA_USE_MOUNT_LOCK -DTALPA_MOUNT_LOCK_ADDR=0x${mount_lock}UL")
    elif test x"$vfsmount_lock_lock" == x"" ; then
        AC_MSG_RESULT([vfsmount lock is spinlock])
        # Find vfsmnt_lock address
        AC_MSG_CHECKING([for vfsmount_lock address])
        vfsmnt_lock_addr=`${EGREP} " vfsmount_lock\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test "$vfsmnt_lock_addr" != ""; then
            AC_MSG_RESULT([0x$vfsmnt_lock_addr])
            AC_SUBST(vfsmntlock, "-DTALPA_USE_VFSMOUNT_LOCK -DTALPA_VFSMOUNT_LOCK_ADDR=0x${vfsmnt_lock_addr}UL")
        else
            AC_MSG_ERROR([not found])
        fi
    else
        AC_MSG_ERROR([not found])
    fi

    if test $((kern_version_code)) -ge 199936; then
        ## 3.13+
        ## Needed to count mount points
        AC_MSG_CHECKING([for __lookup_mnt_last address])
        lookup_mnt_last_val=`${EGREP} " __lookup_mnt_last\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test x"$lookup_mnt_last_val" != x""
        then
            AC_MSG_RESULT([0x$lookup_mnt_last_val])
            AC_SUBST(lookup_mnt_last, "-DTALPA_SHARED_MOUNTS -DTALPA_HAVE_LOOKUP_MNT_LAST -DTALPA__LOOKUP_MNT_LAST=0x${lookup_mnt_last_val}UL")
        else
            AC_MSG_RESULT([not found])
            AC_MSG_CHECKING([for __lookup_mnt address])
            lookup_mnt_val=`${EGREP} " __lookup_mnt\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
            if test x"$lookup_mnt_val" != x""
            then
                AC_MSG_RESULT([0x$lookup_mnt_val])
                AC_SUBST(lookup_mnt_last, "-DTALPA_SHARED_MOUNTS -DTALPA_HAVE_LOOKUP_MNT2 -DTALPA__LOOKUP_MNT=0x${lookup_mnt_val}UL")
            else
                AC_MSG_ERROR([not found])
            fi
        fi
    elif test $((kern_version_code)) -ge 132623; then
        ## 2.6.15 - 3.12
        AC_MSG_CHECKING([for __lookup_mnt address])
        lookup_mnt_val=`${EGREP} " __lookup_mnt\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test x"$lookup_mnt_val" != x""
        then
            AC_MSG_RESULT([0x$lookup_mnt_val])
            AC_SUBST(lookup_mnt_last, "-DTALPA_SHARED_MOUNTS -DTALPA_HAVE_LOOKUP_MNT -DTALPA__LOOKUP_MNT=0x${lookup_mnt_val}UL")
        else
            AC_MSG_ERROR([not found])
        fi
    else
        AC_SUBST(lookup_mnt_last, "")
    fi

    if test $((kern_version_code)) -lt 199936; then
        ## < 3.13.0
        TALPA_LOCATE_HEADER(linux/fs_struct.h, $kernelhdrspath)
        AC_MSG_CHECKING([for get_fs_root_and_pwd function])
        if ${EGREP} "void get_fs_root_and_pwd\(" $TALPA_HEADER_LOCATION/linux/fs_struct.h >/dev/null 2>&1; then
            AC_MSG_RESULT([system has get_fs_root_and_pwd])
            AC_SUBST(get_fs_root_and_pwd, "-DTALPA_SYSTEM_GET_FS_ROOT_AND_PWD")
        else
            AC_MSG_RESULT([system does not have get_fs_root_and_pwd])
            AC_SUBST(get_fs_root_and_pwd, "")
        fi
    else
        AC_MSG_RESULT([assuming system does not have get_fs_root_and_pwd])
        AC_SUBST(get_fs_root_and_pwd, "")
    fi

    if test $((kern_version_code)) -ge 132623; then
        ## 2.6.15+
        # vfsmount's namespace element changed from mnt_namespace to mnt_ns in 2.6.20
        TALPA_LOCATE_HEADER(linux/mount.h, $kernelhdrspath)
        AC_MSG_CHECKING([for vfsmount mnt_namespace element])
        if ${EGREP} "struct namespace \*mnt_namespace;" $TALPA_HEADER_LOCATION/linux/mount.h >/dev/null 2>&1; then
            AC_MSG_RESULT([vfsmount has mnt_namespace])
            AC_SUBST(vfsmount_namespace, "-DTALPA_VFSMOUNT_NAMESPACE=mnt_namespace")
        else
            AC_MSG_RESULT([assuming vfsmount has mnt_ns])
            AC_SUBST(vfsmount_namespace, "-DTALPA_VFSMOUNT_NAMESPACE=mnt_ns")
        fi
    else
        AC_SUBST(vfsmount_namespace, "")
    fi

    # Autodetect if we are running on 2.6.5 with backported sched.h
    if test $((kern_version_code)) -le 132613; then
        if test "$auto_tasknewtty" = "yes"; then
            TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
            AC_MSG_CHECKING([for backported sched.h])
            ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/tasktty.c -o /dev/null 1>/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(tasknewtty,"-DTALPA_HAS_TASK_NEW_TTY")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if rcupdate.h was backported
    # <2.6.12
    if test $((kern_version_code)) -lt 132620; then
        if test "$auto_rcubackport" = "yes"; then
            AC_MSG_CHECKING([for backported rcupdate.h])
            ${EGREP} "deprecated.*synchronize_kernel" $TALPA_HEADER_LOCATION/linux/rcupdate.h >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(rcubackport,"-DTALPA_HAS_BACKPORTED_RCU")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if mutexes were backported
    # <2.6.16
    if test $((kern_version_code)) -lt 132624; then
        if test "$auto_mutexbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/mutex.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
            AC_MSG_CHECKING([for backported mutexes])
            if ${EGREP} -q "struct mutex" "$TALPA_HEADER_LOCATION/linux/mutex.h" 2>/dev/null; then
                AC_MSG_RESULT([detected])
                AC_SUBST(mutexes,"-DTALPA_HAS_MUTEXES")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    else
        # Kernels starting with 2.6.16 have them
        AC_SUBST(mutexes,"-DTALPA_HAS_MUTEXES")
    fi

    # Check for nested mutex support
    if test "$mutexes" != ""; then
        AC_MSG_CHECKING([for nested mutexes])
        if ${EGREP} -q "mutex_lock_nested" "$TALPA_HEADER_LOCATION/linux/mutex.h" 2>/dev/null; then
            AC_MSG_RESULT([present])
            AC_SUBST(mutexes,"$mutexes -DTALPA_HAS_NESTED_MUTEX")
        else
            AC_MSG_RESULT([not present])
        fi
    fi

    # Autodetect if struct inode uses mutexes
    # < 2.6.16
    TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
    ${EGREP} " inode_lock_nested" $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
    if test $? -eq 0; then
        AC_SUBST(inodemutex,"-DTALPA_INODE_USES_INODE_LOCK")
    elif test "$mutexes" != ""
    then
        if test $((kern_version_code)) -lt 132624
        then
            if test "$auto_inodemutex" = "yes"; then
                AC_MSG_CHECKING([for i_mutex inode struct member])
                ${EGREP} i_mutex\; $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
                if test $? -eq 0; then
                    AC_MSG_RESULT([detected])
                    AC_SUBST(inodemutex,"-DTALPA_INODE_USES_MUTEXES")
                else
                    AC_MSG_RESULT([not detected])
                    AC_SUBST(inodemutex,"-DTALPA_INODE_USES_SEMAPHORES")
                fi
            fi
        else
            # Kernels starting with 2.6.16 use them
            AC_SUBST(inodemutex,"-DTALPA_INODE_USES_MUTEXES")
        fi
    else
        AC_SUBST(inodemutex,"-DTALPA_INODE_USES_SEMAPHORES")
    fi


    # Autodetect if fdentry is defined in fs structure
    TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
    AC_MSG_CHECKING([for f_dentry in fs struct member])
    ${EGREP} f_dentry $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
    if test $? -eq 0; then
        AC_MSG_RESULT([detected])
        AC_SUBST(fdentry,"-DTALPA_FDENTRY_DEFINED")
    else
        AC_MSG_RESULT([not detected])
    fi

    # Autodetect if struct inode has i_private field
    # < 2.6.19
    if test $((kern_version_code)) -lt 132627; then
        if test "$auto_inodeiprivate" = "yes"; then
            TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
            AC_MSG_CHECKING([for i_private inode struct member])
            ${EGREP} i_private\; $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(inodeiprivate,"-DTALPA_INODE_I_PRIVATE")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if task_struct->signal was backported
    # < 2.6.12
    if test $((kern_version_code)) -lt 132620; then
        if test "$auto_signalbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
            AC_MSG_CHECKING([for backported task_struct->signal])
            ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/tasksignal.c -o /dev/null 1>/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(signalbackport,"-DTALPA_HAS_BACKPORTED_SIGNAL")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if msecs_to_jiffies was backported
    # < 2.6.7
    if test $((kern_version_code)) -lt 132615; then
        if test "$auto_jiffiesbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/time.h, $kernelhdrspath)
            TALPA_LOCATE_HEADER(linux/jiffies.h, $kernelhdrspath)
            AC_MSG_CHECKING([for backported msecs_to_jiffies])
            ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/msecstojiffies.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(jiffiesbackport,"-DTALPA_HAS_BACKPORTED_JIFFIES")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if filldir_t was backported
    # < 2.6.19
    if test $((kern_version_code)) -lt 132627; then
        if test "$auto_filldirbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath, , ,[quiet])
            AC_MSG_CHECKING([for backported filldir])
            ${EGREP} "filldir_t.*u64" $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(filldirbackport,"-DTALPA_HAS_BACKPORTED_FILLDIR")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if RCU in struct mount was backported
    # < 3.13.0
    if test $((kern_version_code)) -lt 199936; then
        if test "$auto_mountrcubackport" = "yes"; then
            AC_MSG_CHECKING([for backported mount rcu])
            if test "$rhel_release" = "yes"; then
                ## 7.4
                if test $((rhel_release_code)) -ge 1796; then
                    AC_MSG_RESULT([detected])
                    AC_SUBST(mountrcubackport,"-DTALPA_HAS_BACKPORTED_MOUNTRCU")
                else
                    AC_MSG_RESULT([not detected])
                fi
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Detect whether smbfs is present
    AC_MSG_CHECKING([for smbfs])
    TALPA_LOCATE_HEADER(linux/smb_fs.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
    if test $? -eq 0; then
        AC_MSG_RESULT([present])
        AC_SUBST(smbfs,"-DTALPA_HAS_SMBFS")
    else
        AC_MSG_RESULT([not present])
    fi

    # Check how to build syscallhook dependent modules and if possible at all
    AC_MSG_CHECKING([for system call table hooking support])
    TALPA_LOCATE_HEADER($autoconf_h, $kernelhdrspath, , , [quiet])
    ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/rodata.c -o tests/configure/rodata
    tests/configure/rodata
    rodatarc=$?
    if test $rodatarc -eq 0; then
        AC_SUBST(syscallhook, "yes")

        ${CC} -Werror-implicit-function-declaration -c ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/probe_kernel_write.c -o tests/configure/probe_kernel_write >/dev/null 2>&1
        probe=$?
        if test $probe -eq 0
        then
            AC_SUBST(rodata, "-DTALPA_RODATA_MAP_WRITABLE -DTALPA_HAS_PROBE_KERNEL_WRITE")
            AC_SUBST(map_writable, yes)
            AC_MSG_RESULT([yes - kernel writable - has probe_kernel_write - shadow mapping])
        else
            AC_MSG_RESULT([yes - kernel writable])
        fi
    else
        # Detect SLES11 kernels
        # Blacklist openSUSE 11.3 release
        kern_release=`$UNAME -r`
        if test "$kern_release" != "2.6.34-12-desktop"; then
            kfunc_mark_rodata_rw=`${EGREP} " mark_rodata_rw\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
            kfunc_mark_rodata_ro=`${EGREP} " mark_rodata_ro\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
        fi
        ## Kernel's >= 3.0.0 don't seem to work with SuSE's functions (SLES 11 SP2)
        if test "$kfunc_mark_rodata_rw" != "" -a "$kfunc_mark_rodata_ro" != "" -a $((kern_version_code)) -lt 196608 ; then
            # First SLES11 release on x86_64 does not work
            if test "$kern_arch" = "x86_64" -a "$kern_uts_release" = "2.6.27.19-5-default"; then
                AC_MSG_ERROR([unsupported kernel])
            else
                has_mark_rodata_rw="yes"
                AC_SUBST(rodata, "-DTALPA_HAS_RODATA -DTALPA_HAS_MARK_RODATA_RW")
                AC_SUBST(syscallhook, "yes")
                AC_MSG_RESULT([yes, sles11])
            fi
        else
            # If passed through environment do nothing since makefile will handle that
            if test "$TALPA_RODATA_START" = "" -a "$TALPA_RODATA_END" = ""; then
                start_rodata=`${EGREP} " __start_rodata\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                end_rodata=`${EGREP} " __end_rodata\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                if test "$start_rodata" != "" -a "$end_rodata" != ""; then
                    AC_SUBST(syscallhook, "yes")
                    AC_SUBST(rodata, "-DTALPA_HAS_RODATA -DTALPA_NEED_MANUAL_RODATA -DTALPA_RODATA_START=0x${start_rodata}UL -DTALPA_RODATA_END=0x${end_rodata}UL")
                    ## >= 2.6.25
                    if test $((kern_version_code)) -ge 132633; then
                        AC_SUBST(rodata, "$rodata -DTALPA_RODATA_MAP_WRITABLE -DTALPA_HAS_PROBE_KERNEL_WRITE")
                        AC_SUBST(map_writable, yes)
                        AC_MSG_RESULT([yes; shadow mapping])
                    else
                        AC_MSG_RESULT([yes])
                    fi
                else
                    AC_MSG_RESULT([no])
                    AC_SUBST(syscallhook, "no")
                fi
            else
                AC_MSG_RESULT([yes])
                AC_SUBST(syscallhook, "yes")
                AC_SUBST(rodata, "-DTALPA_HAS_RODATA -DTALPA_NEED_MANUAL_RODATA")
            fi
        fi
    fi
    ${RM} -f tests/configure/rodata

    if test "$syscallhook" = "yes" -a "$has_mark_rodata_rw" = "" -a "$map_writable" = "" -a "$rodata" != ""; then
        # Check whether to use set_page_XXX or change_page_attr functions
        TALPA_LOCATE_HEADER(asm/cacheflush.h, $kernelhdrspath, , , [quiet])
        AC_MSG_CHECKING([for set_pages/memory interface])
        if ${EGREP} set_pages_rw $TALPA_HEADER_LOCATION/asm/cacheflush.h >/dev/null 2>&1; then
            AC_MSG_RESULT([present])
            if test "$kern_arch" = "x86_64"; then
                AC_MSG_CHECKING([for set_memory symbols])
                kfunc_set_memory_rw=`${EGREP} " set_memory_rw\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                kfunc_set_memory_ro=`${EGREP} " set_memory_ro\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                if test "$kfunc_set_memory_rw" != "" -a "$kfunc_set_memory_ro" != ""; then
                    AC_MSG_RESULT([ok])
                    AC_SUBST(hassetpages, "-DTALPA_HAS_SET_PAGES -DTALPA_KFUNC_SET_MEMORY_RW=0x${kfunc_set_memory_rw}UL -DTALPA_KFUNC_SET_MEMORY_RO=0x${kfunc_set_memory_ro}UL")
                else
                    AC_MSG_ERROR([failed to get])
                fi
            else
                AC_MSG_CHECKING([for set_pages symbols])
                kfunc_set_pages_rw=`${EGREP} " set_pages_rw\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                kfunc_set_pages_ro=`${EGREP} " set_pages_ro\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                if test "$kfunc_set_pages_rw" != "" -a "$kfunc_set_pages_ro" != ""; then
                    AC_MSG_RESULT([ok])
                    AC_SUBST(hassetpages, "-DTALPA_HAS_SET_PAGES -DTALPA_KFUNC_SET_PAGES_RW=0x${kfunc_set_pages_rw}UL -DTALPA_KFUNC_SET_PAGES_RO=0x${kfunc_set_pages_ro}UL")
                else
                    AC_MSG_ERROR([failed to get])
                fi
            fi
        else # old change_page_attr_addr interface
            AC_MSG_RESULT([not present])
            # Get change_page_attr_addr on x86_64
            if test "$kern_arch" = "x86_64"; then
                AC_MSG_CHECKING([for change_page_attr_addr symbol])
                kfuncchpgattraddr=`${EGREP} " change_page_attr_addr\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                if test "$kfuncchpgattraddr" != ""; then
                    AC_MSG_RESULT([ok])
                    AC_SUBST(kfuncchpgattraddr, "-DTALPA_KFUNC_CHANGE_PAGE_ATTR_ADDR=0x${kfuncchpgattraddr}UL")
                else
                    AC_MSG_ERROR([failed to get])
                fi
                # Check for RHEL 5 kernels which need special handling
                AC_MSG_CHECKING([for type of addressed passed to change_page_attr_addr])
                TALPA_LOCATE_HEADER(asm/const.h, $kernelhdrspath, constheader=yes, constheader=no, [quiet])
                if test "$constheader" = "yes"; then
                    AC_MSG_RESULT([virtual])
                    AC_SUBST(needsvacpa, "-DTALPA_NEEDS_VA_CPA")
                    AC_MSG_CHECKING([if __pa_symbol is available])
                    TALPA_LOCATE_HEADER(asm/page.h, $kernelhdrspath, , , [quiet])
                    if ${EGREP} "v - __START_KERNEL_map.*phys_base" $TALPA_HEADER_LOCATION/asm/page.h >/dev/null 2>&1; then
                        AC_MSG_RESULT([no])
                        AC_MSG_CHECKING([for phys_base address])
                        phys_base=`${EGREP} " phys_base\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                        if test "$phys_base" != ""; then
                            AC_MSG_RESULT([ok])
                            AC_SUBST(nopasymbol, "-DTALPA_NO_PA_SYMBOL -DTALPA_PHYS_BASE=0x${phys_base}UL")
                        else
                            AC_MSG_ERROR([error])
                        fi
                    else
                        AC_MSG_RESULT([yes])
                    fi
                else
                    AC_MSG_RESULT([logical])
                fi
            fi
        fi
    fi

    if test "$syscallhook" = "no" -a "$interceptor_module" != "lsm"; then
        AC_SUBST(interceptor_module,lsm)
        AC_SUBST(interceptor_name,LSMInterceptor)
    fi

    # Check whether to build LSM related modules
    AC_MSG_CHECKING([for LSM support])
    if test "$auto_lsm" = "yes"; then
        # First check if LSM supports modules
        TALPA_LOCATE_HEADER(linux/security.h, $kernelhdrspath, , , [quiet])
        if ${EGREP} unregister_security $TALPA_HEADER_LOCATION/linux/security.h >/dev/null 2>&1; then
            TALPA_LOCATE_HEADER($autoconf_h, $kernelhdrspath, , , [quiet])
            ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/lsm.c -o tests/configure/lsm
            tests/configure/lsm
            if test $? -eq 0; then
                AC_MSG_RESULT([present])
                AC_SUBST(lsm, "yes")
                AM_CONDITIONAL(BUILDLSM, test 1 -eq 1)
                # Autodetect if we are compiling for a 2.6.0-test in which case we will disable LSM modules
                if test $((kern_version_code)) -eq 132608; then
                    AC_MSG_CHECKING([for 2.6.0-test kernel])
                    echo ${kern_uts_release} | ${EGREP} test >/dev/null 2>&1
                    if test $? -eq 0; then
                        AC_MSG_RESULT([disabling LSM modules])
                        AC_SUBST(lsm, "no")
                        AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
                    else
                        AC_MSG_RESULT([everything is fine])
                    fi
                fi
            else
                AC_MSG_RESULT([not present])
                AC_SUBST(lsm, "no")
                AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
            fi
            ${RM} -f tests/configure/lsm
        else
            AC_MSG_RESULT([static only, disabling])
            AC_SUBST(lsm, "no")
            AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
        fi
    else
        if test "$lsm" = "yes"; then
            AC_MSG_RESULT([forced])
            AC_SUBST(lsm, "yes")
            AM_CONDITIONAL(BUILDLSM, test 1 -eq 1)
        else
            AC_MSG_RESULT([disabled])
            AC_SUBST(lsm, "no")
            AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
        fi
    fi

    if test "$lsm" = "yes"; then
        # Autodetect LSM backports
        TALPA_LOCATE_HEADER(linux/security.h, $kernelhdrspath)

        # Autodetect if LSM has key support
        if test "$auto_lsmkeys" = "yes"; then
            AC_MSG_CHECKING([for LSM key support])
            ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/lsmkeys.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(lsmkeys,"-DTALPA_HAS_LSM_KEYS")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi

        # <= 2.6.13
        if test $((kern_version_code)) -le 132621; then
            # Autodetect if LSM from 2.6.14 is backported to the earlier version
            if test "$auto_lsm2614" = "yes"; then
                AC_MSG_CHECKING([for 2.6.14 LSM])
                ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/lsm2614.c -o /dev/null 1>/dev/null 2>&1
                if test $? -eq 0; then
                    AC_MSG_RESULT([detected])
                    AC_SUBST(lsm2614,"-DTALPA_HAS_2614_LSM")
                else
                    AC_MSG_RESULT([not detected])
                fi
            fi
        fi

        ## <= 2.6.9
        if test $((kern_version_code)) -le 132617; then
            # Autodetect if LSM from 2.6.10 is backported to 2.6.9
            if test "$auto_lsm2610" = "yes"; then
                AC_MSG_CHECKING([for 2.6.10 LSM])
                ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/lsm2610.c -o /dev/null 1>/dev/null 2>&1
                if test $? -eq 0; then
                    AC_MSG_RESULT([detected])
                    AC_SUBST(lsm2610,"-DTALPA_HAS_2610_LSM")
                else
                    AC_MSG_RESULT([not detected])
                fi
            fi
        fi

        ## <= 2.6.5
        if test $((kern_version_code)) -le 132613; then
            # Autodetect if LSM from 2.6.6 is backported to 2.6.5
            if test "$auto_lsm266" = "yes"; then
                AC_MSG_CHECKING([for 2.6.6 LSM])
                ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/lsm266.c -o /dev/null 1>/dev/null 2>&1
                if test $? -ne 0; then
                    AC_MSG_RESULT([detected])
                    AC_SUBST(lsm266,"-DTALPA_HAS_266_LSM")
                else
                    AC_MSG_RESULT([not detected])
                fi
            fi

            # Autodetect if LSM from 2.6.5 is backported to 2.6.4
            if test $((kern_version_code)) -le 132612 -a $((kern_version_code)) -ge 132611; then
                if test "$auto_lsm265" = "yes"; then
                    AC_MSG_CHECKING([for 2.6.5 LSM])
                    ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/lsm265.c -o /dev/null 1>/dev/null 2>&1
                    if test $? -ne 0; then
                        AC_MSG_RESULT([detected])
                        AC_SUBST(lsm265,"-DTALPA_HAS_265_LSM")
                    else
                        AC_MSG_RESULT([not detected])
                    fi
                fi
            fi

        fi
    else
        # Do not run test with LSM inteceptor if it will not be built
        if test "$interceptor_module" = "lsm"; then
            AC_SUBST(interceptor_module,vfshook)
            AC_SUBST(interceptor_name,VFSHookInterceptor)
        fi
    fi

    # Check for hrtimers presence
    if test "$auto_hrtimers" = "yes"; then
        # Vanilla 2.6.16 has hrtimers but no exports. However, backports can exist.
        # Vanilla 2.6.17 exports the needed symbols but again handle backports as well.
        AC_MSG_CHECKING([for exported hrtimers])
        ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/hrtimersversion17.c -o /dev/null 1>/dev/null 2>&1
        if test $? -eq 0; then
            AC_SUBST(hrtimers,"-DTALPA_HAS_HRTIMERS")
            ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/hrtimersversion21.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_SUBST(hrtimers,"$hrtimers -DTALPA_HAS_HRTIMERS_V21")
            fi
            AC_MSG_RESULT([present])
        else
            AC_MSG_RESULT([missing])
        fi
    fi

    ## Hook d_ops on 2.6.32 (RHEL6,SLES11SP1,OEL6) and above by default
    ## And on 2.6.18 and above to support NFS v3 on empty file systems, or with root_squash
    if test "$auto_hookdops" = yes ; then
        if test $((kern_version_code)) -ge 132626; then
            AC_SUBST(hookdops,"-DTALPA_CONFIG_HOOK_DOPS")
        fi
    fi

    # Check whether xhack can be implemented
    if test "$auto_xhack" = "yes"; then
        if test "$hrtimers" = ""; then
            ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure -c ${srcdir}/tests/configure/hrtimersversion16.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_SUBST(xhack,"")
            fi
        fi
    fi

    AC_MSG_CHECKING([for struct filename])
    if test "$auto_struct_filename" == "yes"
    then
        TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath, , , [quiet])
        if ${EGREP} "struct filename" $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
        then
            AC_SUBST(structfilename,"-DTALPA_HAS_STRUCT_FILENAME")
            AC_MSG_RESULT([present])
        else
            AC_MSG_RESULT([not present])
        fi
    else
        if test "$structfilename" = "-DTALPA_HAS_STRUCT_FILENAME"; then
            AC_MSG_RESULT([forced])
        else
            AC_MSG_RESULT([disabled])
        fi
    fi

    TALPA_LOCATE_HEADER(asm-generic/fcntl.h, $kernelhdrspath, asmgenericfctntlfound=yes, asmgenericfctntlfound=no)
    if test "$asmgenericfctntlfound" = "yes" ; then
        kernccflags="${kernccflags} -DTALPA_HAS_ASM_GENERIC_FCNTL"
        asmgenericfcntl="-DTALPA_HAS_ASM_GENERIC_FCNTL"
        AC_MSG_RESULT([yes])
    else
        asmgenericfcntl=""
        AC_MSG_RESULT([no])
    fi

    AC_MSG_CHECKING([for correct getname])
    ${CC} -c ${kernccflags} $structfilename -Werror TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/structfilename.c
    if test $? -eq 0
    then
        AC_MSG_RESULT([passed])
    else
        AC_MSG_ERROR([failed])
    fi

    # Check whether to use securityfs
    AC_MSG_CHECKING([for securityfs support])
    if test "$auto_securityfs" = "yes"; then
        TALPA_LOCATE_HEADER(linux/security.h, $kernelhdrspath, , , [quiet])
        # Kernel knows about securityfs at all?
        if ${EGREP} securityfs_remove $TALPA_HEADER_LOCATION/linux/security.h >/dev/null 2>&1; then
            if ${EGREP} CONFIG_SECURITYFS $TALPA_HEADER_LOCATION/linux/security.h >/dev/null 2>&1; then
                # Latest flavour with separate config option, is it enabled?
                ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/securityfs.c -o tests/configure/securityfs
                if ! tests/configure/securityfs; then
                    AC_SUBST(buildsecurityfs, "yes")
                else
                    AC_MSG_RESULT([not enabled])
                fi
            else
                # Security implies securityfs, is it enabled?
                ${CC} ${kernccflags} TALPA_INCLUDE_PATH($kernelhdrspath) -Itests/configure ${srcdir}/tests/configure/security.c -o tests/configure/security
                if ! tests/configure/security; then
                    AC_SUBST(buildsecurityfs, "yes")
                else
                    AC_MSG_RESULT([not available])
                fi
            fi

            if test "$buildsecurityfs" = "yes"; then
                AC_MSG_RESULT([present])
                AC_SUBST(securityfs, "-DTALPA_HAS_SECURITYFS")
                AM_CONDITIONAL(BUILDSECURITYFS, test 1 -eq 1)
            else
                AM_CONDITIONAL(BUILDSECURITYFS, test 0 -eq 1)
            fi
        else
            AM_CONDITIONAL(BUILDSECURITYFS, test 0 -eq 1)
            AC_MSG_RESULT([not present])
        fi
    else
        if test "$buildsecurityfs" = "yes"; then
            AC_MSG_RESULT([forced])
        else
            AC_MSG_RESULT([disabled])
        fi
    fi

    # Check whether to use dualfs
    if test "$wantdualfs" = "yes"; then
        # Check if binary sysctls are supported
        AC_MSG_CHECKING([for binary sysctl support])
        TALPA_LOCATE_HEADER(linux/sysctl.h, $kernelhdrspath, , , [quiet])
        if test $((kern_version_code)) -ge 197376 || ${EGREP} sysctl_check_table $TALPA_HEADER_LOCATION/linux/sysctl.h >/dev/null 2>&1; then
            AC_MSG_RESULT([disabled])
            AM_CONDITIONAL(BINARYSYSCTL, test 0 -eq 1)
            AC_SUBST(binarysysctl, "")
        else
            AC_MSG_RESULT([enabled])
            AM_CONDITIONAL(BINARYSYSCTL, test 1 -eq 1)
            AC_SUBST(binarysysctl, "-DTALPA_BINARY_SYSCTL")
        fi
        # procfs will be built
        AM_CONDITIONAL(BUILDPROCFS, test 1 -eq 1)
        AC_SUBST(buildprocfs, "yes")
        AC_MSG_CHECKING([for legacy configuration support])
        # So its just the question whether it is only procfs or dualfs maybe
        if test "$buildsecurityfs" != "yes"; then
            AC_SUBST(builddualfs, "no")
        else
            AC_SUBST(builddualfs, "yes")
        fi
        if test "$builddualfs" = "yes"; then
            AC_SUBST(dualfs, "-DTALPA_HAS_DUALFS")
            AM_CONDITIONAL(BUILDDUALFS, test 1 -eq 1)
            AC_MSG_RESULT([included])
        else
            AM_CONDITIONAL(BUILDDUALFS, test 0 -eq 1)
            AC_MSG_RESULT([no])
        fi
    else
        AM_CONDITIONAL(BUILDPROCFS, test 0 -eq 1)
        AC_SUBST(buildprocfs, "no")
        AM_CONDITIONAL(BINARYSYSCTL, test 0 -eq 1)
        AC_SUBST(binarysysctl, "")
        AM_CONDITIONAL(BUILDDUALFS, test 0 -eq 1)
    fi

    # Autodetect bool typdef
    if test $((kern_version_code)) -lt 132627; then
        TALPA_LOCATE_HEADER(linux/types.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
        AC_MSG_CHECKING([for boolean datatype])
        if ${EGREP} -q "bool" "$TALPA_HEADER_LOCATION/linux/types.h" 2>/dev/null; then
            AC_MSG_RESULT([detected])
            AC_SUBST(bool,"-DTALPA_HAS_BOOL")
        else
            AC_MSG_RESULT([not detected])
        fi
    else
        # Kernels starting with 2.6.19 have it
        AC_SUBST(bool,"-DTALPA_HAS_BOOL")
    fi

    # Check for IMA with ima_path_check API
    AC_MSG_CHECKING([for IMA])
    TALPA_LOCATE_HEADER(linux/ima.h, $kernelhdrspath, imapresent=yes, imapresent=no , [quiet])
    if test "$imapresent" = "yes"; then
        AC_MSG_RESULT([present])
        AC_MSG_CHECKING([for ima_path_check])
        ${EGREP} "ima_path_check" $TALPA_HEADER_LOCATION/linux/ima.h >/dev/null 2>&1
        if test $? -eq 0; then
            AC_MSG_RESULT([present])
            AC_SUBST(imapathcheck,"-DTALPA_IMA_HAS_PATH_CHECK")
        else
            AC_MSG_RESULT([not present])
        fi
    else
        AC_MSG_RESULT([not present])
    fi

    AC_MSG_CHECKING([for putname])
    ${EGREP} "\s+putname.*EXPORT_SYMBOL" ${symvers} >/dev/null 2>&1
    if test $? -eq 0 ; then
        AC_MSG_RESULT([putname present and exported])
        AC_SUBST(putname,"-DTALPA_PUTNAME_SYMBOL -DTALPA_PUTNAME_EXPORTED")
    else
        putname_addr=`${EGREP} " putname\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test "$putname_addr" != ""; then
            AC_MSG_RESULT([putname present but not exported])
            AC_SUBST(putname, "-DTALPA_PUTNAME_SYMBOL -DTALPA_PUTNAME_ADDRESS=0x${putname_addr}UL")
        else
            final_putname_addr=`${EGREP} " final_putname\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
            if test "$final_putname_addr" != ""; then
                AC_MSG_RESULT([not available; final_putname present but not exported])
                AC_SUBST(putname, "-DTALPA_FINAL_PUTNAME_SYMBOL -DTALPA_PUTNAME_ADDRESS=0x${final_putname_addr}UL")
            else
                if test $((kern_version_code)) -lt 198400; then ## 3.7
                    AC_SUBST(putname, "-DTALPA_PUTNAME_DEFINE  -DTALPA_PUTNAME_EXPORTED")
                else
                    AC_MSG_ERROR([putname not available])
                fi
            fi
        fi
    fi

    AC_MSG_CHECKING([for getname])
    ${EGREP} "\s+getname.*EXPORT_SYMBOL" ${symvers} >/dev/null 2>&1
    if test $? -eq 0 ; then
        AC_MSG_RESULT([getname present and exported])
        AC_SUBST(getname,"-DTALPA_GETNAME_SYMBOL -DTALPA_GETNAME_EXPORTED")
    else
        getname_addr=`${EGREP} " getname\$" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test "$getname_addr" != ""; then
            AC_MSG_RESULT([getname present but not exported])
            AC_SUBST(getname, "-DTALPA_GETNAME_SYMBOL -DTALPA_GETNAME_ADDRESS=0x${getname_addr}UL")
        fi
    fi


    # Autodetect ctl_table  typdef
    TALPA_LOCATE_HEADER(linux/sysctl.h, $kernelhdrspath, , , [quiet])
    AC_MSG_CHECKING([typedef ctl_table])
    if ${EGREP} -q "typedef struct ctl_table ctl_table" "$TALPA_HEADER_LOCATION/linux/sysctl.h" 2>/dev/null; then
        AC_MSG_RESULT([detected])
        AC_SUBST(ctltable,"-DTALPA_HAS_CTLTABLE")
    else
        AC_MSG_RESULT([not detected])
    fi

    ${SED} -e  "s/@talpaversion@/${talpaversion}/; \
                s/@debug@/${debug}/; \
                s/@assert@/${assert}/; \
                s/@bool@/${bool}/; \
                s/@ctltable@/${ctltable}/; \
                s/@freetaskflag@/${freetaskflag}/; \
                s/@dpath@/${dpath}/; \
                s/@newparent@/${newparent}/; \
                s/@printkaddr@/${printkaddr}/; \
                s/@dotruncatetype@/${dotruncatetype}/; \
                s/@dotruncateaddr@/${dotruncateaddr}/; \
                s/@vfsunlink@/${vfsunlink}/; \
                s/@vfsreaddir@/${vfsreaddir}/; \
                s/@tasknewtty@/${tasknewtty}/; \
                s/@rcubackport@/${rcubackport}/; \
                s/@mutexes@/${mutexes}/; \
                s/@inodemutex@/${inodemutex}/; \
                s/@fdentry@/${fdentry}/; \
                s/@inodeiprivate@/${inodeiprivate}/; \
                s/@signalbackport@/${signalbackport}/; \
                s/@jiffiesbackport@/${jiffiesbackport}/; \
                s/@filldirbackport@/${filldirbackport}/; \
                s/@mountrcubackport@/${mountrcubackport}/; \
                s/@smbfs@/${smbfs}/; \
                s/@buildlsm@/${lsm}/; \
                s/@lsm265@/${lsm265}/; \
                s/@lsm266@/${lsm266}/; \
                s/@lsm2610@/${lsm2610}/; \
                s/@lsm2614@/${lsm2614}/; \
                s/@lsmkeys@/${lsmkeys}/; \
                s/@hidden@/${hidden}/; \
                s/@xhack@/${xhack}/; \
                s/@structfilename@/${structfilename}/; \
                s/@hrtimers@/${hrtimers}/; \
                s/@hookdops@/${hookdops}/; \
                s/@imapathcheck@/${imapathcheck}/; \
                s/@buildstacker@/${buildstacker}/; \
                s/@syscallhook@/${syscallhook}/; \
                s/@rodata@/${rodata}/; \
                s/@hassetpages@/${hassetpages}/; \
                s/@needsvacpa@/${needsvacpa}/; \
                s/@nopasymbol@/${nopasymbol}/; \
                s/@kfuncchpgattraddr@/${kfuncchpgattraddr}/; \
                s/@notasklistlock@/${notasklistlock}/; \
                s/@probe_kernel_read@/${probe_kernel_read}/; \
                s/@vfsmntlock@/${vfsmntlock}/; \
                s/@samefile@/${samefile}/; \
                s/@buildprocfs@/${buildprocfs}/; s/@binarysysctl@/${binarysysctl}/; \
                s/@buildsecurityfs@/${buildsecurityfs}/; s/@securityfs@/${securityfs}/; \
                s/@buildsymbolver@/${buildsymbolver}/; \
                s/@putname@/${putname}/; \
                s/@getname@/${getname}/; \
                s/@strdupuser@/${strdupuser}/; \
                s/@linuxuidgid@/${linuxuidgid}/; \
                s/@lookup_mnt_last@/${lookup_mnt_last}/; \
                s/@get_fs_root_and_pwd@/${get_fs_root_and_pwd}/; \
                s/@vfsmount_namespace@/${vfsmount_namespace}/; \
                s/@compile_flags@/${compile_flags}/; \
                s/@builddualfs@/${builddualfs}/; \
                s/@dualfs@/${dualfs}/;" ${srcdir}/Makefile26.in >${srcdir}/Makefile

    ${SED} -e  "s/@talpaversion@/${talpaversion}/; \
                s/@debug@/${debug}/; \
                s/@assert@/${assert}/; \
                s/@bool@/${bool}/; \
                s/@ctltable@/${ctltable}/; \
                s/@freetaskflag@/${freetaskflag}/; \
                s/@dpath@/${dpath}/; \
                s/@newparent@/${newparent}/; \
                s/@printkaddr@/${printkaddr}/; \
                s/@dotruncatetype@/${dotruncatetype}/; \
                s/@dotruncateaddr@/${dotruncateaddr}/; \
                s/@vfsunlink@/${vfsunlink}/; \
                s/@vfsreaddir@/${vfsreaddir}/; \
                s/@tasknewtty@/${tasknewtty}/; \
                s/@rcubackport@/${rcubackport}/; \
                s/@mutexes@/${mutexes}/; \
                s/@inodemutex@/${inodemutex}/; \
                s/@fdentry@/${fdentry}/; \
                s/@inodeiprivate@/${inodeiprivate}/; \
                s/@signalbackport@/${signalbackport}/; \
                s/@jiffiesbackport@/${jiffiesbackport}/; \
                s/@filldirbackport@/${filldirbackport}/; \
                s/@mountrcubackport@/${mountrcubackport}/; \
                s/@smbfs@/${smbfs}/; \
                s/@buildlsm@/${lsm}/; \
                s/@lsm265@/${lsm265}/; \
                s/@lsm266@/${lsm266}/; \
                s/@lsm2610@/${lsm2610}/; \
                s/@lsm2614@/${lsm2614}/; \
                s/@lsmkeys@/${lsmkeys}/; \
                s/@hidden@/${hidden}/; \
                s/@xhack@/${xhack}/; \
                s/@structfilename@/${structfilename}/; \
                s/@hrtimers@/${hrtimers}/; \
                s/@hookdops@/${hookdops}/; \
                s/@imapathcheck@/${imapathcheck}/; \
                s/@buildstacker@/${buildstacker}/; \
                s/@syscallhook@/${syscallhook}/; \
                s/@rodata@/${rodata}/; \
                s/@hassetpages@/${hassetpages}/; \
                s/@needsvacpa@/${needsvacpa}/; \
                s/@nopasymbol@/${nopasymbol}/; \
                s/@kfuncchpgattraddr@/${kfuncchpgattraddr}/; \
                s/@notasklistlock@/${notasklistlock}/; \
                s/@probe_kernel_read@/${probe_kernel_read}/; \
                s/@vfsmntlock@/${vfsmntlock}/; \
                s/@samefile@/${samefile}/; \
                s/@buildprocfs@/${buildprocfs}/; s/@binarysysctl@/${binarysysctl}/; \
                s/@buildsecurityfs@/${buildsecurityfs}/; s/@securityfs@/${securityfs}/; \
                s/@putname@/${putname}/; \
                s/@getname@/${getname}/; \
                s/@strdupuser@/${strdupuser}/; \
                s/@linuxuidgid@/${linuxuidgid}/; \
                s/@builddualfs@/${builddualfs}/; \
                s!@linuxmagicinclude@!${linuxmagicinclude}!; \
                s!@linuxuapimagicinclude@!${linuxuapimagicinclude}!; \
                s!@linuxcompilerinclude@!${linuxcompilerinclude}!; \
                s!@uapiunistdinclude@!${uapiunistdinclude}!; \
                s!@unistd64x32include@!${unistd64x32include}!; \
                s!@autoconf_h_include@!${autoconf_h_include}!; \
                s/@lookup_mnt_last@/${lookup_mnt_last}/; \
                s/@get_fs_root_and_pwd@/${get_fs_root_and_pwd}/; \
                s/@vfsmount_namespace@/${vfsmount_namespace}/; \
                s/@compile_flags@/${compile_flags}/; \
                s/@dualfs@/${dualfs}/;" ${srcdir}/tests/modules/Makefile26.in >${srcdir}/tests/modules/Makefile
else
    AC_MSG_RESULT([2.4 build system detected])
    AC_SUBST(ko,o)
    AC_SUBST(talpaversion, "-DTALPA_VERSION=\\\"${PACKAGE_VERSION}\\\"")
    AM_CONDITIONAL(KBUILDUSEM, test 0 -eq 1)
    AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
    AM_CONDITIONAL(BUILDPROCFS, test 1 -eq 1)
    AM_CONDITIONAL(BINARYSYSCTL, test 1 -eq 1)
    AC_SUBST(binarysysctl, "-DTALPA_BINARY_SYSCTL")
    AM_CONDITIONAL(BUILDSECURITYFS, test 0 -eq 1)
    AM_CONDITIONAL(BUILDDUALFS, test 0 -eq 1)

    # Check for hidden syscall table
    if test "$auto_hidden" = "yes"; then
        AC_MSG_CHECKING([for syscall table])
        if test -f $kerneldir/kernel/ksyms.c; then
            ${EGREP} EXPORT_SYMBOL\\\(sys_call_table\\\)\; $kerneldir/kernel/ksyms.c >/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([hidden])
                AC_SUBST(hidden,"-DTALPA_HIDDEN_SYSCALLS")
                if find_syscall_table "$system_map"; then
                    AC_SUBST(hidden,"${hidden} ${FIND_SYSCALL_TABLE_RESULT}")
                fi
            else
                AC_MSG_RESULT([exported])
            fi
        else
            syscalls_unknown=yes
            AC_MSG_RESULT([skipped])
        fi
    fi

    # Check for exported path_lookup
    if test "$auto_pathlookup" = "yes"; then
        if test $((kern_version_code)) -lt 132121; then
            AC_MSG_CHECKING([for path_lookup])
            if test -f $kerneldir/kernel/ksyms.c; then
                ${EGREP} EXPORT_SYMBOL\\\(path_lookup\\\)\; $kerneldir/kernel/ksyms.c >/dev/null 2>&1
                if test $? -ne 0; then
                    AC_MSG_RESULT([hidden])
                else
                    AC_SUBST(pathlookup,"-DTALPA_HAS_PATH_LOOKUP")
                    AC_MSG_RESULT([exported])
                fi
            else
                AC_MSG_RESULT([undetectable])
            fi
        fi
    fi

    # Check for backported scheduler
    if test "$auto_parent" = "yes"; then
        TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
        AC_MSG_CHECKING([for backported scheduler])
        ${EGREP} parent\; $TALPA_HEADER_LOCATION/linux/sched.h >/dev/null 2>&1
        if test $? -eq 0; then
            AC_MSG_RESULT([found])
            AC_SUBST(newparent,"-DTALPA_HAS_NEW_PARENT")
        else
            AC_MSG_RESULT([original])
        fi
    fi

    # Check for backported prefetch.h
    if test $((kern_version_code)) -lt 132106; then
        AC_MSG_CHECKING([for backported prefetch.h])
        TALPA_LOCATE_FILE(linux/prefetch.h, $kernelhdrspath,
            [AC_MSG_RESULT([found])
            AC_SUBST(backportedprefetch,"-DTALPA_BACKPORTED_PREFETCH")],
            [AC_MSG_RESULT([not found])])
    fi
fi

AC_MSG_CHECKING([for X workaround])
if test "$xhack" != ""; then
    AC_MSG_RESULT([enabled])
else
    AC_MSG_RESULT([disabled])
    AM_CONDITIONAL(TESTXWORKAROUND, test 0 -eq 1)
fi

AC_SUBST(kernelincludes,TALPA_INCLUDE_PATH($kernelhdrspath))

#
# ...Should we build?
#
else
    # define these to please autoconf
    AM_CONDITIONAL(KBUILD26, test 1 -eq 1)
    AM_CONDITIONAL(KBUILDUSEM, test 0 -eq 1)
    AM_CONDITIONAL(BUILDLSM, test 1 -eq 1)
    AM_CONDITIONAL(BUILDSTACKER, test 1 -eq 1)
    AM_CONDITIONAL(BUILDSYMBOLVER, test 1 -eq 1)
    AM_CONDITIONAL(BUILDPROCFS, test 1 -eq 1)
    AM_CONDITIONAL(BINARYSYSCTL, test 1 -eq 1)
    AM_CONDITIONAL(BUILDSECURITYFS, test 1 -eq 1)
    AM_CONDITIONAL(BUILDDUALFS, test 1 -eq 1)
    ## Defined to be true so that tests are included in source tar file
    AM_CONDITIONAL(TESTXWORKAROUND, test 1 -eq 1)
    AM_CONDITIONAL(TESTNAMESPACES, test 1 -eq 1)
    AM_CONDITIONAL(M32_BUILD, test 1 -eq 1)
    AM_CONDITIONAL(MX32_BUILD, test 1 -eq 1)
fi


#
# Output.
#
AC_OUTPUT([makefile clients/Makefile tests/Makefile tests/modules/makefile tests/benchmark/Makefile])

if test "$syscalls_unknown" = "yes"; then
    echo -e "\nFailed to autodetect syscall table status - defaulting to exported.\nUse separate --with-kernel and --with-kernel-include, or set --enable-hidden-syscall-table.\n"
fi

#
# End of configure.ac
#
