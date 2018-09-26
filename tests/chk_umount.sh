#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2004-2018 Sophos Limited, Oxford, England.
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

. ${srcdir}/tlp-cleanup.sh

if test -f /etc/SuSE-release; then
    kernel_ver="`uname -r`"
    if test "${kernel_ver%%-*}" = "3.0.101"; then
        # LINUXEP-3019 - kernel lockup on loopback sync/umount on SLES11 SP4
        exit 77
    fi
fi

mkfs='/sbin/mkfs.ext2'
if test ! -x "$mkfs"; then
    exit 77
fi

. ${srcdir}/talpa-init.sh

tmpdir='/tmp/tlp-test'

dd if=/dev/zero of=${tmpdir}/fs.img bs=1M count=4 >/dev/null 2>&1

device=`losetup --find --show ${tmpdir}/fs.img`
rc=$?
if test $rc -ne 0 -o -z "$device"; then
    echo >&2 "Failed to create loopback device"
    exit $rc
fi

${mkfs} ${device} >/dev/null 2>&1
rc=$?
if test $rc -ne 0; then
    echo >&2 "Failed to create filesystem"
    losetup --detach ${device} >/dev/null 2>&1
    exit $rc
fi

mkdir -p ${tmpdir}/mnt

./chk_umount ${device} ${tmpdir}/mnt ext2
rc=$?

if mount 2>/dev/null | grep ${tmpdir}/mnt ;then
    umount ${tmpdir}/mnt >/dev/null 2>&1
fi
losetup --detach ${device} >/dev/null 2>&1

exit $rc
