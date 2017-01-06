#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2004-2016 Sophos Limited, Oxford, England.
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

. ${srcdir}/talpa-init.sh

if test -f /etc/SuSE-release; then
    kernel_ver="`uname -r`"
    if test "${kernel_ver%%-*}" = "3.0.101"; then
        # LINUXEP-3019 - kernel lockup on loopback sync/umount on SLES11 SP4
        exit 77
    fi
fi

tmpdir=/tmp/tlp-test

echo ${tmpdir}/mnt >${talpafs}/intercept-filters/FilesystemInclusionProcessor/include-path

mkdir -p ${tmpdir}/mnt
dd if=/dev/zero of=${tmpdir}/fs.img bs=1M count=4 >/dev/null 2>&1

mkfs='/sbin/mkfs.ext2'
if test ! -x "$mkfs"; then
    exit 77
fi

${mkfs} -F ${tmpdir}/fs.img >/dev/null 2>&1
mount ${tmpdir}/fs.img ${tmpdir}/mnt -o loop

./vc_inclusionproc ${tmpdir}/mnt
rc=$?

umount ${tmpdir}/mnt

exit $rc
