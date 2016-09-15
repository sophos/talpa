#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2004-2014 Sophos Limited, Oxford, England.
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

tmpdir='/tmp/tlp-test/mnt1'
mkdir -p $tmpdir

talpa_disable
talpa_unload

lsmod | grep talpa && { echo "Unable to unload Talpa" >&2 ; exit 77 ; }
./chk_null_fstype_mnt "$tmpdir" || {
    echo "Kernel doesn't support NULL device" >&2
    umount $tmpdir
    rmdir $tmpdir
    exit 77
}

talpa_load
talpa_defaults
talpa_enable

lsmod | grep talpa

./chk_null_fstype_mnt "$tmpdir"
EXIT=$?
rmdir $tmpdir
exit $EXIT
