#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2004-2017 Sophos Limited, Oxford, England.
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

function get_count() { awk '{ sum += $2 } END { print sum }' $talpafs/interceptors/VFSHookInterceptor/fs-list; }
function fail() { echo "$@"; exit 1; }

## fail on error
set -e

## prepare test dirs

mkdir /tmp/tlp-test/base

mount --bind /tmp/tlp-test/base /tmp/tlp-test/base
mount --make-private /tmp/tlp-test/base 2>/dev/null || true

mkdir /tmp/tlp-test/base/a
mkdir /tmp/tlp-test/base/b
mkdir /tmp/tlp-test/base/c

a=$(get_count)
mount --bind /tmp/tlp-test/base/a /tmp/tlp-test/base/b
b=$(get_count)
mount --move /tmp/tlp-test/base/b /tmp/tlp-test/base/c
c=$(get_count)
umount /tmp/tlp-test/base/c
d=$(get_count)
umount /tmp/tlp-test/base

(( a > 1 )) || fail "failed to get usage count"
(( a < b )) || fail "bind mount didn't increase usage count"
(( c == b )) || fail "move mount changed usage count"
(( d < c )) || fail "umount didn't decrease usage count"
(( d == a )) || fail "usage count not restored after umount"

exit 0
