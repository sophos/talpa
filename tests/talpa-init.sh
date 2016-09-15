#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
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

mkdir -p /tmp/tlp-test
dd if=/dev/zero of=/tmp/tlp-test/file bs=1k count=128 1>/dev/null 2>&1

cp -a $(which true) /tmp/tlp-test/
cp -a $(which bash) /tmp/tlp-test/
cp -a ${srcdir}/test-script*.sh /tmp/tlp-test/

talpa_load
talpa_defaults
talpa_enable
