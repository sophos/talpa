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

##
## Check that a file opened before a chroot, then written and closed after
## the chroot still has the correct path reported.
##

. ${srcdir}/talpa-init.sh

mkdir /tmp/tlp-test/dir

./chk_chroot1 0 /tmp/tlp-test/dir /tmp/tlp-test/file

exit $?
