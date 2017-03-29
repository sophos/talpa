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

. ${srcdir}/tlp-cleanup.sh

tlp_insmod modules/tlp-allowsyslog.${ko}

function check()
{
    ./chk_allowsyslog3 "$@" || exit 1
}

## check for truncated process name as proc->comm is truncated to 15 chars
check "Timeout occurred while opening /bin/bash on behalf of process chk_allowsyslog[" 1 5
check "Timeout occurred while closing /bin/bash on behalf of process chk_allowsyslog[" 2 5
check "Timeout occurred while executing /bin/bash on behalf of process chk_allowsyslog[" 3 5

exit 0
