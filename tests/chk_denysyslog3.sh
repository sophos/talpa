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

tlp_insmod modules/tlp-denysyslog.${ko}

function check()
{
    ./chk_denysyslog3 "$@" || exit 1
}

check "Standard interceptor processor failure while opening /bin/bash on behalf of process chk_denysyslog3[" 1 1
check "Unexpected pass through action request while opening /bin/bash on behalf of process chk_denysyslog3[" 1 2
check "Unexpected allow action request while opening /bin/bash on behalf of process chk_denysyslog3[" 1 3
check "Access denied while opening /bin/bash on behalf of process chk_denysyslog3[" 1 4
check "Timeout occurred while opening /bin/bash on behalf of process chk_denysyslog3[" 1 5
check "Error occurred while opening /bin/bash on behalf of process chk_denysyslog3[" 1 6

check "Standard interceptor processor failure while closing /bin/bash on behalf of process chk_denysyslog3[" 2 1
check "Unexpected pass through action request while closing /bin/bash on behalf of process chk_denysyslog3[" 2 2
check "Unexpected allow action request while closing /bin/bash on behalf of process chk_denysyslog3[" 2 3
check "Access denied while closing /bin/bash on behalf of process chk_denysyslog3[" 2 4
check "Timeout occurred while closing /bin/bash on behalf of process chk_denysyslog3[" 2 5
check "Error occurred while closing /bin/bash on behalf of process chk_denysyslog3[" 2 6

check "Standard interceptor processor failure while executing /bin/bash on behalf of process chk_denysyslog3[" 3 1
check "Unexpected pass through action request while executing /bin/bash on behalf of process chk_denysyslog3[" 3 2
check "Unexpected allow action request while executing /bin/bash on behalf of process chk_denysyslog3[" 3 3
check "Access denied while executing /bin/bash on behalf of process chk_denysyslog3[" 3 4
check "Timeout occurred while executing /bin/bash on behalf of process chk_denysyslog3[" 3 5
check "Error occurred while executing /bin/bash on behalf of process chk_denysyslog3[" 3 6

exit 0
