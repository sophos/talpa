#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2008-2019 Sophos Limited, Oxford, England.
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

## Test that talpa_syscallhook will block an interceptor that
## is using the wrong protocol version to talk to it.

. ${srcdir}/tlp-cleanup.sh

if test "$interceptor_module" = "syscall"; then
    tlp_insmod ../talpa_syscallhook.${ko}
elif test "$interceptor_module" = "vfshook"; then
    tlp_insmod ../talpa_syscallhook.${ko} hook_mask=mu
else
    exit 77
fi

tlp_insmod modules/tlp-wronginterceptor.${ko} 2>/dev/null

# expecting EPROTO (71) 
if test $? -ne 71; then
    exit 0
fi

exit 1
