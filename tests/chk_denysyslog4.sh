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
    ./chk_denysyslog4 "$@" # || exit 1
}

check "Standard interceptor processor failure while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 1
check "Unexpected pass through action request while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 2
check "Unexpected allow action request while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 3
check "Access denied while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 4
check "Timeout occurred while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 5
check "Error occurred while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 6

# Commented out since reworked FilesystemInfo object does not support creating from fake data.
#check "Standard interceptor processor failure while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 1
#check "Unexpected pass through action request while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 2
#check "Unexpected allow action request while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 3
#check "Access denied while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 4
#check "Timeout occured while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 5
#check "Error occured while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 6
#check "Error occured while processing unsupported object type /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 3 6

exit 0
