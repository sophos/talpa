##
## tests/Makefile.am
##
## TALPA Filesystem Interceptor
##
## Copyright (C) 2004-2014 Sophos Limited, Oxford, England.
##
## This program is free software; you can redistribute it and/or modify it under the terms of the
## GNU General Public License Version 2 as published by the Free Software Foundation.
##
## This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
## even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
## See the GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along with this program; if not,
## write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
##

AM_CFLAGS = -I$(srcdir)/include -I$(srcdir) -I$(top_srcdir) @autoconf_h_include@ @linuxmagicinclude@ @linuxuapimagicinclude@ @linuxcompilerinclude@ @uapiunistdinclude@ @unistd64x32include@ -Wall
USERSPACE_C_FLAGS = -I$(srcdir)/include -I$(srcdir) -I$(top_srcdir) -Wall

check_PROGRAMS =    chkpersonality \
                    chkfileinfo \
                    chkfsinfo \
                    syslog_ops

if BINARYSYSCTL
check_PROGRAMS +=   sysctldisable \
                    sysctlenable \
                    sysctlchk
endif

check_PROGRAMS +=   chkstdinterceptor \
                    chkinterceptorfilter \
                    chkinterceptorfilter1 \
                    chkinterceptorfilter2 \
                    chkinterceptorfilter3 \
                    chkinterceptorfilter4 \
                    chkinterceptorfilter5 \
                    chkinterceptorfilter6 \
                    chkinterceptorfilter7 \
                    chkinterceptorfilter8 \
                    chkinterceptorfilter9 \
                    chkinterceptorfilter10 \
                    chkinterceptorfilter11 \
                    chkinterceptorfilter12 \
                    chkinterceptorfilter13 \
                    chkinterceptorfilter14 \
                    chkext2mnt \
                    chkext2umnt \
                    chk_null_mnt \
                    chk_null_fstype_mnt \
                    chkext2fops \
                    vc_inclusionproc \
                    chkvc \
                    chkvc_timeout \
                    chkcacheintcpt \
                    chkinclusionioctl \
                    chkinclusionioctl1 \
                    chkexclusionioctl \
                    chkexclusionioctl1 \
                    chkexclusionioctl2 \
                    chkexclusionioctl3 \
                    chk_denysyslog3 \
                    chk_denysyslog4 \
                    chk_thrdinfo \
                    chk_ddvc \
                    chk_ddvc1 \
                    chk_ddvc2 \
                    chk_ddvc3 \
                    chk_ddvc4 \
                    chk_ddvc5 \
                    chk_ddvc6 \
                    chk_ddvc7 \
                    chk_ddvc8 \
                    chk_vettingctrl \
                    chk_vettingctrl1 \
                    chk_vettingctrl2 \
                    chk_vettingctrl3 \
                    chk_vettingctrl4 \
                    chk_vettingctrl5 \
                    chk_vettingctrl8 \
                    chk_vettingctrl9 \
                    chk_vettingctrl10 \
                    chk_vettingctrl11 \
                    chk_vettingctrl12 \
                    chk_fsexclusion \
                    chk_fsexclusion8 \
                    chk_fsexclusion10 \
                    chk_fsexclusion15 \
                    tlp-4-001 \
                    tlp-4-002 \
                    tlp-4-003 \
                    tlp-4-003a \
                    tlp-4-004 \
                    tlp-4-005 \
                    tlp-4-006 \
                    tlp-5-001 \
                    tlp-5-002 \
                    tlp-5-003 \
                    tlp-6-001 \
                    tlp-6-002 \
                    tlp-6-003 \
                    tlp-6-004 \
                    tlp-6-010 \
                    tlp-6-011 \
                    tlp-6-012 \
                    tlp-6-013 \
                    tlp-6-014 \
                    tlp-6-020 \
                    tlp-6-021 \
                    tlp-6-022 \
                    tlp-6-023 \
                    tlp-6-024 \
                    tlp-6-025 \
                    tlp-6-026 \
                    tlp-6-027 \
                    tlp-6-028 \
                    tlp-6-029 \
                    tlp-6-030 \
                    tlp-7-001 \
                    tlp-7-003 \
                    tlp-7-005 \
                    tlp-8-001 \
                    tlp-8-002 \
                    tlp-8-003 \
                    tlp-8-004

PTHREAD_FLAG = -pthread

chkpersonality_SOURCES = chkpersonality.c tlp-test.h
chkfileinfo_SOURCES = chkfileinfo.c
chkfsinfo_SOURCES = chkfsinfo.c
syslog_ops_SOURCES = syslog_ops.c
sysctldisable_SOURCES = sysctldisable.c
sysctlenable_SOURCES = sysctlenable.c
sysctlchk_SOURCES = sysctlchk.c
chkstdinterceptor_SOURCES = chkstdinterceptor.c
chkinterceptorfilter_SOURCES = chkinterceptorfilter.c
chkinterceptorfilter1_SOURCES = chkinterceptorfilter1.c
chkinterceptorfilter2_SOURCES = chkinterceptorfilter2.c
chkinterceptorfilter3_SOURCES = chkinterceptorfilter3.c
chkinterceptorfilter4_SOURCES = chkinterceptorfilter4.c
chkinterceptorfilter5_SOURCES = chkinterceptorfilter5.c
chkinterceptorfilter6_SOURCES = chkinterceptorfilter6.c
chkinterceptorfilter7_SOURCES = chkinterceptorfilter7.c
chkinterceptorfilter8_SOURCES = chkinterceptorfilter8.c
chkinterceptorfilter9_SOURCES = chkinterceptorfilter9.c
chkinterceptorfilter10_SOURCES = chkinterceptorfilter10.c
chkinterceptorfilter11_SOURCES = chkinterceptorfilter11.c
chkinterceptorfilter12_SOURCES = chkinterceptorfilter12.c
chkinterceptorfilter13_SOURCES = chkinterceptorfilter13.c
chkinterceptorfilter14_SOURCES = chkinterceptorfilter14.c
chkext2mnt_SOURCES = chkext2mnt.c
chkext2umnt_SOURCES = chkext2umnt.c
chkext2fops_SOURCES = chkext2fops.c
chk_null_mnt_SOURCES = chk_null_mnt.c
chk_null_fstype_mnt_SOURCES = chk_null_fstype_mnt.c

vc_inclusionproc_SOURCES = vc_inclusionproc.c ../clients/vc-lib.c ../clients/talpa.c
vc_inclusionproc_CFLAGS = $(USERSPACE_C_FLAGS)

chkvc_SOURCES = chkvc.c ../clients/vc-lib.c ../clients/talpa.c
chkvc_CFLAGS = $(USERSPACE_C_FLAGS)

chkvc_timeout_SOURCES = chkvc_timeout.c ../clients/vc-lib.c ../clients/talpa.c
chkvc_timeout_CFLAGS = $(USERSPACE_C_FLAGS)

chkcacheintcpt_SOURCES = chkcacheintcpt.c ../clients/vc-lib.c ../clients/talpa.c
chkcacheintcpt_CFLAGS = $(USERSPACE_C_FLAGS)

chkinclusionioctl_SOURCES = chkinclusionioctl.c
chkinclusionioctl1_SOURCES = chkinclusionioctl1.c
chkexclusionioctl_SOURCES = chkexclusionioctl.c
chkexclusionioctl1_SOURCES = chkexclusionioctl1.c
chkexclusionioctl2_SOURCES = chkexclusionioctl2.c
chkexclusionioctl3_SOURCES = chkexclusionioctl3.c
chk_denysyslog3_SOURCES = chk_denysyslog3.c tlp-log-search.c
chk_denysyslog4_SOURCES = chk_denysyslog4.c tlp-log-search.c
chk_thrdinfo_SOURCES = chk_thrdinfo.c
chk_ddvc_SOURCES = chk_ddvc.c tlp-log-search.c ../clients/talpa.c
chk_ddvc1_SOURCES = chk_ddvc1.c tlp-log-search.c ../clients/talpa.c
chk_ddvc2_SOURCES = chk_ddvc2.c ../clients/talpa.c
chk_ddvc3_SOURCES = chk_ddvc3.c ../clients/talpa.c
chk_ddvc4_SOURCES = chk_ddvc4.c ../clients/talpa.c
chk_ddvc5_SOURCES = chk_ddvc5.c ../clients/talpa.c
chk_ddvc6_SOURCES = chk_ddvc6.c ../clients/talpa.c
chk_ddvc7_SOURCES = chk_ddvc7.c ../clients/talpa.c
chk_ddvc8_SOURCES = chk_ddvc8.c ../clients/talpa.c

chk_vettingctrl_SOURCES = chk_vettingctrl.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl1_SOURCES = chk_vettingctrl1.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl1_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl2_SOURCES = chk_vettingctrl2.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl2_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl3_SOURCES = chk_vettingctrl3.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl3_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl4_SOURCES = chk_vettingctrl4.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl4_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl5_SOURCES = chk_vettingctrl5.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl5_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl8_SOURCES = chk_vettingctrl8.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl8_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl9_SOURCES = chk_vettingctrl9.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl9_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl10_SOURCES = chk_vettingctrl10.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl10_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl11_SOURCES = chk_vettingctrl11.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl11_CFLAGS = $(USERSPACE_C_FLAGS)

chk_vettingctrl12_SOURCES = chk_vettingctrl12.c ../clients/vc-lib.c ../clients/talpa.c
chk_vettingctrl12_CFLAGS = $(USERSPACE_C_FLAGS)

chk_fsexclusion_SOURCES = chk_fsexclusion.c
chk_fsexclusion8_SOURCES = chk_fsexclusion8.c
chk_fsexclusion10_SOURCES = chk_fsexclusion10.c
chk_fsexclusion15_SOURCES = chk_fsexclusion15.c
tlp_4_001_SOURCES = tlp-4-001.c ../clients/vc-lib.c ../clients/pe-lib.c ../clients/talpa.c
tlp_4_001_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_4_002_SOURCES = tlp-4-002.c ../clients/vc-lib.c ../clients/pe-lib.c ../clients/talpa.c
tlp_4_002_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_4_003_SOURCES = tlp-4-003.c ../clients/pe-lib.c ../clients/talpa.c
tlp_4_003_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_4_003a_SOURCES = tlp-4-003a.c ../clients/vc-lib.c ../clients/talpa.c
tlp_4_003a_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_4_004_SOURCES = tlp-4-004.c ../clients/pe-lib.c ../clients/talpa.c
tlp_4_004_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_4_005_SOURCES = tlp-4-005.c ../clients/pe-lib.c ../clients/talpa.c
tlp_4_005_LDFLAGS = $(PTHREAD_FLAG)
tlp_4_005_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_4_006_SOURCES = tlp-4-006.c ../clients/vc-lib.c ../clients/pe-lib.c ../clients/talpa.c
tlp_4_006_LDFLAGS = $(PTHREAD_FLAG)
tlp_4_006_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_5_001_SOURCES = tlp-5-001.c
tlp_5_002_SOURCES = tlp-5-002.c
tlp_5_003_SOURCES = tlp-5-003.c
tlp_6_001_SOURCES = tlp-6-001.c
tlp_6_002_SOURCES = tlp-6-002.c
tlp_6_003_SOURCES = tlp-6-003.c
tlp_6_004_SOURCES = tlp-6-004.c
tlp_6_010_SOURCES = tlp-6-010.c
tlp_6_011_SOURCES = tlp-6-011.c
tlp_6_012_SOURCES = tlp-6-012.c
tlp_6_013_SOURCES = tlp-6-013.c
tlp_6_014_SOURCES = tlp-6-014.c
tlp_6_020_SOURCES = tlp-6-020.c
tlp_6_021_SOURCES = tlp-6-021.c
tlp_6_022_SOURCES = tlp-6-022.c
tlp_6_023_SOURCES = tlp-6-023.c
tlp_6_024_SOURCES = tlp-6-024.c
tlp_6_025_SOURCES = tlp-6-025.c
tlp_6_026_SOURCES = tlp-6-026.c
tlp_6_027_SOURCES = tlp-6-027.c
tlp_6_028_SOURCES = tlp-6-028.c
tlp_6_029_SOURCES = tlp-6-029.c
tlp_6_030_SOURCES = tlp-6-030.c

tlp_7_001_SOURCES = tlp-7-001.c ../clients/vc-lib.c ../clients/talpa.c
tlp_7_001_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_7_003_SOURCES = tlp-7-003.c ../clients/vc-lib.c ../clients/talpa.c
tlp_7_003_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_7_005_SOURCES = tlp-7-005.c ../clients/vc-lib.c ../clients/talpa.c
tlp_7_005_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_8_001_SOURCES = tlp-8-001.c ../clients/vc-lib.c ../clients/pe-lib.c ../clients/talpa.c
tlp_8_001_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_8_002_SOURCES = tlp-8-002.c ../clients/vc-lib.c ../clients/pe-lib.c ../clients/talpa.c
tlp_8_002_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_8_003_SOURCES = tlp-8-003.c ../clients/vc-lib.c ../clients/pe-lib.c ../clients/talpa.c
tlp_8_003_CFLAGS = $(USERSPACE_C_FLAGS)

tlp_8_004_SOURCES = tlp-8-004.c ../clients/vc-lib.c ../clients/pe-lib.c ../clients/talpa.c
tlp_8_004_CFLAGS = $(USERSPACE_C_FLAGS)

if LOADTEST

check_PROGRAMS +=  reiserfsmnt

reiserfsmnt_SOURCES = reiserfsmnt.c

endif

SUBDIRS = modules

TESTS                   = tlp-init.sh \
                          chk_null_mnt.sh \
                          chk_null_fstype_mnt.sh \
                          chkpersonality.sh \
                          chkfileinfo.sh \
                          chkfsinfo.sh \
                          syslog_ops.sh \
                          tlp_dualfsdisable.sh \
                          tlp_dualfsenable.sh \
                          chklinuxvfs.sh
if BINARYSYSCTL
TESTS +=                  sysctldisable.sh \
                          sysctlenable.sh \
                          sysctlchk.sh
endif

TESTS +=                  chkstdinterceptor.sh \
                          chkinterceptorfilter.sh \
                          chkinterceptorfilter1.sh \
                          chkinterceptorfilter2.sh \
                          chkinterceptorfilter3.sh \
                          chkinterceptorfilter4.sh \
                          chkinterceptorfilter5.sh \
                          chkinterceptorfilter6.sh \
                          chkinterceptorfilter7.sh \
                          chkinterceptorfilter8.sh \
                          chkinterceptorfilter9.sh \
                          chkinterceptorfilter10.sh \
                          chkinterceptorfilter11.sh \
                          chkinterceptorfilter12.sh \
                          chkinterceptorfilter13.sh \
                          chkinterceptorfilter14.sh \
                          chkinclusionioctl.sh \
                          chkinclusionioctl1.sh \
                          chkexclusionioctl.sh \
                          chkexclusionioctl1.sh \
                          chkexclusionioctl2.sh \
                          chkexclusionioctl3.sh \
                          chk_denysyslog.sh \
                          chk_denysyslog1.sh \
                          chk_denysyslog2.sh \
                          chk_denysyslog3.sh \
                          chk_denysyslog4.sh \
                          chk_thrdinfo.sh \
                          chk_ddvc.sh \
                          chk_ddvc1.sh \
                          chk_ddvc2.sh \
                          chk_ddvc3.sh \
                          chk_ddvc4.sh \
                          chk_ddvc5.sh \
                          chk_ddvc6.sh \
                          chk_ddvc7.sh \
                          chk_ddvc8.sh \
                          chk_vettingctrl.sh \
                          chk_vettingctrl1.sh \
                          chk_vettingctrl2.sh \
                          chk_vettingctrl3.sh \
                          chk_vettingctrl4.sh \
                          chk_vettingctrl5.sh \
                          chk_vettingctrl6.sh \
                          chk_vettingctrl7.sh \
                          chk_vettingctrl8.sh \
                          chk_vettingctrl9.sh

if TESTXWORKAROUND
TESTS +=                  chk_vettingctrl10.sh \
						  chk_vettingctrl11.sh
endif

TESTS +=                  chk_vettingctrl12.sh \
                          chk_fsexclusion.sh \
                          chk_fsexclusion1.sh \
                          chk_fsexclusion2.sh \
                          chk_fsexclusion3.sh \
                          chk_fsexclusion4.sh \
                          chk_fsexclusion5.sh \
                          chk_fsexclusion6.sh \
                          chk_fsexclusion7.sh \
                          chk_fsexclusion8.sh \
                          chk_fsexclusion9.sh \
                          chk_fsexclusion10.sh \
                          chk_fsexclusion11.sh \
                          chk_fsexclusion12.sh \
                          chk_fsexclusion13.sh \
                          chk_fsexclusion14.sh \
                          chk_fsexclusion15.sh \
                          chk_fsexclusion16.sh \
                          chk_fsexclusion17.sh \
                          chk_fsexclusion18.sh \
                          chk_fsexclusion19.sh \
                          tlp-4-001.sh \
                          tlp-4-002.sh \
                          tlp-4-003.sh \
                          tlp-4-004.sh \
                          tlp-4-005.sh \
                          tlp-4-006.sh \
                          tlp-5-001.sh \
                          tlp-5-002.sh \
                          tlp-5-003.sh \
                          tlp-6-001.sh \
                          tlp-6-002.sh \
                          tlp-6-003.sh \
                          tlp-6-004.sh \
                          tlp-6-010.sh \
                          tlp-6-011.sh \
                          tlp-6-012.sh \
                          tlp-6-013.sh \
                          tlp-6-014.sh \
                          tlp-6-020.sh \
                          tlp-6-021.sh \
                          tlp-6-022.sh \
                          tlp-6-023.sh \
                          tlp-6-024.sh \
                          tlp-6-025.sh \
                          tlp-6-026.sh \
                          tlp-6-027.sh \
                          tlp-6-028.sh \
                          tlp-6-029.sh \
                          tlp-6-030.sh \
                          tlp-7-001.sh \
                          tlp-7-002.sh \
                          tlp-7-003.sh \
                          tlp-7-004.sh \
                          tlp-7-005.sh \
                          tlp-8-001.sh \
                          tlp-8-002.sh \
                          tlp-8-003.sh \
                          tlp-8-004.sh \
                          tlp-9-001.sh \
                          tlp-9-002.sh \
                          tlp-9-003.sh \
                          tlp-9-004.sh \
                          chkext2mnt.sh \
                          chkext2umnt.sh

if LOADTEST
TESTS +=                  reiserfsmnt.sh \
                          getsysstats.sh
endif

TESTS +=                  chkext2fops.sh \
                          vc_inclusionproc.sh \
                          chkvc.sh \
                          chkvc_timeout.sh \
                          chkcacheintcpt.sh \
                          chkminix.sh \
                          chkminix1.sh \
                          chkminix2.sh \
                          chk_lsattr.sh \
                          tlp-cleanup.sh

check_SCRIPTS =           $(TESTS) \
			  sysctldisable.sh \
			  sysctlenable.sh \
			  sysctlchk.sh \
			  tlp-4-003a.sh \
			  tlp-4-003b.sh \
			  tlp-4-004a.sh \
			  tlp-4-004b.sh \
                          getsysstats.pl \
                          talpa-init.sh \
                          tlp-init.sh \
                          tlp-cleanup.sh \
                          test-script1.sh \
                          test-script2.sh \
                          test-script3.sh \
                          test-script4.sh

talpa-test.sh : Makefile.in
	echo "#/bin/bash" >$@
	echo "export srcdir=$(srcdir)" >>$@
	echo "export ko=$(ko)" >>$@
	echo "export interceptor_module=$(interceptor_module)" >>$@
	echo "export interceptor_name=$(interceptor_name)" >>$@
	echo 'cd $$(dirname $$0)' >>$@
	echo 'exec "$$@"' >>$@
	chmod 700 $@

runTest : $(TEST) talpa-test.sh
	bash -x ./talpa-test.sh ./$(TEST) $(TESTARGS)

EXTRA_DIST  = $(check_SCRIPTS) configure

testProgs : $(check_PROGRAMS)

.PHONY : testProgs
