
if [ "$testfunctionsincluded" = "yes" ]; then
    true
else
    _mount_fs="dummy"

    function get_mount_fs()
    {
        rc=1
        mnt="$1"

        exec 6<&0
        exec < /proc/mounts

        while read des fs type rest; do
            test "$fs" != "$mnt" -o "$type" = "rootfs" && continue
            _mount_fs="${type}"
            rc=0
            break
        done

        if test $rc -ne 0; then
            mnt=/
        fi

        rc=1

        exec 0>&6 6<&-

        exec 6<&0
        exec < /proc/mounts

        while read des fs type rest; do
            test "$fs" != "$mnt" -o "$type" = "rootfs" && continue
            _mount_fs="${type}"
            rc=0
            break
        done

        exec 0>&6 6<&-

        return $rc
    }

    function find_talpa_config
    {
        talpafs=""
        talpafstype=""
        talpaprocfs=""
        talpasecurityfs=""
        talpadualfs=""

        if [ -d /sys/kernel/security/talpa ]; then
            talpafstype=securityfs
            talpafs=/sys/kernel/security/talpa
            talpasecurityfs=yes
        fi

        if [ -d /proc/sys/talpa ]; then
            talpaprocfs=yes
            if [ "$talpafs" = "" ]; then
                talpafs=/proc/sys/talpa
                talpafstype=procfs
            else
                talpadualfs=yes
                talpafstype=dualfs
            fi
        fi

        export talpafs talpafstype talpaprocfs talpasecurityfs talpadualfs

        return 0
    }

    function tlp_insmod
    {
        insmod $*
        rc=$?
        find_talpa_config

        return $rc
    }

    function talpa_load
    {
        sync

        tlp_insmod ../talpa_linux.${ko}
        tlp_insmod ../talpa_core.${ko}
        tlp_insmod ../talpa_vcdevice.${ko}
        tlp_insmod ../talpa_pedevice.${ko}
        tlp_insmod ../talpa_pedconnector.${ko}
        if test "$interceptor_module" = "syscall"; then
            tlp_insmod ../talpa_syscallhook.${ko}
        fi
        if test "$interceptor_module" = "vfshook"; then
            tlp_insmod ../talpa_syscallhook.${ko} hook_mask=mu
        fi
        tlp_insmod ../talpa_${interceptor_module}.${ko}
    }

    function talpa_defaults
    {
        echo disable >${talpafs}/intercept-filters/DebugSyslog/status
        echo +proc >${talpafs}/intercept-filters/FilesystemExclusionProcessor/fstypes
        echo /tmp/tlp-test/ >${talpafs}/intercept-filters/FilesystemInclusionProcessor/include-path
        echo enable >${talpafs}/intercept-filters/FilesystemInclusionProcessor/status
        echo enable >${talpafs}/intercept-filters/ProcessExclusionProcessor/status
        echo enable >${talpafs}/intercept-filters/Cache/status
        echo enable >${talpafs}/intercept-filters/DegradedModeProcessor/status
    }

    function talpa_enable
    {
        echo enable >${talpafs}/interceptors/${interceptor_name}/status
    }

    function talpa_disable
    {
        if test -f ${talpafs}/interceptors/${interceptor_name}/status; then
            echo disable >${talpafs}/interceptors/${interceptor_name}/status
        fi
    }

    function talpa_unload
    {
        sync

        # Before syscallhook
        rmmod tlp-syscalltable 2>/dev/null

        rmmod talpa_${interceptor_module} 2>/dev/null
        if test "$interceptor_module" = "syscall" -o "$interceptor_module" = "vfshook"; then
            rmmod talpa_syscallhookprobe 2>/dev/null
            rmmod talpa_syscallhook 2>/dev/null
        fi
        rmmod talpa_pedconnector 2>/dev/null
        rmmod talpa_pedevice 2>/dev/null
        rmmod talpa_vcdevice 2>/dev/null
        rmmod talpa_core 2>/dev/null
        rmmod talpa_linux 2>/dev/null

        rmmod tlp-personality 2>/dev/null
        rmmod tlp-fileinfo 2>/dev/null
        rmmod tlp-filesysteminfo 2>/dev/null
        rmmod tlp-syslog 2>/dev/null
        rmmod tlp-procfs 2>/dev/null
        rmmod tlp-securityfs 2>/dev/null
        rmmod tlp-dualfs 2>/dev/null
        rmmod tlp-stdinterceptor 2>/dev/null
        rmmod tlp-inclusion 2>/dev/null
        rmmod tlp-opexcl 2>/dev/null
        rmmod tlp-allowsyslog 2>/dev/null
        rmmod tlp-denysyslog 2>/dev/null
        rmmod tlp-threadinfo 2>/dev/null
        rmmod tlp-exclusion 2>/dev/null
        rmmod tlp-ddvc 2>/dev/null
        rmmod tlp-cache 2>/dev/null
        rmmod tlp-cacheobj 2>/dev/null
        rmmod tlp-degrmode 2>/dev/null
        rmmod tlp-file 2>/dev/null
        rmmod tlp-wronginterceptor 2>/dev/null
    }

    find_talpa_config

    testfunctionsincluded=yes
fi
