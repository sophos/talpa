
tlpPersonalitySOURCES    =  tlp_personality.c \
                            src/components/services/linux_personality_impl/linux_personality.c

tlpPersonalityOBJS       =  $(tlpPersonalitySOURCES:.c=.o)

tlpFileInfoSOURCES    =  tlp_fileinfo.c \
                         src/platforms/linux/glue.c \
                         src/platforms/linux/vfs_mount.c \
                         src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                         src/components/services/linux_filesystem_impl/linux_systemroot.c

tlpFileInfoOBJS       =  $(tlpFileInfoSOURCES:.c=.o)

tlpFilesystemInfoSOURCES    =  tlp_filesysteminfo.c \
                             src/platforms/linux/glue.c \
                             src/platforms/linux/vfs_mount.c \
                             src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                             src/components/services/linux_filesystem_impl/linux_systemroot.c

tlpFilesystemInfoOBJS       =  $(tlpFilesystemInfoSOURCES:.c=.o)

tlpSyslogSOURCES    =  tlp_syslog.c \
                     src/platforms/linux/glue.c \
                     src/platforms/linux/vfs_mount.c \
                     src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                     src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                     src/components/services/linux_filesystem_impl/linux_systemroot.c \
                     src/components/services/linux_personality_impl/linux_personality.c \
                     src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                     src/components/core/intercept_filters_impl/syslog/syslog_filter.c

tlpSyslogOBJS       =  $(tlpSyslogSOURCES:.c=.o)

tlpProcfsSOURCES    =  tlp_procfs.c \
                     src/components/services/configurator_impl/procfs_configurator.c

tlpProcfsOBJS       =  $(tlpProcfsSOURCES:.c=.o)

tlpSecurityfsSOURCES    =  tlp_securityfs.c \
                          src/components/services/configurator_impl/securityfs_configurator.c

tlpSecurityfsOBJS       =  $(tlpSecurityfsSOURCES:.c=.o)

tlpDualfsSOURCES    =  tlp_dualfs.c \
                       src/components/services/configurator_impl/dualfs_configurator.c \
                       src/components/services/configurator_impl/procfs_configurator.c \
                       src/components/services/configurator_impl/securityfs_configurator.c

tlpDualfsOBJS       =  $(tlpDualfsSOURCES:.c=.o)

tlpStdInterceptorSOURCES    =  tlp_stdinterceptor.c \
                             src/platforms/linux/glue.c \
                             src/platforms/linux/vfs_mount.c \
                             src/components/services/linux_filesystem_impl/linux_file.c \
                             src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                             src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                             src/components/services/linux_filesystem_impl/linux_filesystem_factoryimpl.c \
                             src/components/services/linux_filesystem_impl/linux_systemroot.c \
                             src/components/services/linux_personality_impl/linux_personality.c \
                             src/components/services/linux_personality_impl/linux_personality_factoryimpl.c \
                             src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                             src/components/core/intercept_processing_impl/std_intercept_processor.c

tlpStdInterceptorOBJS       =  $(tlpStdInterceptorSOURCES:.c=.o)

tlpInclusionSOURCES    =  tlp_inclusion.c \
                        src/platforms/linux/glue.c \
                        src/platforms/linux/vfs_mount.c \
                        src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                        src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                        src/components/services/linux_filesystem_impl/linux_systemroot.c \
                        src/components/services/linux_personality_impl/linux_personality.c \
                        src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                        src/components/core/intercept_filters_impl/fsobj_incl/filesystem_inclusion_processor.c

tlpInclusionOBJS       =  $(tlpInclusionSOURCES:.c=.o)

tlpOpExclSOURCES    =  tlp_opexcl.c \
                     src/platforms/linux/glue.c \
                     src/platforms/linux/vfs_mount.c \
                     src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                     src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                     src/components/services/linux_filesystem_impl/linux_systemroot.c \
                     src/components/services/linux_personality_impl/linux_personality.c \
                     src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                     src/components/core/intercept_filters_impl/operation_excl/operation_excl.c

tlpOpExclOBJS       =  $(tlpOpExclSOURCES:.c=.o)

tlpDenySyslogSOURCES    =  tlp_denysyslog.c \
                         src/platforms/linux/glue.c \
                         src/platforms/linux/vfs_mount.c \
                         src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                         src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                         src/components/services/linux_filesystem_impl/linux_systemroot.c \
                         src/components/services/linux_personality_impl/linux_personality.c \
                         src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                         src/components/core/intercept_filters_impl/deny_syslog/deny_syslog.c \
                         src/components/services/configurator_impl/procfs_configurator.c

tlpDenySyslogOBJS       =  $(tlpDenySyslogSOURCES:.c=.o)

tlpThreadInfoSOURCES    =  tlp_threadinfo.c \
                         src/platforms/linux/glue.c \
                         src/platforms/linux/vfs_mount.c \
                         src/components/services/linux_processandthread_impl/linux_threadinfo.c \
                         src/components/services/linux_filesystem_impl/linux_systemroot.c

tlpThreadInfoOBJS       =  $(tlpThreadInfoSOURCES:.c=.o)

tlpExclusionSOURCES    =  tlp_exclusion.c \
                        src/platforms/linux/glue.c \
                        src/platforms/linux/vfs_mount.c \
                        src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                        src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                        src/components/services/linux_filesystem_impl/linux_systemroot.c \
                        src/components/services/linux_personality_impl/linux_personality.c \
                        src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                        src/components/core/intercept_filters_impl/fsobj_excl/filesystem_exclusion_processor.c \
                        src/components/services/configurator_impl/procfs_configurator.c

tlpExclusionOBJS       =  $(tlpExclusionSOURCES:.c=.o)

tlpDDVCSOURCES    =  tlp_ddvc.c \
                   src/components/filter-iface/vetting-clients/device_driver_vc_impl/device_driver_vetting_client.c

tlpDDVCOBJS       =  $(tlpDDVCSOURCES:.c=.o)

tlpCacheObjSOURCES    =  tlp_cacheobj.c \
                       src/platforms/linux/glue.c \
                       src/platforms/linux/vfs_mount.c \
                       src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                       src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                       src/components/services/linux_filesystem_impl/linux_systemroot.c \
                       src/components/services/linux_personality_impl/linux_personality.c \
                       src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                       src/components/core/cache_impl/cache.c \
                       src/components/services/configurator_impl/procfs_configurator.c

tlpCacheObjOBJS       =  $(tlpCacheObjSOURCES:.c=.o)

tlpCacheSOURCES    =  tlp_cache.c \
                    src/platforms/linux/glue.c \
                    src/platforms/linux/vfs_mount.c \
                    src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                    src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                    src/components/services/linux_filesystem_impl/linux_systemroot.c \
                    src/components/services/linux_personality_impl/linux_personality.c \
                    src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                    src/components/core/cache_impl/cache.c \
                    src/components/core/intercept_filters_impl/cache/cache_eval.c \
                    src/components/core/intercept_filters_impl/cache/cache_allow.c \
                    src/components/core/intercept_filters_impl/cache/cache_deny.c \
                    src/components/services/configurator_impl/procfs_configurator.c

tlpCacheOBJS       =  $(tlpCacheSOURCES:.c=.o)

tlpDegrModeSOURCES    =  tlp_degrmode.c \
                       src/platforms/linux/glue.c \
                       src/platforms/linux/vfs_mount.c \
                       src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                       src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                       src/components/services/linux_filesystem_impl/linux_systemroot.c \
                       src/components/services/linux_personality_impl/linux_personality.c \
                       src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                       src/components/core/intercept_filters_impl/degraded_mode/degraded_mode.c \
                       src/components/services/configurator_impl/procfs_configurator.c

tlpDegrModeOBJS       =  $(tlpDegrModeSOURCES:.c=.o)

tlpFileSOURCES    =  tlp_file.c \
                     src/platforms/linux/glue.c \
                     src/platforms/linux/vfs_mount.c \
                     src/components/services/linux_filesystem_impl/linux_file.c

tlpFileOBJS       =  $(tlpFileSOURCES:.c=.o)

tlpWrongInterceptorSOURCES    =  tlp_wronginterceptor.c

tlpWrongInterceptorOBJS      =  $(tlpWrongInterceptorSOURCES:.c=.o)

tlpSyscallTableSOURCES    =  tlp_syscalltable.c

tlpSyscallTableOBJS       =  $(tlpSyscallTableSOURCES:.c=.o)
