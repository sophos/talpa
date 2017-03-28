
talpaCoreSOURCES    =  src/app-ctrl/core/talpa-core/talpa_core_module.c \
                       src/components/core/intercept_processing_impl/std_intercept_processor.c \
                       src/components/core/intercept_processing_impl/evaluation_report_impl.c \
                       src/components/core/intercept_filters_impl/syslog/syslog_filter.c \
                       src/components/core/intercept_filters_impl/deny_syslog/deny_syslog.c \
                       src/components/core/intercept_filters_impl/allow_syslog/allow_syslog.c \
                       src/components/core/intercept_filters_impl/operation_excl/operation_excl.c \
                       src/components/core/intercept_filters_impl/fsobj_incl/filesystem_inclusion_processor.c \
                       src/components/core/intercept_filters_impl/fsobj_excl/filesystem_exclusion_processor.c \
                       src/components/core/intercept_filters_impl/vetting_ctrl/vetting_ctrl.c \
                       src/components/core/intercept_filters_impl/proc_excl/process_exclusion.c \
                       src/components/core/intercept_filters_impl/degraded_mode/degraded_mode.c \
                       src/components/core/cache_impl/cache.c \
                       src/components/core/intercept_filters_impl/cache/cache_eval.c \
                       src/components/core/intercept_filters_impl/cache/cache_allow.c \
                       src/components/core/intercept_filters_impl/cache/cache_deny.c

talpaCoreOBJS       =  $(talpaCoreSOURCES:.c=.o)
