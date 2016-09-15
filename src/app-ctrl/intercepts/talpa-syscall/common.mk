
talpaSyscallSOURCES =  src/app-ctrl/intercepts/talpa-syscall/talpa_syscall_module.c \
                       src/platforms/linux/glue.c \
                       src/platforms/linux/vfs_mount.c \
                       src/components/intercepts/syscall_impl/syscall_interceptor.c

talpaSyscallOBJS    =  $(talpaSyscallSOURCES:.c=.o)
