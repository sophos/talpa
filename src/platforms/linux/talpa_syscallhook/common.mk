talpaSyscallHookSOURCES = src/platforms/linux/talpa_syscallhook/talpa_syscallhook.c \
				src/platforms/linux/glue.c \
				src/platforms/linux/vfs_mount.c

talpaSyscallHookOBJS    = $(talpaSyscallHookSOURCES:.c=.o)
