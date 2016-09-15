/*
* vfs_mount.c
*
* TALPA Filesystem Interceptor
*
* Copyright (C) 2004-2016 Sophos Limited, Oxford, England.
*
* This program is free software; you can redistribute it and/or modify it under the terms of the
* GNU General Public License Version 2 as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
* even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with this program; if not,
* write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*
*/
#include <linux/version.h>
#include "platforms/linux/vfs_mount.h"
#include "platforms/linux/log.h"
#include "platforms/linux/glue.h"

#ifdef TALPA_MNT_NAMESPACE
# ifndef TALPA_REPLACE_MOUNT_STRUCT
#include <linux/mnt_namespace.h>
# endif
#endif

#ifdef TALPA_REPLACE_MOUNT_STRUCT
struct talpa_mnt_pcp {
	int mnt_count;
	int mnt_writers;
};


 #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
 typedef u64 talpa_mnt_namespace_event_t;
 #else
 typedef int talpa_mnt_namespace_event_t;
 #endif

/* Changes in 3.19 */
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)

struct proc_ns_operations;

struct talpa_ns_common {
    atomic_long_t stashed;
    const struct proc_ns_operations *ops;
    unsigned int inum;
};

struct talpa_mnt_namespace {
        atomic_t                count;
        struct talpa_ns_common        ns;
        struct mount *  root;
         struct list_head        list;
         struct user_namespace   *user_ns;
         u64                     seq;    /* Sequence number to prevent loops */
         wait_queue_head_t poll;
         u64 event;
 };

 #define PROC_INUM_FROM_MNT_NAMESPACE(x) (x)->ns.inum

 #elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
struct talpa_mnt_namespace {
        atomic_t                count;
        unsigned int            proc_inum;
        struct mount *  root;
        struct list_head        list;
         struct user_namespace   *user_ns;
         u64                     seq;    /* Sequence number to prevent loops */
         wait_queue_head_t poll;
         talpa_mnt_namespace_event_t event; /* Changed to u64 in 3.15 */
 };
 #define PROC_INUM_FROM_MNT_NAMESPACE(x) (x)->proc_inum
 #else
struct talpa_mnt_namespace {
	atomic_t		count;
	struct mount *	root;
	struct list_head	list;
	wait_queue_head_t poll;
	int event;
};
/**
 * Before 3.8 mnt namespaces didn't have inodes
 * It wasn't possible for a process to join an existing mnt namespace
 */
 #define PROC_INUM_FROM_MNT_NAMESPACE(x) 0
 #endif

typedef struct talpa_mnt_namespace talpa_mnt_namespace_t;

struct talpa_replacement_mount_struct;
typedef struct talpa_replacement_mount_struct talpa_mount_struct;

 #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
 struct talpa_replacement_mount_struct {
	struct list_head mnt_hash;
	talpa_mount_struct *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
 # if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
    struct rcu_head mnt_rcu;
 # endif
 #ifdef CONFIG_SMP
	struct talpa_mnt_pcp __percpu *mnt_pcp;
 #else /* ! CONFIG_SMP */
	int mnt_count;
	int mnt_writers;
 #endif /* CONFIG_SMP */
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	talpa_mount_struct *mnt_master;	/* slave is on master->mnt_slave_list */
	struct talpa_mnt_namespace *mnt_ns;	/* containing namespace */
};
 #else /* 3.3 - 3.5 */
 struct talpa_replacement_mount_struct {
	struct list_head mnt_hash;
	talpa_mount_struct *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
 #ifdef CONFIG_SMP
	struct talpa_mnt_pcp __percpu *mnt_pcp;
	atomic_t mnt_longterm;		/* how many of the refs are longterm */
 #else
	int mnt_count;
	int mnt_writers;
 #endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct talpa_mnt_namespace *mnt_ns;	/* containing namespace */
};
 #endif /* 3.6 */

static inline talpa_mount_struct *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, talpa_mount_struct, mnt);
}

static inline struct vfsmount* vfs_mount(talpa_mount_struct* mnt)
{
    return &mnt->mnt;
}

static inline struct vfsmount* talpa_mntget(talpa_mount_struct* mnt)
{
    return mntget(&mnt->mnt);
}

static inline void talpa_mntput(talpa_mount_struct* mnt)
{
    mntput(&mnt->mnt);
}

#else
typedef struct vfsmount talpa_mount_struct;
typedef struct mnt_namespace talpa_mnt_namespace_t;
 #define PROC_INUM_FROM_MNT_NAMESPACE(x) 0


static inline talpa_mount_struct *real_mount(struct vfsmount *mnt)
{
	return mnt;
}

static inline struct vfsmount* vfs_mount(talpa_mount_struct* mnt)
{
    return mnt;
}

static inline struct vfsmount* talpa_mntget(talpa_mount_struct* mnt)
{
    return mntget(mnt);
}

static inline void talpa_mntput(talpa_mount_struct* mnt)
{
    mntput(mnt);
}

#endif /* TALPA_REPLACE_MOUNT_STRUCT */

struct vfsmount* getParent(struct vfsmount* mnt)
{
#ifndef TALPA_REPLACE_MOUNT_STRUCT
    return mnt->mnt_parent;
#else
    talpa_mount_struct *realmnt = real_mount(mnt);
    return &(realmnt->mnt_parent->mnt);
#endif
}

/**
 * @return borrowed reference to device name
 */
const char *getDeviceName(struct vfsmount* mnt)
{
    talpa_mount_struct *realmnt = real_mount(mnt);
    return realmnt->mnt_devname;
}

#ifdef TALPA_MNT_NAMESPACE
struct mnt_namespace *getNamespaceInfo(struct vfsmount* mnt)
{
    talpa_mount_struct *realmnt = real_mount(mnt);
    return (struct mnt_namespace *)realmnt->mnt_ns;
}

#endif

/**
 */
struct dentry *getVfsMountPoint(struct vfsmount* mnt)
{
    talpa_mount_struct *realmnt = real_mount(mnt);
    dbg("%p", realmnt->mnt_mountpoint);
    return realmnt->mnt_mountpoint;
}


int iterateFilesystems(struct vfsmount* root, int (*callback) (struct vfsmount* mnt, unsigned long flags, bool fromMount))
{
    talpa_mount_struct *mnt, *nextmnt, *prevmnt;
    struct list_head *nexthead = NULL;
    int ret;
    unsigned m_seq = 1;

    mnt = real_mount(root);
    talpa_mntget(mnt); /* Take extra reference count for the loop */
    do
    {
        struct vfsmount* vfsmnt = vfs_mount(mnt);
        dbg("VFSMNT: 0x%p (at 0x%p), sb: 0x%p, dev: %s, flags: 0x%lx, fs: %s", mnt, mnt->mnt_parent,
                vfsmnt->mnt_sb, mnt->mnt_devname, vfsmnt->mnt_sb->s_flags, vfsmnt->mnt_sb->s_type->name);

        ret = callback(vfsmnt, vfsmnt->mnt_sb->s_flags, false);
        if (ret)
        {
            break;
        }

        talpa_vfsmount_lock(&m_seq); /* locks dcache_lock on 2.4 */

        /* Go down the tree for a child if there is one */
        if ( !list_empty(&mnt->mnt_mounts) )
        {
            nextmnt = list_entry(mnt->mnt_mounts.next, talpa_mount_struct, mnt_child);
        }
        else
        {
            nextmnt = mnt;
            /* If no children, go up until we found some. Abort on root. */
            while ( nextmnt != nextmnt->mnt_parent )
            {
                nexthead = nextmnt->mnt_child.next;
                /* Take next child if available */
                if ( nexthead != &nextmnt->mnt_parent->mnt_mounts )
                {
                    break;
                }
                /* Otherwise go up the tree */
                nextmnt = nextmnt->mnt_parent;
            }

            /* Abort if we are at the root */
            if ( nextmnt == nextmnt->mnt_parent )
            {
                talpa_vfsmount_unlock(&m_seq); /* unlocks dcache_lock on 2.4 */
                talpa_mntput(mnt);
                break;
            }

            /* Take next mount from the list */
            nextmnt = list_entry(nexthead, talpa_mount_struct, mnt_child);
        }

        talpa_mntget(nextmnt);
        prevmnt = mnt;
        mnt = nextmnt;
        talpa_vfsmount_unlock(&m_seq); /* unlocks dcache_lock on 2.4 */
        talpa_mntput(prevmnt);
    } while (mnt);

    /* Don't mntput root as we didn't take a reference for ourselves */

    return ret;
}

/* Implement countPropagationPoints, copying code from pnode.c to do it */

#ifdef TALPA_SHARED_MOUNTS

static inline talpa_mount_struct *next_peer(talpa_mount_struct *p)
{
        return list_entry(p->mnt_share.next, talpa_mount_struct, mnt_share);
}

static inline talpa_mount_struct *first_slave(talpa_mount_struct *p)
{
        return list_entry(p->mnt_slave_list.next, talpa_mount_struct, mnt_slave);
}

static inline talpa_mount_struct *next_slave(talpa_mount_struct *p)
{
        return list_entry(p->mnt_slave.next, talpa_mount_struct, mnt_slave);
}

/* TALPA_VFSMOUNT_NAMESPACE is either mnt_namespace or mnt_ns */
#define IS_MNT_NEW(m)  (!(m)->TALPA_VFSMOUNT_NAMESPACE)


/*
 * get the next mount in the propagation tree.
 * @m: the mount seen last
 * @origin: the original mount from where the tree walk initiated
 *
 * Note that peer groups form contiguous segments of slave lists.
 * We rely on that in get_source() to be able to find out if
 * vfsmount found while iterating with propagation_next() is
 * a peer of one we'd found earlier.
 */
static talpa_mount_struct *propagation_next(talpa_mount_struct *m,
                                         talpa_mount_struct *origin)
{
    /* are there any slaves of this mount? */
    if (!IS_MNT_NEW(m) && !list_empty(&m->mnt_slave_list))
            return first_slave(m);

    while (1) {
            talpa_mount_struct *master = m->mnt_master;

            if (master == origin->mnt_master) {
                    talpa_mount_struct *next = next_peer(m);
                    return (next == origin) ? NULL : next;
            } else if (m->mnt_slave.next != &master->mnt_slave_list)
                    return next_slave(m);

            /* back at master */
            m = master;
    }
}

/*
 *  struct mount *__lookup_mnt_last(struct vfsmount *mnt, struct dentry *dentry)
 *  talpa_mount_struct *__lookup_mnt_last(struct vfsmount *mnt, struct dentry *dentry)
 */
#ifdef TALPA_HAVE_LOOKUP_MNT_LAST
typedef talpa_mount_struct *(*lookup_mnt_last_func)(struct vfsmount *mnt, struct dentry *dentry);
#endif
#ifdef TALPA_HAVE_LOOKUP_MNT
typedef talpa_mount_struct *(*lookup_mnt_func)(struct vfsmount *mnt, struct dentry *dentry, int dir);
#endif

/*
 * Mark the function pointer as 'volatile' to avoid gcc bug/error:
 * "immediate operand illegal with absolute jump"
 *
 * Should be fixed in GCC 4.6.2
 */
#define TALPA_GCC_VERSION(A,B,C) ((A) * 10000 + (B) * 100 + (C))
#define TALPA_GCC_VERSION_CODE TALPA_GCC_VERSION(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__)

#if TALPA_GCC_VERSION_CODE < TALPA_GCC_VERSION(4,6,2)
# define TALPA_PTR_FIX volatile
#else
# define TALPA_PTR_FIX
#endif

static talpa_mount_struct* talpa_lookup_mnt_last(struct vfsmount *mnt, struct dentry *dentry)
{
#ifdef TALPA_HAVE_LOOKUP_MNT_LAST
    TALPA_PTR_FIX lookup_mnt_last_func lookup_mnt_last = (lookup_mnt_last_func)talpa_get_symbol("__lookup_mnt_last", (void *)TALPA__LOOKUP_MNT_LAST);
    return lookup_mnt_last(mnt, dentry);
#endif
#ifdef TALPA_HAVE_LOOKUP_MNT
    TALPA_PTR_FIX lookup_mnt_func lookup_mnt = (lookup_mnt_func)talpa_get_symbol("__lookup_mnt", (void *)TALPA__LOOKUP_MNT);
    return lookup_mnt(mnt, dentry, 0);
#endif
    return NULL;
}


# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#  ifdef DEBUG
#   define DEBUG_PROPAGATION_POINTS
#  endif
# endif

# ifdef DEBUG_PROPAGATION_POINTS
/* calls d_path with dentry and vfsmount */
static char* absolutePath(struct dentry *dentry, struct vfsmount *mnt, char* pathBuffer, int path_size)
{
    struct path pathPath;
    char* path;

    if ( !pathBuffer )
    {
        return NULL;
    }

    pathPath.dentry = dentry;
    pathPath.mnt = mnt;

    path = d_path(&pathPath, pathBuffer, path_size);

    if ( unlikely( IS_ERR(path) != 0 ) )
    {
        critical("talpa__d_path: d_path returned an error: %ld",PTR_ERR(path));
        path = NULL;
    }
    return path;
}
# endif /* DEBUG_PROPAGATION_POINTS */
#endif /* TALPA_SHARED_MOUNTS */

/**
 * We iterate all the possible parents of our mount point,
 * and see if they also have a mount on the same mount point.
 */
int countPropagationPoints(struct vfsmount* vmnt)
{
#ifdef TALPA_SHARED_MOUNTS

    talpa_mount_struct *mnt = real_mount(vmnt);
    talpa_mount_struct *parent = mnt->mnt_parent;
    talpa_mount_struct *child = NULL;
    talpa_mount_struct *m;
    int ret = 1;

    unsigned m_seq = 1;

#ifdef DEBUG_PROPAGATION_POINTS
    talpa_mnt_namespace_t* ns;
    size_t path_size = 0;
    char* path = talpa_alloc_path_atomic(&path_size);
    const char* p = absolutePath(mnt->mnt_mountpoint,vfs_mount(parent), path, path_size);

    if (unlikely( path == NULL ))
    {
        warn("talpa_alloc_path failed");
        return 0;
    }

    ns = mnt->mnt_ns;
    dbg("PATH START: %s ns=%p ns.ns.inum=%u",p,ns,PROC_INUM_FROM_MNT_NAMESPACE(ns));

    ns = parent->mnt_ns;
    p = absolutePath(parent->mnt_mountpoint,vfs_mount(parent->mnt_parent), path, path_size);
    dbg("PARENT: %s ns=%p ns.ns.inum=%u",p,ns,PROC_INUM_FROM_MNT_NAMESPACE(ns));
#endif /* DEBUG_PROPAGATION_POINTS */

    talpa_vfsmount_lock(&m_seq); /* locks dcache_lock on 2.4 */

    /**
     * Iterate all possible shared/slave destination parents for copies of vmnt
     */
    for (m = propagation_next(parent, parent); m;
            m = propagation_next(m, parent))
    {
        child = talpa_lookup_mnt_last(vfs_mount(m), mnt->mnt_mountpoint);
        if (child)
        {
#ifdef DEBUG_PROPAGATION_POINTS
            /* absolutePath() locks up in d_path() if vfsmount_lock is already held */
            p = child->mnt_mountpoint->d_name.name;
            ns = child->mnt_ns;
            dbg("CHILD: %s ns=%p ns.ns.inum=%u",p,ns,PROC_INUM_FROM_MNT_NAMESPACE(ns));
#endif /* DEBUG_PROPAGATION_POINTS */
            if (list_empty(&child->mnt_mounts))
            {
                ret += 1;
            }
        }
    }
    talpa_vfsmount_unlock(&m_seq); /* unlocks dcache_lock on 2.4 */

#ifdef DEBUG_PROPAGATION_POINTS
    talpa_free_path(path);
#endif
    return ret;
#else /* ! TALPA_SHARED_MOUNTS */
    return 1;
#endif /* TALPA_SHARED_MOUNTS */
}
