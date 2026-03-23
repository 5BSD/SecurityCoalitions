/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * vBSD Coalition - Capability-based resource group management
 *
 * Coalitions group processes, jails, and other capability-bearing resources
 * that should be managed (and revoked) as a unit.
 */

#ifndef _SYS_VBSD_COALITION_H_
#define _SYS_VBSD_COALITION_H_

#include <sys/types.h>
#include <sys/ioccom.h>

/* ioctl commands - coalition takes reference, caller keeps fd */

#define VBSD_COALITION_ENLIST		_IOW('V', 1, int)
#define VBSD_COALITION_JOIN		_IO('V', 2)
#define VBSD_COALITION_TERMINATE	_IO('V', 3)
#define VBSD_COALITION_ENLIST_SET	_IOWR('V', 4, struct vbsd_enlist_set)
#define VBSD_COALITION_STAT		_IOR('V', 5, struct vbsd_coalition_stat)
#define VBSD_COALITION_SET_SIGNAL	_IOW('V', 6, int)
#define VBSD_COALITION_TERMINATE_GRACEFUL _IOW('V', 7, struct vbsd_graceful)
#define VBSD_COALITION_SET_DEADLINE	_IOW('V', 8, struct vbsd_deadline)
#define VBSD_COALITION_SET_WATCHDOG	_IOW('V', 9, uint32_t)
#define VBSD_COALITION_HEARTBEAT	_IO('V', 10)
#define VBSD_COALITION_SET_LEADER	_IOW('V', 11, int)
#define VBSD_COALITION_RUSAGE		_IOR('V', 12, struct vbsd_coalition_rusage)

/* Batch enlistment - stops on first error, 'enlisted' returns success count */
struct vbsd_enlist_set {
	const int	*fds;		/* Pointer to fd array */
	u_int		count;		/* Number of fds to enlist */
	u_int		enlisted;	/* OUT: number successfully enlisted */
};

struct vbsd_coalition_stat {
	u_int		vcs_member_count;	/* Total members */
	u_int		vcs_flags;		/* VCF_* flags */
	int		vcs_signal;		/* Termination signal */
	u_int		vcs_nested_count;	/* Nested coalition members */
	u_int		vcs_nesting_depth;	/* Depth if nested in another */
	u_int		vcs_process_count;	/* Process members */
	u_int		vcs_jail_count;		/* Jail members */
	u_int		vcs_other_count;	/* Other member types */
};

#define VBSD_STAT_TERMINATING	0x0001
struct vbsd_graceful {
	int		vg_signal;	/* Signal to send first (e.g., SIGTERM) */
	u_int		vg_timeout_ms;	/* Grace period in milliseconds */
};

/* timeout_ms=0 cancels deadline */
struct vbsd_deadline {
	uint32_t	vd_timeout_ms;	/* Time until termination (0 = cancel) */
	int		vd_signal;	/* Signal before SIGKILL (0 = immediate) */
	uint32_t	vd_grace_ms;	/* Grace period after signal */
};

/* Aggregated resource stats for all process members */
struct vbsd_coalition_rusage {
	uint32_t	vcr_nprocs;
	uint32_t	vcr_nthreads;
	uint64_t	vcr_rss_bytes;
	uint64_t	vcr_vsz_bytes;
	uint64_t	vcr_user_usec;
	uint64_t	vcr_sys_usec;
	uint64_t	vcr_inblock;
	uint64_t	vcr_oublock;
	uint64_t	vcr_majflt;
	uint64_t	vcr_minflt;
	uint64_t	vcr_spare[4];
};

/* Kqueue event flags (EVFILT_READ, delivered in fflags) */
#define VBSD_NOTE_MEMBER_ADDED		0x0001	/* New member enlisted */
#define VBSD_NOTE_MEMBER_REMOVED	0x0002	/* Member exited/removed */
#define VBSD_NOTE_TERMINATING		0x0004	/* Termination started */
#define VBSD_NOTE_TERMINATED		0x0008	/* All members terminated */
#define VBSD_NOTE_LEADER_DIED		0x0010	/* Leader death triggered term */
#define VBSD_NOTE_DEADLINE_FIRED	0x0020	/* Deadline timer expired */
#define VBSD_NOTE_WATCHDOG_FIRED	0x0040	/* Watchdog timeout */
#define VBSD_NOTE_GRACE_STARTED		0x0080	/* Grace period began */

#define VBSD_NOTE_ALL			0x00FF	/* All events */

/* Maximum nesting depth to prevent infinite loops */
#define VBSD_MAX_NESTING_DEPTH	16

#ifdef _KERNEL

#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/callout.h>
#include <sys/taskqueue.h>
#include <sys/event.h>
#include <sys/eventhandler.h>

/* Public API */

/*
 * Third-party member operations.
 *
 * Modules register ops to integrate custom descriptor types with coalitions.
 * Set mo_flags to indicate capabilities (e.g., MOF_CAN_LEAD).
 */
struct vbsd_member_ops {
	int		(*mo_terminate)(struct file *fp, struct thread *td);
	const char	*mo_name;
	uint32_t	mo_flags;
};

/* mo_flags */
#define MOF_CAN_LEAD	0x0001	/* This type can be a coalition leader */

/*
 * Register ops for a new descriptor type. Coalition assigns the dtype.
 * Returns 0 on success, dtype is stored in *dtype_out.
 * Use the returned dtype in finit() when creating your descriptors.
 */
int	vbsd_member_ops_register(struct vbsd_member_ops *ops, int *dtype_out);
int	vbsd_member_ops_deregister(int dtype);

/*
 * Leader death notification event.
 *
 * Third-party modules fire this event when a resource that may be a
 * coalition leader dies. Coalition handles lookup and termination.
 *
 * Usage:
 *     EVENTHANDLER_INVOKE(vbsd_leader_died, fp);
 *
 * Or use the convenience macro:
 *     VBSD_LEADER_DIED(fp);
 */
typedef void (*vbsd_leader_died_fn)(void *arg, struct file *fp);
EVENTHANDLER_DECLARE(vbsd_leader_died, vbsd_leader_died_fn);

#define VBSD_LEADER_DIED(fp)	EVENTHANDLER_INVOKE(vbsd_leader_died, fp)
#ifdef _SYS_MODULE_H_
static __inline bool
vbsd_coalition_available(void)
{

	return (module_lookupbyname("vbsd_coalition") != NULL);
}
#endif /* _SYS_MODULE_H_ */

/* Internal Structures */

#ifdef _VBSD_COALITION_INTERNAL

struct prison;

#define VCF_TERMINATING		0x0001
#define VCF_DEADLINE_ACTIVE	0x0002	/* Deadline timer is running */
#define VCF_DEADLINE_GRACE	0x0004	/* In grace period after initial signal */
#define VCF_WATCHDOG_ACTIVE	0x0008	/* Watchdog timer is running */
#define VCF_HAS_LEADER		0x0010	/* Leader process is set */

/* Lock order: vbsd_proc_hash_lock -> vc_sx */
struct vbsd_coalition {
	struct sx			vc_sx;
	TAILQ_HEAD(, vbsd_member)	vc_members;
	u_int				vc_flags;
	int				vc_signal;
	u_int				vc_nesting_depth;
	volatile u_int			vc_member_count;
	u_int				vc_refcount;
	struct callout			vc_deadline_callout;
	struct task			vc_deadline_task;
	int				vc_deadline_signal;
	uint32_t			vc_deadline_grace_ms;
	struct callout			vc_watchdog_callout;
	struct task			vc_watchdog_task;
	uint32_t			vc_watchdog_timeout_ms;
	struct vbsd_member		*vc_leader;
	pid_t				vc_leader_pid;
	struct vbsd_member		*vc_leader_of;
	struct knlist			vc_knlist;
};

struct vbsd_member {
	TAILQ_ENTRY(vbsd_member)	vm_link;
	LIST_ENTRY(vbsd_member)		vm_hash;
	struct file			*vm_fp;
	struct vbsd_member_ops		*vm_ops;
	struct vbsd_coalition		*vm_coalition;
	void				*vm_data;
	int				vm_dtype;
};

#endif /* _VBSD_COALITION_INTERNAL */

#endif /* _KERNEL */

#endif /* _SYS_VBSD_COALITION_H_ */
