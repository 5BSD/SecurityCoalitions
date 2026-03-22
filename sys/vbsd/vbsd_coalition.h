/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * vBSD Coalition - Capability-based resource group management
 *
 * Coalitions group processes, jails, and other capability-bearing resources
 * that should be managed (and revoked) as a unit. External modules can
 * register their own member types via vbsd_member_ops.
 *
 * INTEGRATION GUIDE FOR EXTERNAL MODULES
 * ======================================
 *
 * To add coalition support to your descriptor type:
 *
 * 1. Define your terminate function:
 *
 *    static int
 *    mytype_coalition_terminate(struct file *fp, struct thread *td)
 *    {
 *        struct mytype *m = fp->f_data;
 *        MYTYPE_LOCK(m);
 *        m->revoked = true;
 *        wakeup(m);
 *        MYTYPE_UNLOCK(m);
 *        return (0);
 *    }
 *
 * 2. Define your ops structure:
 *
 *    static struct vbsd_member_ops mytype_coalition_ops = {
 *        .mo_terminate = mytype_coalition_terminate,
 *        .mo_name = "mytype",
 *    };
 *
 * 3a. Register at module load (REQUIRED coalition support):
 *
 *    MODULE_DEPEND(mymodule, vbsd_coalition, 1, 1, 1);
 *
 *    static int
 *    mytype_modevent(module_t mod, int type, void *arg)
 *    {
 *        switch (type) {
 *        case MOD_LOAD:
 *            vbsd_member_ops_register(DTYPE_MYTYPE, &mytype_coalition_ops);
 *            // ... rest of init ...
 *            return (0);
 *        case MOD_UNLOAD:
 *            vbsd_member_ops_deregister(DTYPE_MYTYPE);
 *            return (0);
 *        }
 *    }
 *
 * 3b. Register at module load (OPTIONAL coalition support):
 *
 *    #include <sys/module.h>
 *
 *    static int
 *    mytype_modevent(module_t mod, int type, void *arg)
 *    {
 *        switch (type) {
 *        case MOD_LOAD:
 *            // Only register if coalition module is loaded
 *            if (vbsd_coalition_available())
 *                vbsd_member_ops_register(DTYPE_MYTYPE, &mytype_coalition_ops);
 *            // ... rest of init ...
 *            return (0);
 *        case MOD_UNLOAD:
 *            if (vbsd_coalition_available())
 *                vbsd_member_ops_deregister(DTYPE_MYTYPE);
 *            return (0);
 *        }
 *    }
 *
 * With optional support, your module works with or without coalition.
 *
 * DTYPE ALLOCATION
 * ================
 *
 * Each descriptor type needs a unique DTYPE_* constant (see sys/file.h).
 * Use finit() to set the type when creating your descriptor:
 *
 *    finit(fp, FREAD | FWRITE, DTYPE_MYTYPE, data, &mytype_fileops);
 *
 * DTYPE ranges:
 *    0-31     Reserved for FreeBSD (DTYPE_VNODE, DTYPE_SOCKET, etc.)
 *    32-255   Available for external modules
 *
 * Example for external module:
 *
 *    #ifndef DTYPE_MYTYPE
 *    #define DTYPE_MYTYPE  33  // Pick unused value in 32-255
 *    #endif
 *
 * To avoid collisions, consider documenting your DTYPE allocation or
 * submitting a patch to FreeBSD to reserve it officially.
 */

#ifndef _SYS_VBSD_COALITION_H_
#define _SYS_VBSD_COALITION_H_

#include <sys/types.h>
#include <sys/ioccom.h>

/*
 * User-space ioctl commands
 *
 * All enlistment operations use REFERENCE SEMANTICS:
 *   - Coalition takes its own reference to the enlisted resource
 *   - Caller RETAINS their file descriptor (not closed)
 *   - Caller can continue using fd (e.g., waitpid on process, query jail)
 *   - Caller is responsible for closing their fd when done
 *   - Coalition still terminates resources when closed/terminated
 *
 * This allows the authority holder to:
 *   - Monitor enlisted processes (waitpid, pdkill with signal 0)
 *   - Query status of enlisted resources
 *   - Maintain a separate handle for cleanup verification
 */
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

/*
 * Batch enlistment structure.
 *
 * Enlist multiple file descriptors in a single call. Processing stops
 * on first error; 'enlisted' returns the count of successful enlistments.
 *
 * Reference semantics: The coalition takes its own reference to each
 * enlisted resource. The caller retains their file descriptor and can
 * continue using it (e.g., for monitoring process status via waitpid).
 * Caller is responsible for closing their fd when done.
 *
 * Maximum batch size is tunable via sysctl kern.coalition.enlist_set_max
 * (default 1024). Requests exceeding the limit return EINVAL.
 *
 * Example:
 *   int fds[] = {fd1, fd2, fd3};
 *   struct vbsd_enlist_set es = {
 *       .fds = fds,
 *       .count = 3,
 *   };
 *   if (ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es) < 0) {
 *       // es.enlisted contains count of successful enlistments
 *       // errno indicates why enlistment stopped
 *   }
 *   // Caller still owns fds[0..enlisted-1], must close them
 */
struct vbsd_enlist_set {
	const int	*fds;		/* Pointer to fd array */
	u_int		count;		/* Number of fds to enlist */
	u_int		enlisted;	/* OUT: number successfully enlisted */
};

/*
 * Coalition status structure.
 *
 * Query current state of a coalition.
 *
 * Example:
 *   struct vbsd_coalition_stat st;
 *   if (ioctl(coal_fd, VBSD_COALITION_STAT, &st) == 0) {
 *       printf("members: %u, signal: %d, nested: %u\n",
 *           st.vcs_member_count, st.vcs_signal, st.vcs_nested_count);
 *   }
 */
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

/* Flags for vcs_flags (same as internal VCF_*) */
#define VBSD_STAT_TERMINATING	0x0001

/*
 * Graceful termination parameters.
 *
 * Send configurable signal first, wait for grace period, then SIGKILL
 * any remaining processes.
 *
 * Example:
 *   struct vbsd_graceful g = {
 *       .vg_signal = SIGTERM,
 *       .vg_timeout_ms = 5000,  // 5 seconds
 *   };
 *   ioctl(coal_fd, VBSD_COALITION_TERMINATE_GRACEFUL, &g);
 */
struct vbsd_graceful {
	int		vg_signal;	/* Signal to send first (e.g., SIGTERM) */
	u_int		vg_timeout_ms;	/* Grace period in milliseconds */
};

/*
 * Deadline termination parameters.
 *
 * Automatically terminate the coalition after a timeout. Useful for
 * batch jobs, serverless functions, or untrusted code with hard time limits.
 *
 * If vd_signal is non-zero, that signal is sent first, followed by
 * SIGKILL after vd_grace_ms. If vd_signal is 0, immediate SIGKILL.
 *
 * Setting vd_timeout_ms to 0 cancels any pending deadline.
 * Setting a new deadline replaces any existing one.
 *
 * Example:
 *   struct vbsd_deadline d = {
 *       .vd_timeout_ms = 30000,   // 30 seconds
 *       .vd_signal = SIGTERM,     // Try graceful first
 *       .vd_grace_ms = 5000,      // 5 second grace period
 *   };
 *   ioctl(coal_fd, VBSD_COALITION_SET_DEADLINE, &d);
 */
struct vbsd_deadline {
	uint32_t	vd_timeout_ms;	/* Time until termination (0 = cancel) */
	int		vd_signal;	/* Signal before SIGKILL (0 = immediate) */
	uint32_t	vd_grace_ms;	/* Grace period after signal */
};

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

/* ========================================================================
 * Public API for External Modules
 * ======================================================================== */

struct vbsd_member_ops;

/*
 * Member ops - operations for a coalition member type.
 *
 * Each descriptor type that can be enlisted in a coalition registers
 * these ops. The coalition calls mo_terminate during termination.
 */
struct vbsd_member_ops {
	/*
	 * Terminate the resource. Called during coalition termination.
	 *
	 * This is where type-specific revocation happens:
	 *   - Processes: kern_psignal(SIGKILL)
	 *   - Jails: prison_remove()
	 *   - Sockets: soshutdown(SHUT_RDWR)
	 *   - SHM: fo_truncate(0) -> SIGBUS on access
	 *   - Custom: set revoked flag, invalidate keys, etc.
	 *
	 * For types without interior revocation (pipes, files), this
	 * can be a no-op - the coalition will fdrop() afterward.
	 *
	 * Returns 0 on success. Errors are logged but don't stop
	 * termination of other members.
	 */
	int	(*mo_terminate)(struct file *fp, struct thread *td);

	/* Name for debugging/logging */
	const char *mo_name;
};

/*
 * Register ops for a file descriptor type.
 * Called at module load time.
 *
 * dtype: DTYPE_* constant (e.g., DTYPE_PROCDESC, DTYPE_KEYVAULT)
 * ops:   operations for this type (must have mo_terminate set)
 *
 * Returns 0 on success, EEXIST if already registered, EINVAL if bad args.
 *
 * For optional coalition support, check vbsd_coalition_available() first.
 * See the integration guide at the top of this file.
 */
int	vbsd_member_ops_register(int dtype, struct vbsd_member_ops *ops);

/*
 * Deregister ops for a file descriptor type.
 * Called at module unload.
 *
 * Returns 0 on success, EBUSY if members of this type exist in any coalition.
 *
 * For optional coalition support, check vbsd_coalition_available() first.
 */
int	vbsd_member_ops_deregister(int dtype);

/*
 * Check if the coalition module is loaded.
 * External modules should include <sys/module.h> to use this.
 *
 * Example usage:
 *   #include <sys/module.h>
 *   if (vbsd_coalition_available()) {
 *       vbsd_member_ops_register(...);
 *   }
 */
#ifdef _SYS_MODULE_H_
static __inline bool
vbsd_coalition_available(void)
{

	return (module_lookupbyname("vbsd_coalition") != NULL);
}
#endif /* _SYS_MODULE_H_ */

/* ========================================================================
 * Internal Structures (for coalition module only)
 * ======================================================================== */

#ifdef _VBSD_COALITION_INTERNAL

struct prison;

#define VCF_TERMINATING		0x0001
#define VCF_DEADLINE_ACTIVE	0x0002	/* Deadline timer is running */
#define VCF_DEADLINE_GRACE	0x0004	/* In grace period after initial signal */
#define VCF_WATCHDOG_ACTIVE	0x0008	/* Watchdog timer is running */

/*
 * Lock order: vbsd_proc_hash_lock -> vc_sx
 */
struct vbsd_coalition {
	struct sx			vc_sx;
	TAILQ_HEAD(, vbsd_member)	vc_members;
	u_int				vc_flags;
	int				vc_signal;	/* Termination signal */
	u_int				vc_nesting_depth; /* Depth when nested */
	volatile u_int			vc_member_count;
	u_int				vc_refcount;

	/* Deadline termination */
	struct callout			vc_deadline_callout;
	struct task			vc_deadline_task;
	int				vc_deadline_signal;  /* Signal before SIGKILL */
	uint32_t			vc_deadline_grace_ms; /* Grace period */

	/* Watchdog */
	struct callout			vc_watchdog_callout;
	struct task			vc_watchdog_task;
	uint32_t			vc_watchdog_timeout_ms;
};

/*
 * Generic coalition member.
 * Holds a file reference and ops pointer for type-specific behavior.
 */
struct vbsd_member {
	TAILQ_ENTRY(vbsd_member)	vm_link;	/* vc_members linkage */
	LIST_ENTRY(vbsd_member)		vm_hash;	/* proc hash (processes only) */
	struct file			*vm_fp;		/* held file reference */
	struct vbsd_member_ops		*vm_ops;	/* type-specific ops */
	struct vbsd_coalition		*vm_coalition;
	void				*vm_data;	/* type-specific data */
	int				vm_dtype;	/* DTYPE_* for member tracking */
};

struct vbsd_coalition_file {
	struct vbsd_coalition		*vcf_coalition;
};

#endif /* _VBSD_COALITION_INTERNAL */

#endif /* _KERNEL */

#endif /* _SYS_VBSD_COALITION_H_ */
