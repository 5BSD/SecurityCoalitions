/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * vBSD Coalition - Capability-based Resource Group Management
 *
 * Lock order: vbsd_proc_hash_lock -> vc_sx
 */

#define _VBSD_COALITION_INTERNAL

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/capsicum.h>
#include <sys/caprights.h>
#include <sys/procdesc.h>
#include <sys/jail.h>
#include <sys/jaildesc.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/eventhandler.h>
#include <sys/hash.h>
#include <sys/syslog.h>
#include <sys/socketvar.h>
#include <sys/sdt.h>
#include <sys/syscall.h>
#include <sys/taskqueue.h>

#include <security/audit/audit.h>

#include <machine/atomic.h>

#include <vm/uma.h>
#include <sys/resourcevar.h>
#include <sys/user.h>
#include <sys/event.h>

#include "vbsd_coalition.h"

/* DTrace SDT Probes */
SDT_PROVIDER_DEFINE(vbsd_coalition);
SDT_PROBE_DEFINE1(vbsd_coalition, , , create, "pid_t");
SDT_PROBE_DEFINE3(vbsd_coalition, , , enlist, "int", "int", "int");
SDT_PROBE_DEFINE3(vbsd_coalition, , , enlist__set, "u_int", "u_int", "int");
SDT_PROBE_DEFINE2(vbsd_coalition, , , join, "pid_t", "int");
SDT_PROBE_DEFINE2(vbsd_coalition, , , terminate, "u_int", "int");
SDT_PROBE_DEFINE1(vbsd_coalition, , , close, "u_int");
SDT_PROBE_DEFINE1(vbsd_coalition, , , member__exit, "pid_t");
SDT_PROBE_DEFINE1(vbsd_coalition, , , leader__exit, "pid_t");
SDT_PROBE_DEFINE2(vbsd_coalition, , , fork__inherit, "pid_t", "pid_t")

MALLOC_DEFINE(M_VBSD_COALITION, "vbsd_coalition", "vBSD Coalition structures");

/* Forward declarations for ops */
static struct vbsd_member_ops vbsd_proc_ops;
static struct vbsd_member_ops vbsd_jail_ops;
static struct vbsd_member_ops vbsd_socket_ops;
static struct vbsd_member_ops vbsd_shm_ops;
static struct vbsd_member_ops vbsd_default_ops;

/* Global member counter */
static volatile u_int vbsd_member_count;

/* External module ops registration (linked list, unlimited) */
struct vbsd_external_ops {
	LIST_ENTRY(vbsd_external_ops)	link;
	int				dtype;
	struct vbsd_member_ops		*ops;
};

static LIST_HEAD(, vbsd_external_ops) vbsd_external_ops_list =
    LIST_HEAD_INITIALIZER(vbsd_external_ops_list);
static struct mtx vbsd_external_ops_lock;
static int vbsd_next_external_dtype = 64;	/* Start above kernel dtypes */
#define VBSD_DTYPE_MAX	0x7fff			/* Reasonable upper bound */

int
vbsd_member_ops_register(struct vbsd_member_ops *ops, int *dtype_out)
{
	struct vbsd_external_ops *new_entry;

	if (ops == NULL || ops->mo_terminate == NULL || dtype_out == NULL)
		return (EINVAL);

	new_entry = malloc(sizeof(*new_entry), M_VBSD_COALITION, M_WAITOK);
	new_entry->ops = ops;

	mtx_lock(&vbsd_external_ops_lock);
	if (vbsd_next_external_dtype >= VBSD_DTYPE_MAX) {
		mtx_unlock(&vbsd_external_ops_lock);
		free(new_entry, M_VBSD_COALITION);
		return (ENOSPC);
	}
	new_entry->dtype = vbsd_next_external_dtype++;
	LIST_INSERT_HEAD(&vbsd_external_ops_list, new_entry, link);
	mtx_unlock(&vbsd_external_ops_lock);

	*dtype_out = new_entry->dtype;
	return (0);
}

int
vbsd_member_ops_deregister(int dtype)
{
	struct vbsd_external_ops *entry;

	mtx_lock(&vbsd_external_ops_lock);
	LIST_FOREACH(entry, &vbsd_external_ops_list, link) {
		if (entry->dtype == dtype) {
			LIST_REMOVE(entry, link);
			mtx_unlock(&vbsd_external_ops_lock);
			free(entry, M_VBSD_COALITION);
			return (0);
		}
	}
	mtx_unlock(&vbsd_external_ops_lock);

	return (ENOENT);
}

/* Get ops based on dtype - built-ins first, then external */
static struct vbsd_member_ops *
vbsd_member_ops_get(int dtype)
{
	struct vbsd_external_ops *entry;

	/* Built-in types */
	switch (dtype) {
	case DTYPE_PROCDESC:
		return (&vbsd_proc_ops);
	case DTYPE_JAILDESC:
		return (&vbsd_jail_ops);
	case DTYPE_SOCKET:
		return (&vbsd_socket_ops);
	case DTYPE_SHM:
		return (&vbsd_shm_ops);
	}

	/* Check external registrations */
	mtx_lock(&vbsd_external_ops_lock);
	LIST_FOREACH(entry, &vbsd_external_ops_list, link) {
		if (entry->dtype == dtype) {
			mtx_unlock(&vbsd_external_ops_lock);
			return (entry->ops);
		}
	}
	mtx_unlock(&vbsd_external_ops_lock);

	return (&vbsd_default_ops);
}

/* UMA Zones and Global State */

static uma_zone_t vbsd_coalition_zone;
static uma_zone_t vbsd_member_zone;

static volatile u_int vbsd_coalition_count;

/* Process hash for exit handler lookup */
#define VBSD_PROC_HASH_SIZE	256
static LIST_HEAD(, vbsd_member) vbsd_proc_hash[VBSD_PROC_HASH_SIZE];
static struct rwlock vbsd_proc_hash_lock;

static inline u_int
vbsd_proc_hash_index(struct proc *p)
{
	/*
	 * Hash the proc pointer value itself (not the proc contents).
	 * &p is the address of the local variable containing the pointer,
	 * sizeof(p) bytes at that address is the pointer value.
	 */
	uintptr_t key = (uintptr_t)p;
	return (hash32_buf(&key, sizeof(key), 0) & (VBSD_PROC_HASH_SIZE - 1));
}

/* Jail OSD for fork inheritance */
static u_int vbsd_jail_osd_slot;

static eventhandler_tag vbsd_fork_tag;
static eventhandler_tag vbsd_exit_tag;

/*
 * Leader hash for third-party leader death notification.
 * Maps file pointer -> member for quick lookup when vbsd_leader_died fires.
 * Only contains third-party leaders (processes/jails use their own mechanisms).
 */
#define VBSD_LEADER_HASH_SIZE	64
static LIST_HEAD(vbsd_leader_hashhead, vbsd_leader_entry) vbsd_leader_hash[VBSD_LEADER_HASH_SIZE];
static struct mtx vbsd_leader_hash_lock;
static eventhandler_tag vbsd_leader_died_tag;

struct vbsd_leader_entry {
	LIST_ENTRY(vbsd_leader_entry)	vle_link;
	struct file			*vle_fp;
	struct vbsd_member		*vle_member;
};

static inline u_int
vbsd_leader_hash_index(struct file *fp)
{
	uintptr_t key = (uintptr_t)fp;
	return (hash32_buf(&key, sizeof(key), 0) & (VBSD_LEADER_HASH_SIZE - 1));
}

static void vbsd_leader_hash_insert(struct file *fp, struct vbsd_member *vm);
static struct vbsd_member *vbsd_leader_hash_lookup(struct file *fp);
static void vbsd_leader_hash_remove(struct file *fp);
static void vbsd_leader_died_handler(void *arg, struct file *fp);

/* Forward declarations */
static fo_ioctl_t	vbsd_coalition_fo_ioctl;
static fo_kqfilter_t	vbsd_coalition_fo_kqfilter;
static fo_close_t	vbsd_coalition_fo_close;
static fo_stat_t	vbsd_coalition_fo_stat;
static void		vbsd_coalition_terminate_members_locked(
			    struct vbsd_coalition *vc, struct thread *td,
			    bool skip_self);
static void		vbsd_deadline_callout(void *arg);
static void		vbsd_deadline_task_fn(void *context, int pending);
static void		vbsd_watchdog_callout(void *arg);
static void		vbsd_watchdog_task_fn(void *context, int pending);
static int		vbsd_coalition_terminate(struct vbsd_coalition *vc);

/* Sysctl Interface and Resource Limits */
#define VBSD_DEFAULT_MAX_COALITIONS	0	/* 0 = unlimited */
#define VBSD_DEFAULT_MAX_MEMBERS	0	/* 0 = unlimited */
#define VBSD_DEFAULT_MAX_MEMBERS_PER	0	/* 0 = unlimited */
#define VBSD_DEFAULT_ENLIST_SET_MAX	1024

static u_int vbsd_max_coalitions = VBSD_DEFAULT_MAX_COALITIONS;
static u_int vbsd_max_members = VBSD_DEFAULT_MAX_MEMBERS;
static u_int vbsd_max_members_per_coalition = VBSD_DEFAULT_MAX_MEMBERS_PER;
static u_int vbsd_enlist_set_max = VBSD_DEFAULT_ENLIST_SET_MAX;

SYSCTL_NODE(_kern, OID_AUTO, vbsd_coalition, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "vBSD Coalition");

SYSCTL_UINT(_kern_vbsd_coalition, OID_AUTO, count, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &vbsd_coalition_count), 0,
    "Number of active coalitions");

SYSCTL_UINT(_kern_vbsd_coalition, OID_AUTO, max_coalitions, CTLFLAG_RW,
    &vbsd_max_coalitions, 0,
    "Maximum number of coalitions (0 = unlimited)");

SYSCTL_UINT(_kern_vbsd_coalition, OID_AUTO, max_members, CTLFLAG_RW,
    &vbsd_max_members, 0,
    "Maximum total members across all coalitions (0 = unlimited)");

SYSCTL_UINT(_kern_vbsd_coalition, OID_AUTO, max_members_per_coalition, CTLFLAG_RW,
    &vbsd_max_members_per_coalition, 0,
    "Maximum members per coalition (0 = unlimited)");

SYSCTL_UINT(_kern_vbsd_coalition, OID_AUTO, enlist_set_max, CTLFLAG_RW,
    &vbsd_enlist_set_max, 0,
    "Maximum fds per VBSD_COALITION_ENLIST_SET call (default 1024)");

SYSCTL_UINT(_kern_vbsd_coalition, OID_AUTO, members, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &vbsd_member_count), 0,
    "Total members across all coalitions");

static int
vbsd_check_member_limits(struct vbsd_coalition *vc)
{
	u_int max, current;

	max = vbsd_max_members_per_coalition;
	if (max != 0) {
		current = atomic_load_acq_int(&vc->vc_member_count);
		if (current >= max)
			return (ENOMEM);
	}

	max = vbsd_max_members;
	if (max != 0) {
		current = atomic_load_acq_int(&vbsd_member_count);
		if (current >= max)
			return (ENOMEM);
	}

	return (0);
}

/* Built-in Process Ops */

static int
vbsd_proc_terminate(struct file *fp, struct thread *td __unused)
{
	struct procdesc *pd;
	struct proc *p;

	KASSERT(fp != NULL, ("vbsd_proc_terminate: NULL fp"));
	KASSERT(fp->f_data != NULL, ("vbsd_proc_terminate: NULL f_data"));

	pd = fp->f_data;
	sx_slock(&proctree_lock);
	p = pd->pd_proc;
	if (p == NULL) {
		sx_sunlock(&proctree_lock);
		/* Process already exited - success (already dead). */
		return (0);
	}
	PROC_LOCK(p);
	sx_sunlock(&proctree_lock);
	kern_psignal(p, SIGKILL);
	PROC_UNLOCK(p);

	return (0);
}

static struct vbsd_member_ops vbsd_proc_ops = {
	.mo_terminate	= vbsd_proc_terminate,
	.mo_name	= "process",
};

/* Built-in Jail Ops */

static int
vbsd_jail_terminate(struct file *fp, struct thread *td __unused)
{
	struct jaildesc *jd;
	struct prison *pr;

	KASSERT(fp != NULL, ("vbsd_jail_terminate: NULL fp"));
	KASSERT(fp->f_data != NULL, ("vbsd_jail_terminate: NULL f_data"));

	jd = fp->f_data;
	JAILDESC_LOCK(jd);
	pr = jd->jd_prison;
	if (pr == NULL || !prison_isvalid(pr)) {
		JAILDESC_UNLOCK(jd);
		return (ENOENT);
	}
	prison_hold(pr);
	JAILDESC_UNLOCK(jd);

	/* prison_remove releases locks and reference */
	sx_xlock(&allprison_lock);
	mtx_lock(&pr->pr_mtx);

	if (prison_isalive(pr)) {
		prison_remove(pr);
		/* prison_remove releases locks and reference */
	} else {
		mtx_unlock(&pr->pr_mtx);
		sx_xunlock(&allprison_lock);
		prison_free(pr);
	}

	return (0);
}

static struct vbsd_member_ops vbsd_jail_ops = {
	.mo_terminate	= vbsd_jail_terminate,
	.mo_name	= "jail",
};

/* Built-in Default Ops */
static int
vbsd_default_terminate(struct file *fp __unused, struct thread *td __unused)
{
	return (0);
}

static struct vbsd_member_ops vbsd_default_ops = {
	.mo_terminate	= vbsd_default_terminate,
	.mo_name	= "generic",
};

/* Built-in Socket Ops */

static int
vbsd_socket_terminate(struct file *fp, struct thread *td __unused)
{
	struct socket *so;

	KASSERT(fp != NULL, ("vbsd_socket_terminate: NULL fp"));
	KASSERT(fp->f_data != NULL, ("vbsd_socket_terminate: NULL f_data"));

	so = fp->f_data;
	return (soshutdown(so, SHUT_RDWR));
}

static struct vbsd_member_ops vbsd_socket_ops = {
	.mo_terminate	= vbsd_socket_terminate,
	.mo_name	= "socket",
};

/* Built-in SHM Ops */

static int
vbsd_shm_terminate(struct file *fp, struct thread *td)
{

	KASSERT(fp != NULL, ("vbsd_shm_terminate: NULL fp"));

	return (fo_truncate(fp, 0, td->td_ucred, td));
}

static struct vbsd_member_ops vbsd_shm_ops = {
	.mo_terminate	= vbsd_shm_terminate,
	.mo_name	= "shm",
};

/* Built-in Coalition Ops (nested) */

/* Forward declaration */
static struct fileops vbsd_coalition_fileops;

/*
 * Check if a file is a coalition descriptor.
 * Used to detect nested coalitions during enlistment.
 */
static bool
vbsd_is_coalition(struct file *fp)
{

	return (fp->f_ops == &vbsd_coalition_fileops);
}

/*
 * Nested coalition terminate.
 * Cascades termination to all members of the nested coalition.
 */
static int
vbsd_nested_coalition_terminate(struct file *fp, struct thread *td)
{
	struct vbsd_coalition *vc;

	KASSERT(fp != NULL, ("NULL fp"));
	KASSERT(vbsd_is_coalition(fp), ("not a coalition"));

	vc = fp->f_data;

	/*
	 * Terminate the nested coalition. This cascades to all its
	 * members, including any further nested coalitions.
	 */
	sx_xlock(&vc->vc_sx);

	if (!(vc->vc_flags & VCF_TERMINATING))
		vbsd_coalition_terminate_members_locked(vc, td, false);

	sx_xunlock(&vc->vc_sx);

	return (0);
}

static struct vbsd_member_ops vbsd_coalition_ops = {
	.mo_terminate	= vbsd_nested_coalition_terminate,
	.mo_name	= "coalition",
};

/* Coalition Core */

static int
vbsd_coalition_fo_stat(struct file *fp __unused, struct stat *sb,
    struct ucred *active_cred __unused)
{
	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFIFO;
	return (0);
}

/* Kqueue Filter Operations */
static void
vbsd_knlist_lock(void *arg)
{
	struct sx *sx = arg;

	sx_xlock(sx);
}

static void
vbsd_knlist_unlock(void *arg)
{
	struct sx *sx = arg;

	sx_xunlock(sx);
}

static void
vbsd_knlist_assert_lock(void *arg, int what)
{

#ifdef INVARIANTS
	struct sx *sx = arg;

	if (what == LA_LOCKED)
		sx_assert(sx, SA_XLOCKED);
	else
		sx_assert(sx, SA_UNLOCKED);
#else
	(void)arg;
	(void)what;
#endif
}

static void
filt_vbsd_coalition_detach(struct knote *kn)
{
	struct vbsd_coalition *vc = kn->kn_hook;

	knlist_remove(&vc->vc_knlist, kn, 0);
}

static int
filt_vbsd_coalition_event(struct knote *kn, long hint)
{

	/*
	 * Store the event type in fflags for delivery.
	 * hint contains VBSD_NOTE_* flags.
	 */
	if (hint != 0)
		kn->kn_fflags |= hint;

	return (kn->kn_fflags != 0);
}

static struct filterops vbsd_coalition_filtops = {
	.f_isfd = 1,
	.f_detach = filt_vbsd_coalition_detach,
	.f_event = filt_vbsd_coalition_event,
};

static int
vbsd_coalition_fo_kqfilter(struct file *fp, struct knote *kn)
{
	struct vbsd_coalition *vc;

	vc = fp->f_data;
	if (vc == NULL)
		return (EBADF);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &vbsd_coalition_filtops;
		kn->kn_hook = vc;
		knlist_add(&vc->vc_knlist, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static struct fileops vbsd_coalition_fileops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = vbsd_coalition_fo_ioctl,
	.fo_poll = invfo_poll,
	.fo_kqfilter = vbsd_coalition_fo_kqfilter,
	.fo_stat = vbsd_coalition_fo_stat,
	.fo_close = vbsd_coalition_fo_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_flags = DFLAG_PASSABLE,
};

static struct vbsd_coalition *
vbsd_coalition_alloc(void)
{
	struct vbsd_coalition *vc;

	vc = uma_zalloc(vbsd_coalition_zone, M_WAITOK | M_ZERO);
	sx_init(&vc->vc_sx, "vbsd_coalition");
	TAILQ_INIT(&vc->vc_members);
	knlist_init(&vc->vc_knlist, &vc->vc_sx, vbsd_knlist_lock,
	    vbsd_knlist_unlock, vbsd_knlist_assert_lock);
	vc->vc_signal = SIGKILL;	/* Default to immediate termination */
	vc->vc_nesting_depth = 0;
	vc->vc_flags = 0;
	callout_init(&vc->vc_deadline_callout, 1);  /* MPSAFE */
	TASK_INIT(&vc->vc_deadline_task, 0, vbsd_deadline_task_fn, vc);
	callout_init(&vc->vc_watchdog_callout, 1);  /* MPSAFE */
	TASK_INIT(&vc->vc_watchdog_task, 0, vbsd_watchdog_task_fn, vc);
	refcount_init(&vc->vc_refcount, 1);
	atomic_add_int(&vbsd_coalition_count, 1);

	return (vc);
}

static void
vbsd_coalition_free(struct vbsd_coalition *vc)
{

	KASSERT(TAILQ_EMPTY(&vc->vc_members),
	    ("vbsd_coalition_free: members not empty"));
	KASSERT(vc->vc_refcount == 0,
	    ("vbsd_coalition_free: refcount %u != 0", vc->vc_refcount));

	sx_destroy(&vc->vc_sx);
	uma_zfree(vbsd_coalition_zone, vc);
	atomic_subtract_int(&vbsd_coalition_count, 1);
}

static void
vbsd_coalition_ref(struct vbsd_coalition *vc)
{
	refcount_acquire(&vc->vc_refcount);
}

static void
vbsd_coalition_rel(struct vbsd_coalition *vc)
{
	if (refcount_release(&vc->vc_refcount))
		vbsd_coalition_free(vc);
}

/* Deadline Termination */
static void
vbsd_deadline_task_fn(void *context, int pending __unused)
{
	struct vbsd_coalition *vc = context;
	struct thread *td = curthread;

	sx_xlock(&vc->vc_sx);

	/*
	 * Check if coalition was already terminated or deadline cancelled.
	 * If so, just release our reference and return.
	 */
	if ((vc->vc_flags & VCF_TERMINATING) ||
	    !(vc->vc_flags & VCF_DEADLINE_ACTIVE)) {
		sx_xunlock(&vc->vc_sx);
		vbsd_coalition_rel(vc);  /* Release task's reference */
		return;
	}

	/*
	 * If we're in grace period, this is the final SIGKILL phase.
	 * Otherwise, this is the initial signal phase.
	 */
	if (vc->vc_flags & VCF_DEADLINE_GRACE) {
		/* Grace period expired - do full termination with SIGKILL */
		KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_DEADLINE_FIRED);
		vc->vc_flags &= ~(VCF_DEADLINE_ACTIVE | VCF_DEADLINE_GRACE);
		vbsd_coalition_terminate_members_locked(vc, td, false);
	} else if (vc->vc_deadline_signal != 0 &&
		   vc->vc_deadline_grace_ms > 0) {
		/*
		 * Initial deadline hit - send configured signal and
		 * schedule grace period callout for SIGKILL.
		 */
		struct vbsd_member *vm;
		int sig = vc->vc_deadline_signal;

		TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
			if (vm->vm_dtype == DTYPE_PROCDESC && vm->vm_fp != NULL) {
				struct procdesc *pd = vm->vm_fp->f_data;
				struct proc *p;

				sx_slock(&proctree_lock);
				p = pd->pd_proc;
				if (p != NULL) {
					PROC_LOCK(p);
					sx_sunlock(&proctree_lock);
					kern_psignal(p, sig);
					PROC_UNLOCK(p);
				} else {
					sx_sunlock(&proctree_lock);
				}
			}
		}

		/* Notify that deadline fired and grace period is starting */
		KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_DEADLINE_FIRED);
		KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_GRACE_STARTED);

		/* Schedule grace period timeout */
		vc->vc_flags |= VCF_DEADLINE_GRACE;
		vbsd_coalition_ref(vc);  /* Reference for next callout */
		callout_reset(&vc->vc_deadline_callout,
		    vc->vc_deadline_grace_ms * hz / 1000,
		    vbsd_deadline_callout, vc);
	} else {
		/* No grace period - immediate termination */
		KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_DEADLINE_FIRED);
		vc->vc_flags &= ~VCF_DEADLINE_ACTIVE;
		vbsd_coalition_terminate_members_locked(vc, td, false);
	}

	sx_xunlock(&vc->vc_sx);
	vbsd_coalition_rel(vc);  /* Release task's reference */
}

/*
 * Callout function for deadline termination.
 * Runs in softirq context (cannot sleep), schedules task for actual work.
 */
static void
vbsd_deadline_callout(void *arg)
{
	struct vbsd_coalition *vc = arg;

	/*
	 * Enqueue task to do the actual termination work.
	 * The task will release our reference when done.
	 * Reference was taken when callout was scheduled.
	 */
	taskqueue_enqueue(taskqueue_thread, &vc->vc_deadline_task);
}

/* Watchdog */
static void
vbsd_watchdog_task_fn(void *context, int pending __unused)
{
	struct vbsd_coalition *vc = context;
	struct thread *td = curthread;

	sx_xlock(&vc->vc_sx);

	/*
	 * Check if coalition was already terminated or watchdog disabled.
	 */
	if ((vc->vc_flags & VCF_TERMINATING) ||
	    !(vc->vc_flags & VCF_WATCHDOG_ACTIVE)) {
		sx_xunlock(&vc->vc_sx);
		vbsd_coalition_rel(vc);
		return;
	}

	/* Watchdog expired - terminate everything */
	KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_WATCHDOG_FIRED);
	vc->vc_flags &= ~VCF_WATCHDOG_ACTIVE;
	vbsd_coalition_terminate_members_locked(vc, td, false);

	sx_xunlock(&vc->vc_sx);
	vbsd_coalition_rel(vc);
}

/*
 * Callout function for watchdog.
 * Runs in softirq context, schedules task for termination.
 */
static void
vbsd_watchdog_callout(void *arg)
{
	struct vbsd_coalition *vc = arg;

	taskqueue_enqueue(taskqueue_thread, &vc->vc_watchdog_task);
}

static int
vbsd_coalition_init_file(struct file *fp)
{
	struct vbsd_coalition *vc;
	u_int max, current;

	/* Check coalition count limit */
	max = vbsd_max_coalitions;
	if (max != 0) {
		current = atomic_load_acq_int(&vbsd_coalition_count);
		if (current >= max)
			return (ENOMEM);
	}

	vc = vbsd_coalition_alloc();
	finit(fp, FREAD | FWRITE, DTYPE_DEV, vc, &vbsd_coalition_fileops);

	SDT_PROBE1(vbsd_coalition, , , create, curthread->td_proc->p_pid);

	return (0);
}

/* Process Hash Table */

static void
vbsd_proc_hash_insert_locked(struct vbsd_member *vm, struct proc *p)
{
	u_int idx;

	rw_assert(&vbsd_proc_hash_lock, RA_WLOCKED);
	idx = vbsd_proc_hash_index(p);
	LIST_INSERT_HEAD(&vbsd_proc_hash[idx], vm, vm_hash);
}

static struct vbsd_member *
vbsd_proc_hash_lookup_locked(struct proc *p)
{
	struct vbsd_member *vm;
	u_int idx;

	rw_assert(&vbsd_proc_hash_lock, RA_LOCKED);
	idx = vbsd_proc_hash_index(p);
	LIST_FOREACH(vm, &vbsd_proc_hash[idx], vm_hash) {
		if (vm->vm_data == p)
			return (vm);
	}
	return (NULL);
}

/* Jail OSD */

struct vbsd_jail_osd {
	struct vbsd_coalition	*vjo_coalition;
	struct vbsd_member	*vjo_member;	/* back-pointer for exit tracking */
};

/*
 * Atomically set jail coalition if not already set.
 * Returns 0 on success, EBUSY if already in a coalition, ENOMEM on failure.
 *
 * This prevents the TOCTOU race between checking vbsd_jail_coalition()
 * and setting the coalition - the check and set are done atomically
 * under the prison's OSD lock.
 */
static int
vbsd_jail_set_coalition_atomic(struct prison *pr, struct vbsd_coalition *vc)
{
	struct vbsd_jail_osd *vjo, *existing;

	if (vbsd_jail_osd_slot == 0)
		return (ENXIO);

	vjo = malloc(sizeof(*vjo), M_VBSD_COALITION, M_WAITOK);
	vjo->vjo_coalition = vc;
	vjo->vjo_member = NULL;

	/*
	 * Atomically check-and-set: only set if slot is currently NULL.
	 * osd_jail_set_reserved() would be ideal but we use get+set pattern
	 * under the prison lock.
	 */
	prison_lock(pr);
	existing = osd_jail_get(pr, vbsd_jail_osd_slot);
	if (existing != NULL) {
		prison_unlock(pr);
		free(vjo, M_VBSD_COALITION);
		return (EBUSY);
	}
	osd_jail_set(pr, vbsd_jail_osd_slot, vjo);
	prison_unlock(pr);

	return (0);
}


static void
vbsd_jail_set_member(struct prison *pr, struct vbsd_member *vm)
{
	struct vbsd_jail_osd *vjo;

	if (vbsd_jail_osd_slot == 0)
		return;

	prison_lock(pr);
	vjo = osd_jail_get(pr, vbsd_jail_osd_slot);
	if (vjo != NULL)
		vjo->vjo_member = vm;
	prison_unlock(pr);
}

static void
vbsd_jail_osd_dtor(void *value)
{
	struct vbsd_jail_osd *vjo = value;
	struct vbsd_coalition *vc;
	struct vbsd_member *vm;

	if (vjo == NULL)
		return;

	vc = vjo->vjo_coalition;
	vm = vjo->vjo_member;

	if (vm != NULL) {
		bool in_tailq;
		bool was_leader = false;

		sx_xlock(&vc->vc_sx);
		in_tailq = (vm->vm_link.tqe_prev != NULL);
		if (in_tailq) {
			TAILQ_REMOVE(&vc->vc_members, vm, vm_link);
			vm->vm_link.tqe_prev = NULL;  /* Mark as removed */

			/* Check if this was the leader */
			if ((vc->vc_flags & VCF_HAS_LEADER) &&
			    vc->vc_leader == vm) {
				was_leader = true;
				vc->vc_leader = NULL;
			}
		}
		sx_xunlock(&vc->vc_sx);

		if (was_leader) {
			SDT_PROBE1(vbsd_coalition, , , leader__exit, 0);
			vbsd_coalition_terminate(vc);
		}

		if (in_tailq) {
			atomic_subtract_int(&vc->vc_member_count, 1);
			atomic_subtract_int(&vbsd_member_count, 1);

			/*
			 * Don't fdrop the jaildesc here - we're inside the
			 * prison destructor, and jaildesc_close would try to
			 * access the prison which is being freed. The jaildesc
			 * reference will be released when fo_close runs.
			 */

			uma_zfree(vbsd_member_zone, vm);

			/* Release member's coalition reference */
			vbsd_coalition_rel(vc);
		}
		/* If !in_tailq, fo_close will free vm */
	}

	/*
	 * Release OSD's coalition reference and free OSD structure.
	 * This reference was taken in vbsd_jail_set_coalition_atomic().
	 */
	if (vc != NULL)
		vbsd_coalition_rel(vc);
	free(vjo, M_VBSD_COALITION);
}

/* Generic Enlistment */

/* Must be called with vc_sx held */
static bool
vbsd_coalition_has_member(struct vbsd_coalition *vc, struct file *fp)
{
	struct vbsd_member *vm;

	KASSERT(fp != NULL, ("vbsd_coalition_has_member: NULL fp"));
	sx_assert(&vc->vc_sx, SA_LOCKED);
	TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
		if (vm->vm_fp == fp)
			return (true);
	}
	return (false);
}

static int
vbsd_coalition_enlist_generic(struct vbsd_coalition *vc, struct thread *td,
    struct file *fp)
{
	struct vbsd_member_ops *ops;
	struct vbsd_member *vm;
	int dtype, error;
	bool is_nested_coalition;

	dtype = fp->f_type;

	/*
	 * Check for nested coalition.
	 * Coalitions use DTYPE_DEV but have specific fileops.
	 */
	is_nested_coalition = vbsd_is_coalition(fp);
	if (is_nested_coalition) {
		struct vbsd_coalition *nested_vc = fp->f_data;

		/*
		 * Check nesting depth to prevent infinite loops.
		 * The new nested coalition will be at our depth + 1.
		 */
		if (vc->vc_nesting_depth + 1 >= VBSD_MAX_NESTING_DEPTH)
			return (ELOOP);

		/*
		 * Prevent self-enlistment.
		 */
		if (nested_vc == vc)
			return (EINVAL);

		/*
		 * Use coalition-specific ops for nested coalitions.
		 */
		ops = &vbsd_coalition_ops;
	} else {
		ops = vbsd_member_ops_get(dtype);
		atomic_add_int(&vbsd_member_count, 1);
	}

	/* Check resource limits before allocating */
	error = vbsd_check_member_limits(vc);
	if (error != 0) {
		if (!is_nested_coalition)
			atomic_subtract_int(&vbsd_member_count, 1);
		return (error);
	}

	/*
	 * Take file reference early. This ensures the file (and for
	 * procdescs, the underlying proc) stays valid throughout.
	 */
	if (!fhold(fp)) {
		if (!is_nested_coalition)
			atomic_subtract_int(&vbsd_member_count, 1);
		return (EBADF);
	}

	/* Allocate member */
	vm = uma_zalloc(vbsd_member_zone, M_WAITOK | M_ZERO);
	vm->vm_dtype = dtype;

	/* Type-specific setup */
	if (dtype == DTYPE_PROCDESC) {
		struct procdesc *pd = fp->f_data;
		struct proc *p;

		sx_slock(&proctree_lock);
		p = pd->pd_proc;
		if (p == NULL) {
			sx_sunlock(&proctree_lock);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			atomic_subtract_int(&vbsd_member_count, 1);
			return (ESRCH);
		}

		/* Lock order: proctree_lock -> hash_lock -> vc_sx */
		rw_wlock(&vbsd_proc_hash_lock);
		sx_sunlock(&proctree_lock);

		if (vbsd_proc_hash_lookup_locked(p) != NULL) {
			rw_wunlock(&vbsd_proc_hash_lock);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			atomic_subtract_int(&vbsd_member_count, 1);
			return (EBUSY);
		}

		vm->vm_data = p;

		sx_xlock(&vc->vc_sx);
		if (vc->vc_flags & VCF_TERMINATING) {
			sx_xunlock(&vc->vc_sx);
			rw_wunlock(&vbsd_proc_hash_lock);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			atomic_subtract_int(&vbsd_member_count, 1);
			return (EINVAL);
		}

		vbsd_proc_hash_insert_locked(vm, p);
		rw_wunlock(&vbsd_proc_hash_lock);

	} else if (dtype == DTYPE_JAILDESC) {
		struct jaildesc *jd = fp->f_data;
		struct prison *pr;
		int osd_error;

		JAILDESC_LOCK(jd);
		pr = jd->jd_prison;
		if (pr == NULL || !prison_isvalid(pr)) {
			JAILDESC_UNLOCK(jd);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			atomic_subtract_int(&vbsd_member_count, 1);
			return (ENOENT);
		}
		prison_hold(pr);
		JAILDESC_UNLOCK(jd);

		vm->vm_data = pr;

		sx_xlock(&vc->vc_sx);
		if (vc->vc_flags & VCF_TERMINATING) {
			sx_xunlock(&vc->vc_sx);
			prison_free(pr);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			atomic_subtract_int(&vbsd_member_count, 1);
			return (EINVAL);
		}

		osd_error = vbsd_jail_set_coalition_atomic(pr, vc);
		if (osd_error != 0) {
			sx_xunlock(&vc->vc_sx);
			prison_free(pr);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			atomic_subtract_int(&vbsd_member_count, 1);
			return (osd_error);
		}
		vbsd_coalition_ref(vc);

	} else {
		/* Generic path for other types (sockets, shm, devices, coalitions, etc.) */
		sx_xlock(&vc->vc_sx);
		if (vc->vc_flags & VCF_TERMINATING) {
			sx_xunlock(&vc->vc_sx);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			if (!is_nested_coalition)
				atomic_subtract_int(&vbsd_member_count, 1);
			return (EINVAL);
		}

		/* Check for duplicate enlistment of same fd */
		if (vbsd_coalition_has_member(vc, fp)) {
			sx_xunlock(&vc->vc_sx);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			if (!is_nested_coalition)
				atomic_subtract_int(&vbsd_member_count, 1);
			return (EBUSY);
		}

		/*
		 * For nested coalitions, update the child's nesting depth.
		 */
		if (is_nested_coalition) {
			struct vbsd_coalition *nested_vc = fp->f_data;
			nested_vc->vc_nesting_depth = vc->vc_nesting_depth + 1;
		}
	}

	/* Common member setup - we already hold fp from fhold above */
	vm->vm_fp = fp;
	vm->vm_ops = ops;
	vm->vm_coalition = vc;
	TAILQ_INSERT_TAIL(&vc->vc_members, vm, vm_link);

	/*
	 * For jails, set the member back-pointer in the OSD so the
	 * destructor can remove the member when the prison is freed.
	 * Then release the prison reference we've been holding.
	 */
	if (dtype == DTYPE_JAILDESC) {
		struct prison *pr = vm->vm_data;
		vbsd_jail_set_member(pr, vm);
		prison_free(pr);
	}

	atomic_add_int(&vc->vc_member_count, 1);

	/* Notify kqueue watchers of new member */
	KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_MEMBER_ADDED);

	vbsd_coalition_ref(vc);
	sx_xunlock(&vc->vc_sx);

	return (0);
}

/* Self-Join */

static int
vbsd_coalition_join(struct vbsd_coalition *vc, struct thread *td)
{
	struct vbsd_member *vm;
	struct proc *p;
	int error;

	error = vbsd_check_member_limits(vc);
	if (error != 0)
		return (error);

	p = td->td_proc;
	vm = uma_zalloc(vbsd_member_zone, M_WAITOK | M_ZERO);

	rw_wlock(&vbsd_proc_hash_lock);

	if (vbsd_proc_hash_lookup_locked(p) != NULL) {
		rw_wunlock(&vbsd_proc_hash_lock);
		uma_zfree(vbsd_member_zone, vm);
		return (EBUSY);
	}

	sx_xlock(&vc->vc_sx);

	if (vc->vc_flags & VCF_TERMINATING) {
		sx_xunlock(&vc->vc_sx);
		rw_wunlock(&vbsd_proc_hash_lock);
		uma_zfree(vbsd_member_zone, vm);
		return (EINVAL);
	}

	vm->vm_data = p;
	vm->vm_fp = NULL;
	vm->vm_ops = &vbsd_proc_ops;
	vm->vm_coalition = vc;
	vm->vm_dtype = DTYPE_PROCDESC;

	vbsd_proc_hash_insert_locked(vm, p);
	TAILQ_INSERT_TAIL(&vc->vc_members, vm, vm_link);

	atomic_add_int(&vc->vc_member_count, 1);
	atomic_add_int(&vbsd_member_count, 1);

	/* Notify kqueue watchers of new member */
	KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_MEMBER_ADDED);

	vbsd_coalition_ref(vc);

	sx_xunlock(&vc->vc_sx);
	rw_wunlock(&vbsd_proc_hash_lock);

	return (0);
}

/* Termination */

/* Must be called with vc_sx held */
static void
vbsd_coalition_terminate_members_locked(struct vbsd_coalition *vc,
    struct thread *td, bool skip_self)
{
	struct vbsd_member *vm;
	struct proc *self;

	sx_assert(&vc->vc_sx, SA_XLOCKED);

	if (vc->vc_flags & VCF_TERMINATING)
		return;

	vc->vc_flags |= VCF_TERMINATING;

	/*
	 * Clean up leader tracking before termination.
	 * Remove third-party leaders from hash so they don't
	 * trigger duplicate termination via VBSD_LEADER_DIED.
	 */
	if (vc->vc_leader != NULL) {
		struct vbsd_member *leader_vm = vc->vc_leader;

		if (leader_vm->vm_ops != NULL &&
		    leader_vm->vm_ops != &vbsd_proc_ops &&
		    leader_vm->vm_ops != &vbsd_jail_ops &&
		    leader_vm->vm_ops != &vbsd_coalition_ops &&
		    leader_vm->vm_fp != NULL) {
			vbsd_leader_hash_remove(leader_vm->vm_fp);
		}
		vc->vc_leader = NULL;
		vc->vc_flags &= ~VCF_HAS_LEADER;
	}

	KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_TERMINATING);

	self = (skip_self && td != NULL) ? td->td_proc : NULL;

	TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
		if (vm->vm_ops == NULL)
			continue;

		/*
		 * Skip jail members - must be terminated outside the lock
		 * to avoid deadlock with OSD destructor.
		 */
		if (vm->vm_ops == &vbsd_jail_ops)
			continue;

		if (vm->vm_fp != NULL && vm->vm_ops->mo_terminate != NULL) {
			(void)vm->vm_ops->mo_terminate(vm->vm_fp, td);
		} else if (vm->vm_data != NULL && vm->vm_ops == &vbsd_proc_ops) {
			struct proc *p;

			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&vm->vm_data);
			if (skip_self && self != NULL && p == self)
				continue;
			if (p != NULL) {
				PROC_LOCK(p);
				kern_psignal(p, SIGKILL);
				PROC_UNLOCK(p);
			}
		}
	}
}

static int
vbsd_coalition_terminate(struct vbsd_coalition *vc)
{
	struct vbsd_member *vm;
	struct thread *td = curthread;
	struct file **jail_fps;
	int jail_count, i;

	sx_xlock(&vc->vc_sx);

	if (vc->vc_flags & VCF_TERMINATING) {
		sx_xunlock(&vc->vc_sx);
		/*
		 * ESHUTDOWN: "Can't send after socket shutdown"
		 * Semantically appropriate for "coalition already terminated".
		 * EALREADY is for socket connection in progress.
		 */
		return (ESHUTDOWN);
	}

	/*
	 * Count jail members so we can allocate an array to hold their
	 * file pointers. We need to terminate jails outside the lock
	 * to avoid deadlock with OSD destructor.
	 */
	jail_count = 0;
	TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
		if (vm->vm_ops == &vbsd_jail_ops && vm->vm_fp != NULL)
			jail_count++;
	}

	jail_fps = NULL;
	if (jail_count > 0) {
		jail_fps = malloc(jail_count * sizeof(struct file *),
		    M_VBSD_COALITION, M_NOWAIT);
		if (jail_fps != NULL) {
			i = 0;
			TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
				if (vm->vm_ops == &vbsd_jail_ops &&
				    vm->vm_fp != NULL && i < jail_count) {
					/* Hold file reference for safe access outside lock */
					if (fhold(vm->vm_fp))
						jail_fps[i++] = vm->vm_fp;
				}
			}
			jail_count = i;  /* Actual count after fhold */
		} else {
			jail_count = 0;
		}
	}

	/* Terminate non-jail members while holding the lock */
	vbsd_coalition_terminate_members_locked(vc, td, false);

	sx_xunlock(&vc->vc_sx);

	/*
	 * Terminate jail members outside the lock to avoid deadlock.
	 * vbsd_jail_terminate() needs allprison_lock which could deadlock
	 * with OSD destructor that needs vc_sx.
	 */
	for (i = 0; i < jail_count; i++) {
		(void)vbsd_jail_terminate(jail_fps[i], td);
		fdrop(jail_fps[i], td);
	}

	if (jail_fps != NULL)
		free(jail_fps, M_VBSD_COALITION);

	/*
	 * If this coalition is a leader in a parent coalition, notify the
	 * parent to terminate as well. This implements the "leader death
	 * trigger" for nested coalitions.
	 *
	 * Note: We do this after terminating our own members to avoid
	 * potential deadlocks from recursive termination.
	 */
	sx_slock(&vc->vc_sx);
	if (vc->vc_leader_of != NULL) {
		struct vbsd_member *parent_vm = vc->vc_leader_of;
		struct vbsd_coalition *parent_vc = parent_vm->vm_coalition;

		vc->vc_leader_of = NULL;  /* Clear back-pointer */
		sx_sunlock(&vc->vc_sx);

		if (parent_vc != NULL) {
			sx_xlock(&parent_vc->vc_sx);
			if ((parent_vc->vc_flags & VCF_HAS_LEADER) &&
			    parent_vc->vc_leader == parent_vm &&
			    !(parent_vc->vc_flags & VCF_TERMINATING)) {
				parent_vc->vc_leader = NULL;
				sx_xunlock(&parent_vc->vc_sx);

				SDT_PROBE1(vbsd_coalition, , , leader__exit, 0);
				vbsd_coalition_terminate(parent_vc);
			} else {
				sx_xunlock(&parent_vc->vc_sx);
			}
		}
	} else {
		sx_sunlock(&vc->vc_sx);
	}

	return (0);
}

/* Must be called with vc_sx held */
static void
vbsd_coalition_signal_processes_locked(struct vbsd_coalition *vc, int sig)
{
	struct vbsd_member *vm;

	sx_assert(&vc->vc_sx, SA_XLOCKED);

	TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
		if (vm->vm_ops != &vbsd_proc_ops)
			continue;

		if (vm->vm_fp != NULL) {
			/* Enlisted process descriptor */
			struct procdesc *pd = vm->vm_fp->f_data;
			struct proc *p;

			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p != NULL) {
				PROC_LOCK(p);
				sx_sunlock(&proctree_lock);
				kern_psignal(p, sig);
				PROC_UNLOCK(p);
			} else {
				sx_sunlock(&proctree_lock);
			}
		} else if (vm->vm_data != NULL) {
			struct proc *p;

			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&vm->vm_data);
			if (p != NULL) {
				PROC_LOCK(p);
				kern_psignal(p, sig);
				PROC_UNLOCK(p);
			}
		}
	}
}

/* Must be called with vc_sx held */
static u_int
vbsd_coalition_count_live_processes_locked(struct vbsd_coalition *vc)
{
	struct vbsd_member *vm;
	u_int count = 0;

	sx_assert(&vc->vc_sx, SA_XLOCKED);

	TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
		if (vm->vm_ops != &vbsd_proc_ops)
			continue;

		if (vm->vm_fp != NULL) {
			struct procdesc *pd = vm->vm_fp->f_data;
			struct proc *p;

			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p != NULL && (p->p_flag & P_WEXIT) == 0)
				count++;
			sx_sunlock(&proctree_lock);
		} else if (vm->vm_data != NULL) {
			struct proc *p;

			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&vm->vm_data);
			if (p != NULL && (p->p_flag & P_WEXIT) == 0)
				count++;
		}
	}

	return (count);
}

static int
vbsd_coalition_terminate_graceful(struct vbsd_coalition *vc, int sig,
    u_int timeout_ms)
{
	u_int remaining, elapsed;
	int error;

	if (sig <= 0 || sig >= NSIG)
		return (EINVAL);

	/* Cap timeout at 60 seconds to prevent indefinite hangs */
	if (timeout_ms > 60000)
		timeout_ms = 60000;

	sx_xlock(&vc->vc_sx);

	if (vc->vc_flags & VCF_TERMINATING) {
		sx_xunlock(&vc->vc_sx);
		return (ESHUTDOWN);
	}

	/* Phase 1: Send graceful signal to all processes */
	vbsd_coalition_signal_processes_locked(vc, sig);

	elapsed = 0;
	while (elapsed < timeout_ms) {
		remaining = vbsd_coalition_count_live_processes_locked(vc);
		if (remaining == 0)
			break;
		sx_xunlock(&vc->vc_sx);
		u_int sleep_ms = (timeout_ms - elapsed);
		if (sleep_ms > 100)
			sleep_ms = 100;
		error = pause_sbt("coalition_grace", SBT_1MS * sleep_ms,
		    0, C_HARDCLOCK);
		(void)error;
		elapsed += sleep_ms;
		sx_xlock(&vc->vc_sx);
		if (vc->vc_flags & VCF_TERMINATING) {
			sx_xunlock(&vc->vc_sx);
			return (0);
		}
	}
	vbsd_coalition_terminate_members_locked(vc, curthread, false);

	sx_xunlock(&vc->vc_sx);

	return (0);
}

/* Process Exit Handler */

static void
vbsd_process_exit(void *arg __unused, struct proc *p)
{
	struct vbsd_member *vm;
	struct vbsd_coalition *vc;

	rw_wlock(&vbsd_proc_hash_lock);
	vm = vbsd_proc_hash_lookup_locked(p);
	if (vm == NULL) {
		rw_wunlock(&vbsd_proc_hash_lock);
		return;
	}

	SDT_PROBE1(vbsd_coalition, , , member__exit, p->p_pid);

	vc = vm->vm_coalition;
	vbsd_coalition_ref(vc);
	LIST_REMOVE(vm, vm_hash);
	vm->vm_hash.le_prev = NULL;

	/* NULL out proc pointer for self-joined processes */
	if (vm->vm_fp == NULL)
		atomic_store_rel_ptr((uintptr_t *)&vm->vm_data, (uintptr_t)NULL);

	rw_wunlock(&vbsd_proc_hash_lock);

	if ((vc->vc_flags & VCF_HAS_LEADER) && p->p_pid == vc->vc_leader_pid) {
		SDT_PROBE1(vbsd_coalition, , , leader__exit, p->p_pid);
		vbsd_coalition_terminate(vc);
	}

	vbsd_coalition_rel(vc);
}

/* Process Fork Handler */

static void
vbsd_process_fork(void *arg __unused, struct proc *parent, struct proc *child,
    int flags __unused)
{
	struct vbsd_member *pvm, *cvm;
	struct vbsd_coalition *vc;

	rw_rlock(&vbsd_proc_hash_lock);
	pvm = vbsd_proc_hash_lookup_locked(parent);
	if (pvm == NULL) {
		rw_runlock(&vbsd_proc_hash_lock);
		return;
	}
	vc = pvm->vm_coalition;
	vbsd_coalition_ref(vc);
	rw_runlock(&vbsd_proc_hash_lock);

	if (vbsd_check_member_limits(vc) != 0)
		log(LOG_WARNING, "vbsd_coalition: fork exceeds limits\n");

	cvm = uma_zalloc(vbsd_member_zone, M_WAITOK | M_ZERO);

	rw_wlock(&vbsd_proc_hash_lock);
	sx_xlock(&vc->vc_sx);

	if (vc->vc_flags & VCF_TERMINATING) {
		sx_xunlock(&vc->vc_sx);
		rw_wunlock(&vbsd_proc_hash_lock);
		uma_zfree(vbsd_member_zone, cvm);
		vbsd_coalition_rel(vc);
		return;
	}

	cvm->vm_data = child;
	cvm->vm_fp = NULL;
	cvm->vm_ops = &vbsd_proc_ops;
	cvm->vm_coalition = vc;
	cvm->vm_dtype = DTYPE_PROCDESC;

	vbsd_proc_hash_insert_locked(cvm, child);
	TAILQ_INSERT_TAIL(&vc->vc_members, cvm, vm_link);

	atomic_add_int(&vc->vc_member_count, 1);
	atomic_add_int(&vbsd_member_count, 1);
	vbsd_coalition_ref(vc);

	sx_xunlock(&vc->vc_sx);
	rw_wunlock(&vbsd_proc_hash_lock);

	SDT_PROBE2(vbsd_coalition, , , fork__inherit, parent->p_pid, child->p_pid);
	vbsd_coalition_rel(vc);
}

/* File Operations */

static int
vbsd_coalition_fo_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred __unused, struct thread *td)
{
	struct vbsd_coalition *vc;
	struct file *target_fp;
	int error, target_fd;

	vc = fp->f_data;

	switch (cmd) {
	case VBSD_COALITION_ENLIST:
		target_fd = *(int *)data;
		AUDIT_ARG_FD(target_fd);
		error = fget(td, target_fd, &cap_no_rights, &target_fp);
		if (error != 0) {
			SDT_PROBE3(vbsd_coalition, , , enlist, target_fd, -1, error);
			return (error);
		}
		error = vbsd_coalition_enlist_generic(vc, td, target_fp);
		SDT_PROBE3(vbsd_coalition, , , enlist, target_fd,
		    target_fp->f_type, error);
		fdrop(target_fp, td);
		/*
		 * Reference semantics: coalition holds its own reference
		 * (via fhold in enlist_generic). Caller keeps their fd.
		 * This allows caller to monitor/waitpid the resource while
		 * coalition handles termination.
		 */
		break;

	case VBSD_COALITION_JOIN:
		AUDIT_ARG_PID(td->td_proc->p_pid);
		error = vbsd_coalition_join(vc, td);
		SDT_PROBE2(vbsd_coalition, , , join, td->td_proc->p_pid, error);
		break;

	case VBSD_COALITION_TERMINATE:
		{
			u_int member_count __unused;
			member_count = atomic_load_acq_int(&vc->vc_member_count);
			AUDIT_ARG_VALUE(member_count);
			error = vbsd_coalition_terminate(vc);
			SDT_PROBE2(vbsd_coalition, , , terminate, member_count, error);
		}
		break;

	case VBSD_COALITION_ENLIST_SET:
		{
			struct vbsd_enlist_set *es = data;
			int *fds;
			u_int i;

			es->enlisted = 0;
			AUDIT_ARG_VALUE(es->count);
			error = 0;

			/* Validate count */
			if (es->count == 0) {
				SDT_PROBE3(vbsd_coalition, , , enlist__set, 0, 0, 0);
				break;
			}
			if (es->count > vbsd_enlist_set_max) {
				SDT_PROBE3(vbsd_coalition, , , enlist__set,
				    es->count, 0, EINVAL);
				error = EINVAL;
				break;
			}

			/* Allocate kernel buffer for fd array */
			fds = malloc(es->count * sizeof(int), M_VBSD_COALITION,
			    M_WAITOK);

			/* Copy in fd array from userspace */
			error = copyin(es->fds, fds, es->count * sizeof(int));
			if (error != 0) {
				SDT_PROBE3(vbsd_coalition, , , enlist__set,
				    es->count, 0, error);
				free(fds, M_VBSD_COALITION);
				break;
			}

			/* Enlist each fd, stop on first error */
			for (i = 0; i < es->count; i++) {
				error = fget(td, fds[i], &cap_no_rights,
				    &target_fp);
				if (error != 0)
					break;

				error = vbsd_coalition_enlist_generic(vc, td,
				    target_fp);
				fdrop(target_fp, td);
				if (error != 0)
					break;

				/* Reference semantics: caller keeps their fd */
				es->enlisted++;
			}

			SDT_PROBE3(vbsd_coalition, , , enlist__set,
			    es->count, es->enlisted, error);
			free(fds, M_VBSD_COALITION);

			if (error != 0) {
				void *uaddr;

				if (td != NULL && td->td_sa.code == SYS_ioctl) {
					uaddr = (void *)(uintptr_t)td->td_sa.args[2];
					if (uaddr != NULL)
						(void)copyout(es, uaddr, sizeof(*es));
				}
			}
		}
		break;

	case VBSD_COALITION_STAT:
		{
			struct vbsd_coalition_stat *st = data;
			struct vbsd_member *vm;

			sx_slock(&vc->vc_sx);

			st->vcs_member_count = vc->vc_member_count;
			st->vcs_flags = vc->vc_flags;
			st->vcs_signal = vc->vc_signal;
			st->vcs_nesting_depth = vc->vc_nesting_depth;
			st->vcs_nested_count = 0;
			st->vcs_process_count = 0;
			st->vcs_jail_count = 0;
			st->vcs_other_count = 0;

			/* Count members by type */
			TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
				if (vm->vm_ops == &vbsd_proc_ops)
					st->vcs_process_count++;
				else if (vm->vm_ops == &vbsd_jail_ops)
					st->vcs_jail_count++;
				else if (vm->vm_ops == &vbsd_coalition_ops)
					st->vcs_nested_count++;
				else
					st->vcs_other_count++;
			}

			sx_sunlock(&vc->vc_sx);
			error = 0;
		}
		break;

	case VBSD_COALITION_SET_SIGNAL:
		{
			int sig = *(int *)data;

			if (sig <= 0 || sig >= NSIG) {
				error = EINVAL;
				break;
			}

			sx_xlock(&vc->vc_sx);
			if (vc->vc_flags & VCF_TERMINATING) {
				sx_xunlock(&vc->vc_sx);
				error = ESHUTDOWN;
				break;
			}
			vc->vc_signal = sig;
			sx_xunlock(&vc->vc_sx);
			error = 0;
		}
		break;

	case VBSD_COALITION_TERMINATE_GRACEFUL:
		{
			struct vbsd_graceful *g = data;
			u_int member_count __unused;

			member_count = atomic_load_acq_int(&vc->vc_member_count);
			AUDIT_ARG_VALUE(member_count);
			error = vbsd_coalition_terminate_graceful(vc, g->vg_signal,
			    g->vg_timeout_ms);
		}
		break;

	case VBSD_COALITION_SET_DEADLINE:
		{
			struct vbsd_deadline *d = data;

			sx_xlock(&vc->vc_sx);

			if (vc->vc_flags & VCF_TERMINATING) {
				sx_xunlock(&vc->vc_sx);
				error = ESHUTDOWN;
				break;
			}

			/*
			 * Cancel any existing deadline first.
			 * callout_stop returns true if the callout was pending.
			 */
			if (vc->vc_flags & VCF_DEADLINE_ACTIVE) {
				vc->vc_flags &= ~(VCF_DEADLINE_ACTIVE |
				    VCF_DEADLINE_GRACE);
				if (callout_stop(&vc->vc_deadline_callout)) {
					/*
					 * Callout was pending, release the
					 * reference it held.
					 */
					vbsd_coalition_rel(vc);
				}
				/*
				 * Note: if callout already fired and task is
				 * pending, task will see DEADLINE_ACTIVE cleared
				 * and release its reference without terminating.
				 */
			}

			if (d->vd_timeout_ms == 0) {
				/* Just cancel, don't set new deadline */
				sx_xunlock(&vc->vc_sx);
				error = 0;
				break;
			}

			/* Validate signal if specified */
			if (d->vd_signal != 0 &&
			    (d->vd_signal < 0 || d->vd_signal >= NSIG)) {
				sx_xunlock(&vc->vc_sx);
				error = EINVAL;
				break;
			}

			/* Set up new deadline */
			vc->vc_deadline_signal = d->vd_signal;
			vc->vc_deadline_grace_ms = d->vd_grace_ms;
			vc->vc_flags |= VCF_DEADLINE_ACTIVE;
			vc->vc_flags &= ~VCF_DEADLINE_GRACE;

			/* Take reference for callout */
			vbsd_coalition_ref(vc);

			/* Schedule the deadline callout */
			callout_reset(&vc->vc_deadline_callout,
			    d->vd_timeout_ms * hz / 1000,
			    vbsd_deadline_callout, vc);

			sx_xunlock(&vc->vc_sx);
			error = 0;
		}
		break;

	case VBSD_COALITION_SET_WATCHDOG:
		{
			uint32_t timeout_ms = *(uint32_t *)data;

			sx_xlock(&vc->vc_sx);

			if (vc->vc_flags & VCF_TERMINATING) {
				sx_xunlock(&vc->vc_sx);
				error = ESHUTDOWN;
				break;
			}

			/*
			 * Cancel any existing watchdog first.
			 */
			if (vc->vc_flags & VCF_WATCHDOG_ACTIVE) {
				vc->vc_flags &= ~VCF_WATCHDOG_ACTIVE;
				if (callout_stop(&vc->vc_watchdog_callout))
					vbsd_coalition_rel(vc);
			}

			if (timeout_ms == 0) {
				/* Just disable watchdog */
				sx_xunlock(&vc->vc_sx);
				error = 0;
				break;
			}

			/* Enable watchdog */
			vc->vc_watchdog_timeout_ms = timeout_ms;
			vc->vc_flags |= VCF_WATCHDOG_ACTIVE;
			vbsd_coalition_ref(vc);
			callout_reset(&vc->vc_watchdog_callout,
			    timeout_ms * hz / 1000,
			    vbsd_watchdog_callout, vc);

			sx_xunlock(&vc->vc_sx);
			error = 0;
		}
		break;

	case VBSD_COALITION_HEARTBEAT:
		{
			sx_xlock(&vc->vc_sx);

			if (vc->vc_flags & VCF_TERMINATING) {
				sx_xunlock(&vc->vc_sx);
				error = ESHUTDOWN;
				break;
			}

			if (!(vc->vc_flags & VCF_WATCHDOG_ACTIVE)) {
				/* No watchdog enabled */
				sx_xunlock(&vc->vc_sx);
				error = EINVAL;
				break;
			}

			/*
			 * Reset the watchdog timer.
			 * callout_reset on an already-scheduled callout
			 * just reschedules it.
			 */
			callout_reset(&vc->vc_watchdog_callout,
			    vc->vc_watchdog_timeout_ms * hz / 1000,
			    vbsd_watchdog_callout, vc);

			sx_xunlock(&vc->vc_sx);
			error = 0;
		}
		break;

	case VBSD_COALITION_SET_LEADER:
		{
			int target_fd;
			struct file *target_fp;
			struct vbsd_member *vm;

			target_fd = *(int *)data;

			sx_xlock(&vc->vc_sx);

			if (vc->vc_flags & VCF_TERMINATING) {
				sx_xunlock(&vc->vc_sx);
				error = ESHUTDOWN;
				break;
			}

			/* Clear leader if fd is -1 */
			if (target_fd == -1) {
				/*
				 * Clean up old leader's tracking structures.
				 */
				if (vc->vc_leader != NULL) {
					struct vbsd_member *old_vm = vc->vc_leader;

					if (old_vm->vm_ops == &vbsd_coalition_ops &&
					    old_vm->vm_fp != NULL) {
						/* Coalition: clear back-pointer */
						struct vbsd_coalition *old_child;

						old_child = old_vm->vm_fp->f_data;
						if (old_child != NULL) {
							sx_xlock(&old_child->vc_sx);
							old_child->vc_leader_of = NULL;
							sx_xunlock(&old_child->vc_sx);
						}
					} else if (old_vm->vm_ops != NULL &&
					    old_vm->vm_ops != &vbsd_proc_ops &&
					    old_vm->vm_ops != &vbsd_jail_ops &&
					    old_vm->vm_fp != NULL) {
						/* Third-party: remove from hash */
						vbsd_leader_hash_remove(old_vm->vm_fp);
					}
				}

				vc->vc_leader = NULL;
				vc->vc_leader_pid = 0;
				vc->vc_flags &= ~VCF_HAS_LEADER;
				sx_xunlock(&vc->vc_sx);
				error = 0;
				break;
			}

			/* Get the target file descriptor */
			error = fget(td, target_fd, &cap_no_rights, &target_fp);
			if (error != 0) {
				sx_xunlock(&vc->vc_sx);
				break;
			}

			/*
			 * Find this fd in our member list.
			 * Leader can be a process, jail, or nested coalition.
			 */
			TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
				if (vm->vm_fp == target_fp)
					break;
			}

			if (vm == NULL) {
				/* Not enlisted in this coalition */
				fdrop(target_fp, td);
				sx_xunlock(&vc->vc_sx);
				error = ESRCH;
				break;
			}

			/*
			 * Clean up old leader's tracking before setting new one.
			 */
			if (vc->vc_leader != NULL) {
				struct vbsd_member *old_vm = vc->vc_leader;

				if (old_vm->vm_ops == &vbsd_coalition_ops &&
				    old_vm->vm_fp != NULL) {
					struct vbsd_coalition *old_child;

					old_child = old_vm->vm_fp->f_data;
					if (old_child != NULL) {
						sx_xlock(&old_child->vc_sx);
						old_child->vc_leader_of = NULL;
						sx_xunlock(&old_child->vc_sx);
					}
				} else if (old_vm->vm_ops != NULL &&
				    old_vm->vm_ops != &vbsd_proc_ops &&
				    old_vm->vm_ops != &vbsd_jail_ops &&
				    old_vm->vm_fp != NULL) {
					vbsd_leader_hash_remove(old_vm->vm_fp);
				}
			}

			/*
			 * Validate the member type and extract tracking info.
			 * - Processes: track pid for exit handler
			 * - Jails: track member pointer (OSD destructor handles it)
			 * - Coalitions: track member pointer (terminate callback)
			 * - Third-party with MOF_CAN_LEAD: add to leader hash
			 */
			if (vm->vm_ops == &vbsd_proc_ops) {
				struct procdesc *pd;
				struct proc *p;
				pid_t pid;

				pd = target_fp->f_data;
				sx_slock(&proctree_lock);
				p = pd->pd_proc;
				if (p == NULL || (p->p_flag & P_WEXIT)) {
					sx_sunlock(&proctree_lock);
					fdrop(target_fp, td);
					sx_xunlock(&vc->vc_sx);
					error = ESRCH;
					break;
				}
				pid = p->p_pid;
				sx_sunlock(&proctree_lock);

				vc->vc_leader = vm;
				vc->vc_leader_pid = pid;
				vc->vc_flags |= VCF_HAS_LEADER;
			} else if (vm->vm_ops == &vbsd_jail_ops) {
				/* Jail leader - OSD destructor will trigger */
				vc->vc_leader = vm;
				vc->vc_leader_pid = 0;
				vc->vc_flags |= VCF_HAS_LEADER;
			} else if (vm->vm_ops == &vbsd_coalition_ops) {
				/* Nested coalition leader */
				struct vbsd_coalition *child_vc;

				child_vc = target_fp->f_data;
				if (child_vc == NULL) {
					fdrop(target_fp, td);
					sx_xunlock(&vc->vc_sx);
					error = EINVAL;
					break;
				}

				/*
				 * Set back-pointer so child can notify us
				 * when it terminates.
				 */
				sx_xlock(&child_vc->vc_sx);
				child_vc->vc_leader_of = vm;
				sx_xunlock(&child_vc->vc_sx);

				vc->vc_leader = vm;
				vc->vc_leader_pid = 0;
				vc->vc_flags |= VCF_HAS_LEADER;
			} else if (vm->vm_ops != NULL &&
			    (vm->vm_ops->mo_flags & MOF_CAN_LEAD)) {
				/*
				 * Third-party type with MOF_CAN_LEAD.
				 * Module fires VBSD_LEADER_DIED when resource dies.
				 */
				vbsd_leader_hash_insert(target_fp, vm);

				vc->vc_leader = vm;
				vc->vc_leader_pid = 0;
				vc->vc_flags |= VCF_HAS_LEADER;
			} else {
				/*
				 * Type doesn't support being a leader.
				 * Either no ops, or MOF_CAN_LEAD not set.
				 */
				fdrop(target_fp, td);
				sx_xunlock(&vc->vc_sx);
				error = EINVAL;
				break;
			}

			fdrop(target_fp, td);
			sx_xunlock(&vc->vc_sx);
			error = 0;
		}
		break;

	case VBSD_COALITION_RUSAGE:
		{
			struct vbsd_coalition_rusage *ru;
			struct vbsd_member *vm;
			struct proc *p;
			struct kinfo_proc kp;

			ru = (struct vbsd_coalition_rusage *)data;
			memset(ru, 0, sizeof(*ru));

			sx_slock(&vc->vc_sx);

			TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
				if (vm->vm_ops == &vbsd_proc_ops) {
					p = NULL;
					if (vm->vm_fp != NULL) {
						struct procdesc *pd = vm->vm_fp->f_data;
						if (pd != NULL)
							p = pd->pd_proc;
					} else if (vm->vm_data != NULL) {
						p = (struct proc *)atomic_load_acq_ptr(
						    (uintptr_t *)&vm->vm_data);
					}

					if (p == NULL)
						continue;

					PROC_LOCK(p);
					if (p->p_state == PRS_ZOMBIE ||
					    (p->p_flag & P_WEXIT)) {
						PROC_UNLOCK(p);
						continue;
					}

					fill_kinfo_proc(p, &kp);
					PROC_UNLOCK(p);

					ru->vcr_nprocs++;
					ru->vcr_nthreads += kp.ki_numthreads;
					ru->vcr_rss_bytes +=
					    (uint64_t)kp.ki_rssize * PAGE_SIZE;
					ru->vcr_vsz_bytes += kp.ki_size;
					ru->vcr_user_usec +=
					    (uint64_t)kp.ki_rusage.ru_utime.tv_sec *
					    1000000 + kp.ki_rusage.ru_utime.tv_usec;
					ru->vcr_sys_usec +=
					    (uint64_t)kp.ki_rusage.ru_stime.tv_sec *
					    1000000 + kp.ki_rusage.ru_stime.tv_usec;
					ru->vcr_inblock += kp.ki_rusage.ru_inblock;
					ru->vcr_oublock += kp.ki_rusage.ru_oublock;
					ru->vcr_majflt += kp.ki_rusage.ru_majflt;
					ru->vcr_minflt += kp.ki_rusage.ru_minflt;
					continue;
				}

				/*
				 * Handle jail members - aggregate all processes
				 * running inside the jail.
				 */
				if (vm->vm_ops == &vbsd_jail_ops &&
				    vm->vm_fp != NULL) {
					struct jaildesc *jd;
					struct prison *pr;

					jd = vm->vm_fp->f_data;
					if (jd == NULL)
						continue;

					JAILDESC_LOCK(jd);
					pr = jd->jd_prison;
					if (pr == NULL || !prison_isvalid(pr)) {
						JAILDESC_UNLOCK(jd);
						continue;
					}
					prison_hold(pr);
					JAILDESC_UNLOCK(jd);

					/*
					 * Iterate all processes, aggregate those
					 * in this jail (or its descendants).
					 */
					sx_slock(&allproc_lock);
					FOREACH_PROC_IN_SYSTEM(p) {
						PROC_LOCK(p);
						if (p->p_state == PRS_ZOMBIE ||
						    (p->p_flag & P_WEXIT) ||
						    p->p_ucred == NULL) {
							PROC_UNLOCK(p);
							continue;
						}

						/*
						 * Check if process is in this jail
						 * or a descendant jail.
						 */
						if (!prison_ischild(pr,
						    p->p_ucred->cr_prison)) {
							PROC_UNLOCK(p);
							continue;
						}

						fill_kinfo_proc(p, &kp);
						PROC_UNLOCK(p);

						ru->vcr_nprocs++;
						ru->vcr_nthreads += kp.ki_numthreads;
						ru->vcr_rss_bytes +=
						    (uint64_t)kp.ki_rssize * PAGE_SIZE;
						ru->vcr_vsz_bytes += kp.ki_size;
						ru->vcr_user_usec +=
						    (uint64_t)kp.ki_rusage.ru_utime.tv_sec *
						    1000000 + kp.ki_rusage.ru_utime.tv_usec;
						ru->vcr_sys_usec +=
						    (uint64_t)kp.ki_rusage.ru_stime.tv_sec *
						    1000000 + kp.ki_rusage.ru_stime.tv_usec;
						ru->vcr_inblock += kp.ki_rusage.ru_inblock;
						ru->vcr_oublock += kp.ki_rusage.ru_oublock;
						ru->vcr_majflt += kp.ki_rusage.ru_majflt;
						ru->vcr_minflt += kp.ki_rusage.ru_minflt;
					}
					sx_sunlock(&allproc_lock);
					prison_free(pr);
					continue;
				}

				/*
				 * Handle nested coalition members - recursively
				 * aggregate stats from child coalition.
				 * Note: vc_sx is held as slock, child coalition
				 * will also take its own sx as slock.
				 */
				if (vm->vm_ops == &vbsd_coalition_ops &&
				    vm->vm_fp != NULL &&
				    vbsd_is_coalition(vm->vm_fp)) {
					struct vbsd_coalition *child_vc;
					struct vbsd_coalition_rusage child_ru;
					struct vbsd_member *child_vm;

					child_vc = vm->vm_fp->f_data;
					if (child_vc == NULL)
						continue;

					/*
					 * Aggregate child's process members.
					 * Don't recurse further to avoid stack
					 * overflow; only handle direct processes.
					 */
					memset(&child_ru, 0, sizeof(child_ru));
					sx_slock(&child_vc->vc_sx);

					TAILQ_FOREACH(child_vm,
					    &child_vc->vc_members, vm_link) {
						if (child_vm->vm_ops !=
						    &vbsd_proc_ops)
							continue;

						p = NULL;
						if (child_vm->vm_fp != NULL) {
							struct procdesc *pd;
							pd = child_vm->vm_fp->f_data;
							if (pd != NULL)
								p = pd->pd_proc;
						} else if (child_vm->vm_data != NULL) {
							p = (struct proc *)
							    atomic_load_acq_ptr(
							    (uintptr_t *)&child_vm->vm_data);
						}

						if (p == NULL)
							continue;

						PROC_LOCK(p);
						if (p->p_state == PRS_ZOMBIE ||
						    (p->p_flag & P_WEXIT)) {
							PROC_UNLOCK(p);
							continue;
						}

						fill_kinfo_proc(p, &kp);
						PROC_UNLOCK(p);

						child_ru.vcr_nprocs++;
						child_ru.vcr_nthreads +=
						    kp.ki_numthreads;
						child_ru.vcr_rss_bytes +=
						    (uint64_t)kp.ki_rssize *
						    PAGE_SIZE;
						child_ru.vcr_vsz_bytes +=
						    kp.ki_size;
						child_ru.vcr_user_usec +=
						    (uint64_t)kp.ki_rusage.
						    ru_utime.tv_sec * 1000000 +
						    kp.ki_rusage.ru_utime.tv_usec;
						child_ru.vcr_sys_usec +=
						    (uint64_t)kp.ki_rusage.
						    ru_stime.tv_sec * 1000000 +
						    kp.ki_rusage.ru_stime.tv_usec;
						child_ru.vcr_inblock +=
						    kp.ki_rusage.ru_inblock;
						child_ru.vcr_oublock +=
						    kp.ki_rusage.ru_oublock;
						child_ru.vcr_majflt +=
						    kp.ki_rusage.ru_majflt;
						child_ru.vcr_minflt +=
						    kp.ki_rusage.ru_minflt;
					}
					sx_sunlock(&child_vc->vc_sx);

					/* Merge child stats into parent */
					ru->vcr_nprocs += child_ru.vcr_nprocs;
					ru->vcr_nthreads += child_ru.vcr_nthreads;
					ru->vcr_rss_bytes += child_ru.vcr_rss_bytes;
					ru->vcr_vsz_bytes += child_ru.vcr_vsz_bytes;
					ru->vcr_user_usec += child_ru.vcr_user_usec;
					ru->vcr_sys_usec += child_ru.vcr_sys_usec;
					ru->vcr_inblock += child_ru.vcr_inblock;
					ru->vcr_oublock += child_ru.vcr_oublock;
					ru->vcr_majflt += child_ru.vcr_majflt;
					ru->vcr_minflt += child_ru.vcr_minflt;
					continue;
				}
			}

			sx_sunlock(&vc->vc_sx);
			error = 0;
		}
		break;

	default:
		error = ENOTTY;
		break;
	}

	return (error);
}

static int
vbsd_coalition_fo_close(struct file *fp, struct thread *td)
{
	struct vbsd_coalition *vc;
	struct vbsd_member *vm, *vm_temp;
	u_int member_count __unused;

	vc = fp->f_data;
	if (vc == NULL)
		return (0);
	fp->f_data = NULL;

	/* Drain pending callouts/tasks before acquiring vc_sx to avoid deadlock */
	callout_drain(&vc->vc_deadline_callout);
	taskqueue_drain(taskqueue_thread, &vc->vc_deadline_task);
	callout_drain(&vc->vc_watchdog_callout);
	taskqueue_drain(taskqueue_thread, &vc->vc_watchdog_task);

	member_count = atomic_load_acq_int(&vc->vc_member_count);
	SDT_PROBE1(vbsd_coalition, , , close, member_count);

	sx_xlock(&vc->vc_sx);

	/*
	 * If deadline/watchdog was active, release the reference that was held
	 * for the callout/task. The drain above ensures nothing is running.
	 */
	if (vc->vc_flags & VCF_DEADLINE_ACTIVE) {
		vc->vc_flags &= ~(VCF_DEADLINE_ACTIVE | VCF_DEADLINE_GRACE);
		vbsd_coalition_rel(vc);
	}
	if (vc->vc_flags & VCF_WATCHDOG_ACTIVE) {
		vc->vc_flags &= ~VCF_WATCHDOG_ACTIVE;
		vbsd_coalition_rel(vc);
	}
	vbsd_coalition_terminate_members_locked(vc, td, true);

	/*
	 * Collect ALL members to clean up. We remove from TAILQ while
	 * holding vc_sx, but defer fdrop/termination until after releasing
	 * the lock. This prevents deadlock:
	 * - fdrop on procdesc may need proctree_lock
	 * - jail termination (prison_remove) can trigger OSD destructor
	 *   which tries to take vc_sx
	 */
	struct vbsd_member *cleanup_list = NULL;
	struct vbsd_member **cleanup_tailp = &cleanup_list;
	struct vbsd_member *jail_list = NULL;
	struct vbsd_member **jail_tailp = &jail_list;

	TAILQ_FOREACH_SAFE(vm, &vc->vc_members, vm_link, vm_temp) {
		TAILQ_REMOVE(&vc->vc_members, vm, vm_link);

		if (vm->vm_ops == &vbsd_jail_ops) {
			/*
			 * Collect jails separately for deferred termination.
			 * Mark tqe_prev as NULL so the OSD destructor knows
			 * we already removed this member from the TAILQ.
			 */
			vm->vm_link.tqe_prev = NULL;
			*jail_tailp = vm;
			jail_tailp = (struct vbsd_member **)&vm->vm_link.tqe_next;
			continue;
		}

		/*
		 * For process members, remove from hash table if not already
		 * removed by exit handler. Exit handler sets le_prev to NULL
		 * after removal to signal it's already been removed.
		 */
		if (vm->vm_ops == &vbsd_proc_ops) {
			rw_wlock(&vbsd_proc_hash_lock);
			if (vm->vm_hash.le_prev != NULL)
				LIST_REMOVE(vm, vm_hash);
			rw_wunlock(&vbsd_proc_hash_lock);
		}

		/* Link onto cleanup list via vm_link.tqe_next */
		*cleanup_tailp = vm;
		cleanup_tailp = (struct vbsd_member **)&vm->vm_link.tqe_next;
	}
	*cleanup_tailp = NULL;
	*jail_tailp = NULL;

	/* Notify kqueue watchers that the coalition is terminated */
	KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_TERMINATED);

	sx_xunlock(&vc->vc_sx);

	/* Clean up knlist (detaches all knotes) */
	knlist_destroy(&vc->vc_knlist);

	/*
	 * Now clean up collected members without holding vc_sx.
	 * This allows procdesc_close to acquire proctree_lock without
	 * risking deadlock with dying processes.
	 */
	for (vm = cleanup_list; vm != NULL; ) {
		struct vbsd_member *next = (struct vbsd_member *)vm->vm_link.tqe_next;

		atomic_subtract_int(&vc->vc_member_count, 1);
		/*
		 * Skip ops_release for nested coalitions - they use
		 * vbsd_coalition_ops directly without calling ops_acquire.
		 */
		if (vm->vm_ops != &vbsd_coalition_ops)
			atomic_subtract_int(&vbsd_member_count, 1);

		if (vm->vm_fp != NULL)
			fdrop(vm->vm_fp, td);

		uma_zfree(vbsd_member_zone, vm);
		vbsd_coalition_rel(vc);

		vm = next;
	}

	/*
	 * Now terminate and clean up jail members without holding vc_sx.
	 *
	 * CRITICAL: We must clear vjo_member BEFORE calling prison_remove,
	 * because prison_remove triggers the OSD destructor. If vjo_member
	 * is still set, the destructor would try to TAILQ_REMOVE the member
	 * that we already removed above, corrupting the list.
	 */
	for (vm = jail_list; vm != NULL; ) {
		struct vbsd_member *next = (struct vbsd_member *)vm->vm_link.tqe_next;
		struct jaildesc *jd;
		struct prison *pr;
		struct vbsd_jail_osd *vjo;

		/*
		 * Step 1: Clear the OSD's member pointer FIRST.
		 * This MUST happen before prison_remove/fdrop to prevent
		 * the OSD destructor from doing duplicate TAILQ_REMOVE.
		 */
		if (vm->vm_fp != NULL && vm->vm_fp->f_data != NULL) {
			jd = vm->vm_fp->f_data;
			JAILDESC_LOCK(jd);
			pr = jd->jd_prison;
			if (pr != NULL && prison_isvalid(pr)) {
				prison_hold(pr);
				JAILDESC_UNLOCK(jd);

				prison_lock(pr);
				vjo = osd_jail_get(pr, vbsd_jail_osd_slot);
				if (vjo != NULL)
					vjo->vjo_member = NULL;
				prison_unlock(pr);

				prison_free(pr);
			} else {
				JAILDESC_UNLOCK(jd);
			}
		}

		/*
		 * Step 2: Terminate the jail (kill processes).
		 * Now safe to call because vjo_member is NULL.
		 */
		if (vm->vm_fp != NULL && vm->vm_ops != NULL &&
		    vm->vm_ops->mo_terminate != NULL)
			(void)vm->vm_ops->mo_terminate(vm->vm_fp, td);

		atomic_subtract_int(&vc->vc_member_count, 1);
		atomic_subtract_int(&vbsd_member_count, 1);

		/* Release file reference */
		if (vm->vm_fp != NULL)
			fdrop(vm->vm_fp, td);

		uma_zfree(vbsd_member_zone, vm);
		vbsd_coalition_rel(vc);

		vm = next;
	}

	vbsd_coalition_rel(vc);
	return (0);
}

/* Device and Module Init */

static struct cdev *vbsd_coalition_dev;

static int
vbsd_coalition_dev_fdopen(struct cdev *dev __unused, int oflags __unused,
    struct thread *td __unused, struct file *fp)
{

	return (vbsd_coalition_init_file(fp));
}

static struct cdevsw vbsd_coalition_cdevsw = {
	.d_version = D_VERSION,
	.d_fdopen = vbsd_coalition_dev_fdopen,
	.d_name = "vbsd_coalition",
};

static int
vbsd_proc_hash_init(void)
{
	int i;

	rw_init(&vbsd_proc_hash_lock, "vbsd_proc_hash");
	for (i = 0; i < VBSD_PROC_HASH_SIZE; i++)
		LIST_INIT(&vbsd_proc_hash[i]);
	return (0);
}

static void
vbsd_proc_hash_fini(void)
{
	rw_destroy(&vbsd_proc_hash_lock);
}

/* Leader Hash Table for third-party leader death notification */

static int
vbsd_leader_hash_init(void)
{
	int i;

	mtx_init(&vbsd_leader_hash_lock, "vbsd_leader_hash", NULL, MTX_DEF);
	for (i = 0; i < VBSD_LEADER_HASH_SIZE; i++)
		LIST_INIT(&vbsd_leader_hash[i]);
	return (0);
}

static void
vbsd_leader_hash_fini(void)
{
	mtx_destroy(&vbsd_leader_hash_lock);
}

static void
vbsd_leader_hash_insert(struct file *fp, struct vbsd_member *vm)
{
	struct vbsd_leader_entry *vle;
	u_int idx;

	vle = malloc(sizeof(*vle), M_VBSD_COALITION, M_WAITOK);
	vle->vle_fp = fp;
	vle->vle_member = vm;

	mtx_lock(&vbsd_leader_hash_lock);
	idx = vbsd_leader_hash_index(fp);
	LIST_INSERT_HEAD(&vbsd_leader_hash[idx], vle, vle_link);
	mtx_unlock(&vbsd_leader_hash_lock);
}

static struct vbsd_member *
vbsd_leader_hash_lookup(struct file *fp)
{
	struct vbsd_leader_entry *vle;
	struct vbsd_member *vm = NULL;
	u_int idx;

	mtx_lock(&vbsd_leader_hash_lock);
	idx = vbsd_leader_hash_index(fp);
	LIST_FOREACH(vle, &vbsd_leader_hash[idx], vle_link) {
		if (vle->vle_fp == fp) {
			vm = vle->vle_member;
			break;
		}
	}
	mtx_unlock(&vbsd_leader_hash_lock);
	return (vm);
}

static void
vbsd_leader_hash_remove(struct file *fp)
{
	struct vbsd_leader_entry *vle;
	u_int idx;

	mtx_lock(&vbsd_leader_hash_lock);
	idx = vbsd_leader_hash_index(fp);
	LIST_FOREACH(vle, &vbsd_leader_hash[idx], vle_link) {
		if (vle->vle_fp == fp) {
			LIST_REMOVE(vle, vle_link);
			mtx_unlock(&vbsd_leader_hash_lock);
			free(vle, M_VBSD_COALITION);
			return;
		}
	}
	mtx_unlock(&vbsd_leader_hash_lock);
}

/*
 * Third-party leader death event handler.
 * Called when a third-party module fires VBSD_LEADER_DIED(fp).
 */
static void
vbsd_leader_died_handler(void *arg __unused, struct file *fp)
{
	struct vbsd_member *vm;
	struct vbsd_coalition *vc;

	vm = vbsd_leader_hash_lookup(fp);
	if (vm == NULL)
		return;

	vc = vm->vm_coalition;
	if (vc == NULL)
		return;

	sx_xlock(&vc->vc_sx);

	/* Verify this is still the leader and not already terminating */
	if (vc->vc_leader != vm || (vc->vc_flags & VCF_TERMINATING)) {
		sx_xunlock(&vc->vc_sx);
		return;
	}

	/* Remove from hash before triggering termination */
	vbsd_leader_hash_remove(fp);

	/* Notify kqueue listeners */
	KNOTE_LOCKED(&vc->vc_knlist, VBSD_NOTE_LEADER_DIED);

	/* Trigger coalition termination */
	vbsd_coalition_terminate_members_locked(vc, curthread, false);

	sx_xunlock(&vc->vc_sx);
}

static int
vbsd_jail_osd_init(void)
{
	vbsd_jail_osd_slot = osd_jail_register(vbsd_jail_osd_dtor, NULL);
	if (vbsd_jail_osd_slot == 0)
		return (ENOMEM);
	return (0);
}

static void
vbsd_jail_osd_fini(void)
{
	if (vbsd_jail_osd_slot != 0)
		osd_jail_deregister(vbsd_jail_osd_slot);
}

static int
vbsd_eventhandler_init(void)
{
	vbsd_fork_tag = EVENTHANDLER_REGISTER(process_fork, vbsd_process_fork,
	    NULL, EVENTHANDLER_PRI_ANY);
	if (vbsd_fork_tag == NULL)
		return (ENOMEM);

	vbsd_exit_tag = EVENTHANDLER_REGISTER(process_exit, vbsd_process_exit,
	    NULL, EVENTHANDLER_PRI_ANY);
	if (vbsd_exit_tag == NULL) {
		EVENTHANDLER_DEREGISTER(process_fork, vbsd_fork_tag);
		return (ENOMEM);
	}

	vbsd_leader_died_tag = EVENTHANDLER_REGISTER(vbsd_leader_died,
	    vbsd_leader_died_handler, NULL, EVENTHANDLER_PRI_ANY);
	if (vbsd_leader_died_tag == NULL) {
		EVENTHANDLER_DEREGISTER(process_exit, vbsd_exit_tag);
		EVENTHANDLER_DEREGISTER(process_fork, vbsd_fork_tag);
		return (ENOMEM);
	}

	return (0);
}

static void
vbsd_eventhandler_fini(void)
{
	EVENTHANDLER_DEREGISTER(vbsd_leader_died, vbsd_leader_died_tag);
	EVENTHANDLER_DEREGISTER(process_fork, vbsd_fork_tag);
	EVENTHANDLER_DEREGISTER(process_exit, vbsd_exit_tag);
}

static int
vbsd_coalition_mod_init(void)
{
	int error;

	mtx_init(&vbsd_external_ops_lock, "vbsd_ext_ops", NULL, MTX_DEF);

	vbsd_coalition_zone = uma_zcreate("vbsd_coalition",
	    sizeof(struct vbsd_coalition), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	vbsd_member_zone = uma_zcreate("vbsd_member",
	    sizeof(struct vbsd_member), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	error = vbsd_proc_hash_init();
	if (error != 0)
		goto fail_hash;

	error = vbsd_leader_hash_init();
	if (error != 0)
		goto fail_leader_hash;

	error = vbsd_jail_osd_init();
	if (error != 0)
		goto fail_osd;

	error = vbsd_eventhandler_init();
	if (error != 0)
		goto fail_event;

	vbsd_coalition_dev = make_dev(&vbsd_coalition_cdevsw, 0,
	    UID_ROOT, GID_WHEEL, 0600, "vbsd_coalition");
	if (vbsd_coalition_dev == NULL) {
		error = ENXIO;
		goto fail_dev;
	}

	log(LOG_INFO, "vbsd_coalition: loaded\n");
	return (0);

fail_dev:
	vbsd_eventhandler_fini();
fail_event:
	vbsd_jail_osd_fini();
fail_osd:
	vbsd_leader_hash_fini();
fail_leader_hash:
	vbsd_proc_hash_fini();
fail_hash:
	uma_zdestroy(vbsd_member_zone);
	uma_zdestroy(vbsd_coalition_zone);
	mtx_destroy(&vbsd_external_ops_lock);
	return (error);
}

static int
vbsd_coalition_modevent(module_t mod __unused, int type, void *arg __unused)
{

	switch (type) {
	case MOD_LOAD:
		return (vbsd_coalition_mod_init());
	case MOD_UNLOAD:
		/*
		 * Refuse to unload if any coalitions are still active.
		 * This prevents use-after-free when UMA zones are destroyed.
		 */
		if (atomic_load_acq_int(&vbsd_coalition_count) != 0) {
			log(LOG_WARNING,
			    "vbsd_coalition: cannot unload, %u active coalitions\n",
			    atomic_load_acq_int(&vbsd_coalition_count));
			return (EBUSY);
		}

		destroy_dev(vbsd_coalition_dev);
		vbsd_eventhandler_fini();
		vbsd_jail_osd_fini();
		vbsd_leader_hash_fini();
		vbsd_proc_hash_fini();

		uma_zdestroy(vbsd_member_zone);
		uma_zdestroy(vbsd_coalition_zone);
		mtx_destroy(&vbsd_external_ops_lock);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t vbsd_coalition_mod = {
	"vbsd_coalition",
	vbsd_coalition_modevent,
	NULL
};

DECLARE_MODULE(vbsd_coalition, vbsd_coalition_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(vbsd_coalition, 1);
