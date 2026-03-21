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

#include <security/audit/audit.h>

#include <machine/atomic.h>

#include <vm/uma.h>

#include "vbsd_coalition.h"

/* ========================================================================
 * DTrace SDT Probes
 *
 * Provider: coalition
 *
 * Usage examples:
 *   dtrace -n 'coalition:::create { printf("pid=%d", arg0); }'
 *   dtrace -n 'coalition:::enlist { printf("fd=%d dtype=%d err=%d", arg0, arg1, arg2); }'
 *   dtrace -n 'coalition:::terminate { printf("members=%d err=%d", arg0, arg1); }'
 * ======================================================================== */

SDT_PROVIDER_DEFINE(coalition);

/* coalition:::create(pid_t pid) */
SDT_PROBE_DEFINE1(coalition, , , create,
    "pid_t");

/* coalition:::enlist(int fd, int dtype, int error) */
SDT_PROBE_DEFINE3(coalition, , , enlist,
    "int", "int", "int");

/* coalition:::enlist__set(u_int count, u_int enlisted, int error) */
SDT_PROBE_DEFINE3(coalition, , , enlist__set,
    "u_int", "u_int", "int");

/* coalition:::join(pid_t pid, int error) */
SDT_PROBE_DEFINE2(coalition, , , join,
    "pid_t", "int");

/* coalition:::terminate(u_int member_count, int error) */
SDT_PROBE_DEFINE2(coalition, , , terminate,
    "u_int", "int");

/* coalition:::close(u_int member_count) */
SDT_PROBE_DEFINE1(coalition, , , close,
    "u_int");

/* coalition:::member__exit(pid_t pid) */
SDT_PROBE_DEFINE1(coalition, , , member__exit,
    "pid_t");

/* coalition:::fork__inherit(pid_t parent, pid_t child) */
SDT_PROBE_DEFINE2(coalition, , , fork__inherit,
    "pid_t", "pid_t")

MALLOC_DEFINE(M_VBSD_COALITION, "vbsd_coalition", "vBSD Coalition structures");

/* ========================================================================
 * Ops Registration Table
 *
 * DTYPE allocation:
 *   0-31    Reserved for FreeBSD (DTYPE_VNODE, DTYPE_SOCKET, etc.)
 *   32-255  Available for external modules (DTYPE_KEYVAULT, etc.)
 * ======================================================================== */

#define VBSD_OPS_TABLE_SIZE	256

struct vbsd_ops_entry {
	struct vbsd_member_ops	*ops;
	volatile u_int		member_count;	/* Active members of this type */
};

/* Forward declaration for fallback ops */
static struct vbsd_member_ops vbsd_default_ops;

static struct vbsd_ops_entry vbsd_ops_table[VBSD_OPS_TABLE_SIZE];
static struct mtx vbsd_ops_lock;

int
vbsd_member_ops_register(int dtype, struct vbsd_member_ops *ops)
{

	if (dtype < 0 || dtype >= VBSD_OPS_TABLE_SIZE)
		return (EINVAL);
	if (ops == NULL || ops->mo_terminate == NULL)
		return (EINVAL);

	mtx_lock(&vbsd_ops_lock);
	if (vbsd_ops_table[dtype].ops != NULL) {
		mtx_unlock(&vbsd_ops_lock);
		return (EEXIST);
	}
	vbsd_ops_table[dtype].member_count = 0;
	/*
	 * Release barrier ensures member_count=0 is visible before ops
	 * pointer. Pairs with acquire in vbsd_member_ops_lookup().
	 */
	atomic_store_rel_ptr((uintptr_t *)&vbsd_ops_table[dtype].ops,
	    (uintptr_t)ops);
	mtx_unlock(&vbsd_ops_lock);

	log(LOG_INFO, "vbsd_coalition: registered ops for %s (dtype %d)\n",
	    ops->mo_name, dtype);
	return (0);
}

int
vbsd_member_ops_deregister(int dtype)
{

	if (dtype < 0 || dtype >= VBSD_OPS_TABLE_SIZE)
		return (EINVAL);

	mtx_lock(&vbsd_ops_lock);
	if (vbsd_ops_table[dtype].member_count != 0) {
		mtx_unlock(&vbsd_ops_lock);
		return (EBUSY);
	}
	vbsd_ops_table[dtype].ops = NULL;
	mtx_unlock(&vbsd_ops_lock);

	return (0);
}

/*
 * Acquire ops for a dtype, atomically incrementing member count.
 *
 * This function atomically looks up ops and increments member_count
 * under the ops lock, preventing a race with deregistration.
 *
 * If no ops are registered for this dtype, falls back to default ops.
 * This allows any fd type to be enlisted - types without custom
 * terminate behavior simply get fdrop() on coalition close.
 *
 * Returns ops pointer (never NULL for valid dtype).
 * Returns NULL only for invalid dtype (out of range).
 */
static struct vbsd_member_ops *
vbsd_member_ops_acquire(int dtype)
{
	struct vbsd_member_ops *ops;

	if (dtype < 0 || dtype >= VBSD_OPS_TABLE_SIZE)
		return (NULL);

	mtx_lock(&vbsd_ops_lock);
	ops = vbsd_ops_table[dtype].ops;
	if (ops == NULL)
		ops = &vbsd_default_ops;  /* Fallback: just close on terminate */
	vbsd_ops_table[dtype].member_count++;
	mtx_unlock(&vbsd_ops_lock);

	return (ops);
}

/*
 * Release ops for a dtype, decrementing member count.
 */
static void
vbsd_member_ops_release(int dtype)
{

	KASSERT(dtype >= 0 && dtype < VBSD_OPS_TABLE_SIZE,
	    ("vbsd_member_ops_release: bad dtype %d", dtype));

	mtx_lock(&vbsd_ops_lock);
	KASSERT(vbsd_ops_table[dtype].member_count > 0,
	    ("vbsd_member_ops_release: underflow for dtype %d", dtype));
	vbsd_ops_table[dtype].member_count--;
	mtx_unlock(&vbsd_ops_lock);
}

/*
 * Increment member count for built-in ops that are never deregistered.
 * Used by self-join and fork inheritance where we know the ops are valid.
 */
static void
vbsd_member_count_inc_builtin(int dtype)
{

	KASSERT(dtype >= 0 && dtype < VBSD_OPS_TABLE_SIZE,
	    ("vbsd_member_count_inc_builtin: bad dtype %d", dtype));

	mtx_lock(&vbsd_ops_lock);
	KASSERT(vbsd_ops_table[dtype].ops != NULL,
	    ("vbsd_member_count_inc_builtin: no ops for dtype %d", dtype));
	vbsd_ops_table[dtype].member_count++;
	mtx_unlock(&vbsd_ops_lock);
}

/* ========================================================================
 * UMA Zones and Global State
 * ======================================================================== */

static uma_zone_t vbsd_coalition_zone;
static uma_zone_t vbsd_coalition_file_zone;
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

/* Debug sequence counter for ordering log messages */
static volatile u_int vbsd_debug_seq;
#define VBSD_SEQ() atomic_fetchadd_int(&vbsd_debug_seq, 1)

/* Forward declarations */
static fo_ioctl_t	vbsd_coalition_fo_ioctl;
static fo_close_t	vbsd_coalition_fo_close;
static fo_stat_t	vbsd_coalition_fo_stat;
static void		vbsd_coalition_terminate_members_locked(
			    struct vbsd_coalition *vc, struct thread *td,
			    bool skip_self);

/* ========================================================================
 * Sysctl Interface and Resource Limits
 * ======================================================================== */

/*
 * Resource exhaustion limits.
 * Defaults are generous but prevent unbounded growth.
 * Set to 0 to disable limit (unlimited).
 */
#define VBSD_DEFAULT_MAX_COALITIONS	4096
#define VBSD_DEFAULT_MAX_MEMBERS	65536
#define VBSD_DEFAULT_MAX_MEMBERS_PER	1024
#define VBSD_DEFAULT_ENLIST_SET_MAX	1024

static u_int vbsd_max_coalitions = VBSD_DEFAULT_MAX_COALITIONS;
static u_int vbsd_max_members = VBSD_DEFAULT_MAX_MEMBERS;
static u_int vbsd_max_members_per_coalition = VBSD_DEFAULT_MAX_MEMBERS_PER;
static u_int vbsd_enlist_set_max = VBSD_DEFAULT_ENLIST_SET_MAX;

SYSCTL_NODE(_kern, OID_AUTO, coalition, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "vBSD Coalition");

SYSCTL_UINT(_kern_coalition, OID_AUTO, count, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &vbsd_coalition_count), 0,
    "Number of active coalitions");

SYSCTL_UINT(_kern_coalition, OID_AUTO, max_coalitions, CTLFLAG_RW,
    &vbsd_max_coalitions, 0,
    "Maximum number of coalitions (0 = unlimited)");

SYSCTL_UINT(_kern_coalition, OID_AUTO, max_members, CTLFLAG_RW,
    &vbsd_max_members, 0,
    "Maximum total members across all coalitions (0 = unlimited)");

SYSCTL_UINT(_kern_coalition, OID_AUTO, max_members_per_coalition, CTLFLAG_RW,
    &vbsd_max_members_per_coalition, 0,
    "Maximum members per coalition (0 = unlimited)");

SYSCTL_UINT(_kern_coalition, OID_AUTO, enlist_set_max, CTLFLAG_RW,
    &vbsd_enlist_set_max, 0,
    "Maximum fds per VBSD_COALITION_ENLIST_SET call (default 1024)");

static int
sysctl_kern_coalition_members(SYSCTL_HANDLER_ARGS)
{
	u_int total, i;

	total = 0;
	for (i = 0; i < VBSD_OPS_TABLE_SIZE; i++)
		total += atomic_load_acq_int(&vbsd_ops_table[i].member_count);

	return (sysctl_handle_int(oidp, &total, 0, req));
}

SYSCTL_PROC(_kern_coalition, OID_AUTO, members,
    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_kern_coalition_members, "IU",
    "Total members across all coalitions");

/*
 * Check if adding a member would exceed resource limits.
 * Returns 0 if OK, ENOMEM if limit would be exceeded.
 */
static int
vbsd_check_member_limits(struct vbsd_coalition *vc)
{
	u_int max, current, i;

	/* Check per-coalition limit */
	max = vbsd_max_members_per_coalition;
	if (max != 0) {
		current = atomic_load_acq_int(&vc->vc_member_count);
		if (current >= max)
			return (ENOMEM);
	}

	/* Check global member limit */
	max = vbsd_max_members;
	if (max != 0) {
		current = 0;
		for (i = 0; i < VBSD_OPS_TABLE_SIZE; i++)
			current += atomic_load_acq_int(&vbsd_ops_table[i].member_count);
		if (current >= max)
			return (ENOMEM);
	}

	return (0);
}

/* ========================================================================
 * Built-in Process Ops (DTYPE_PROCDESC)
 * ======================================================================== */

/*
 * Process member data, stored in vm_data.
 * We need the proc pointer for signaling and hash table lookup.
 */
struct vbsd_proc_data {
	struct proc	*vpd_proc;
};

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
		/*
		 * Process already exited. This is not an error condition -
		 * the process is already dead, which is what we wanted.
		 * Return 0 to indicate success (no action needed).
		 */
		log(LOG_WARNING, "vbsd_coalition: proc_terminate: pd=%p pd->pd_proc is NULL (process already exited)\n", pd);
		return (0);
	}
	log(LOG_WARNING, "vbsd_coalition: proc_terminate: sending SIGKILL to pid=%d\n",
	    p->p_pid);
	PROC_LOCK(p);
	sx_sunlock(&proctree_lock);
	kern_psignal(p, SIGKILL);
	PROC_UNLOCK(p);
	log(LOG_WARNING, "vbsd_coalition: proc_terminate: SIGKILL sent to pid=%d\n",
	    p->p_pid);

	return (0);
}

static struct vbsd_member_ops vbsd_proc_ops = {
	.mo_terminate	= vbsd_proc_terminate,
	.mo_name	= "process",
};

/* ========================================================================
 * Built-in Jail Ops (DTYPE_JAILDESC)
 * ======================================================================== */

/*
 * Jail member data, stored in vm_data.
 * We need the prison pointer for prison_remove().
 */
struct vbsd_jail_data {
	struct prison	*vjd_prison;
};

static int
vbsd_jail_terminate(struct file *fp, struct thread *td __unused)
{
	struct jaildesc *jd;
	struct prison *pr;

	if (fp == NULL) {
		log(LOG_WARNING, "vbsd_coalition: jail_terminate: NULL fp\n");
		return (EINVAL);
	}
	if (fp->f_data == NULL) {
		log(LOG_WARNING, "vbsd_coalition: jail_terminate: NULL f_data\n");
		return (EINVAL);
	}

	jd = fp->f_data;
	JAILDESC_LOCK(jd);
	pr = jd->jd_prison;
	if (pr == NULL || !prison_isvalid(pr)) {
		JAILDESC_UNLOCK(jd);
		log(LOG_DEBUG, "vbsd_coalition: jail_terminate: prison invalid\n");
		return (ENOENT);
	}
	prison_hold(pr);
	JAILDESC_UNLOCK(jd);

	/*
	 * Call prison_remove to kill all processes in the jail.
	 *
	 * prison_remove() requires:
	 * 1. allprison_lock held exclusively (sx_xlock)
	 * 2. pr->pr_mtx held (mtx_lock)
	 * 3. A reference held on the prison (prison_hold)
	 *
	 * prison_remove() internally calls prison_deref() with
	 * PD_DEREF | PD_LOCKED | PD_LIST_XLOCKED, which releases:
	 * - Our held reference (PD_DEREF)
	 * - The prison mutex (PD_LOCKED)
	 * - The allprison_lock (PD_LIST_XLOCKED)
	 *
	 * So after prison_remove() returns, all locks are released.
	 */
	sx_xlock(&allprison_lock);
	mtx_lock(&pr->pr_mtx);

	if (prison_isalive(pr)) {
		log(LOG_DEBUG, "vbsd_coalition: jail_terminate: removing jail %d\n",
		    pr->pr_id);
		prison_remove(pr);
		/* prison_remove releases locks and reference */
	} else {
		/*
		 * Prison is already dying. Release locks and our reference.
		 */
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

/* ========================================================================
 * Built-in Default Ops (pipes, sockets, vnodes, etc.)
 * ======================================================================== */

/*
 * Default terminate - no-op.
 * For generic fds, terminate doesn't do anything special.
 * The fd will be closed via fdrop() afterward.
 */
static int
vbsd_default_terminate(struct file *fp __unused, struct thread *td __unused)
{
	return (0);
}

static struct vbsd_member_ops vbsd_default_ops = {
	.mo_terminate	= vbsd_default_terminate,
	.mo_name	= "generic",
};

/* ========================================================================
 * Built-in Socket Ops (DTYPE_SOCKET) - Aggressive shutdown
 * ======================================================================== */

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

/* ========================================================================
 * Built-in SHM Ops (DTYPE_SHM) - Truncate to invalidate mappings
 * ======================================================================== */

static int
vbsd_shm_terminate(struct file *fp, struct thread *td)
{

	KASSERT(fp != NULL, ("vbsd_shm_terminate: NULL fp"));

	/*
	 * Truncate to 0 - any process accessing mapped regions gets SIGBUS.
	 * This effectively kills any process that touches the shared memory.
	 *
	 * Note: Uses caller's credentials. If the caller lacks permission
	 * to truncate this SHM, the truncate will fail silently (error
	 * logged but termination continues).
	 */
	return (fo_truncate(fp, 0, td->td_ucred, td));
}

static struct vbsd_member_ops vbsd_shm_ops = {
	.mo_terminate	= vbsd_shm_terminate,
	.mo_name	= "shm",
};

/* ========================================================================
 * Built-in Coalition Ops (for nested coalitions)
 * ======================================================================== */

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
	struct vbsd_coalition_file *vcf;
	struct vbsd_coalition *vc;

	KASSERT(fp != NULL, ("vbsd_nested_coalition_terminate: NULL fp"));
	KASSERT(vbsd_is_coalition(fp),
	    ("vbsd_nested_coalition_terminate: not a coalition"));

	vcf = fp->f_data;
	vc = vcf->vcf_coalition;

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

/* ========================================================================
 * Coalition Core
 * ======================================================================== */

static int
vbsd_coalition_fo_stat(struct file *fp __unused, struct stat *sb,
    struct ucred *active_cred __unused)
{
	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFIFO;
	return (0);
}

static struct fileops vbsd_coalition_fileops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = vbsd_coalition_fo_ioctl,
	.fo_poll = invfo_poll,
	.fo_kqfilter = invfo_kqfilter,
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
	vc->vc_signal = SIGKILL;	/* Default to immediate termination */
	vc->vc_nesting_depth = 0;
	vc->vc_flags = 0;	/* Explicitly clear flags */
	refcount_init(&vc->vc_refcount, 1);
	atomic_add_int(&vbsd_coalition_count, 1);
	log(LOG_WARNING, "vbsd_coalition: alloc: vc=%p flags=%u\n", vc, vc->vc_flags);

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

static int
vbsd_coalition_init_file(struct file *fp)
{
	struct vbsd_coalition *vc;
	struct vbsd_coalition_file *vcf;
	u_int max, current;

	/* Check coalition count limit */
	max = vbsd_max_coalitions;
	if (max != 0) {
		current = atomic_load_acq_int(&vbsd_coalition_count);
		if (current >= max)
			return (ENOMEM);
	}

	vc = vbsd_coalition_alloc();
	vcf = uma_zalloc(vbsd_coalition_file_zone, M_WAITOK | M_ZERO);
	vcf->vcf_coalition = vc;

	finit(fp, FREAD | FWRITE, DTYPE_DEV, vcf, &vbsd_coalition_fileops);

	SDT_PROBE1(coalition, , , create, curthread->td_proc->p_pid);

	return (0);
}

static void
vbsd_coalition_mark_clofork(struct thread *td, struct file *fp)
{
	struct filedesc *fdp;
	struct filedescent *fde;
	int i;

	if (td == NULL || td->td_proc == NULL)
		return;

	/* Prevent implicit inheritance; coalition fds must be passed explicitly. */
	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	for (i = 0; i < fdp->fd_nfiles; i++) {
		fde = &fdp->fd_ofiles[i];
		if (fde->fde_file == fp)
			fde->fde_flags |= UF_FOCLOSE;
	}
	FILEDESC_XUNLOCK(fdp);
}

/* ========================================================================
 * Process Hash Table (for exit handler)
 * ======================================================================== */

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
		struct vbsd_proc_data *vpd = vm->vm_data;
		if (vpd != NULL && vpd->vpd_proc == p)
			return (vm);
	}
	return (NULL);
}

/* ========================================================================
 * Jail OSD (for fork inheritance)
 * ======================================================================== */

struct vbsd_jail_osd {
	struct vbsd_coalition	*vjo_coalition;
	struct vbsd_member	*vjo_member;	/* back-pointer for exit tracking */
};

static struct vbsd_coalition *
vbsd_jail_coalition(struct prison *pr)
{
	struct vbsd_jail_osd *vjo;

	if (vbsd_jail_osd_slot == 0)
		return (NULL);
	vjo = osd_jail_get(pr, vbsd_jail_osd_slot);
	if (vjo == NULL)
		return (NULL);
	return (vjo->vjo_coalition);
}

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


/*
 * Set the member back-pointer in the jail OSD.
 * Called after the member is fully set up, so the OSD destructor
 * can remove the member from the coalition when the prison is freed.
 *
 * Must be called with a valid prison reference held by caller.
 */
static void
vbsd_jail_set_member(struct prison *pr, struct vbsd_member *vm)
{
	struct vbsd_jail_osd *vjo;

	if (vbsd_jail_osd_slot == 0)
		return;

	/*
	 * Take prison_lock to synchronize with OSD destructor.
	 * The destructor runs under prison_lock during prison_free.
	 */
	prison_lock(pr);
	vjo = osd_jail_get(pr, vbsd_jail_osd_slot);
	if (vjo != NULL)
		vjo->vjo_member = vm;
	prison_unlock(pr);
}

/*
 * Jail OSD destructor - called when prison is being freed.
 *
 * This is called from prison_deref() which runs in process context,
 * so curthread is valid and we can safely sleep (sx_xlock, fdrop).
 */
static void
vbsd_jail_osd_dtor(void *value)
{
	struct vbsd_jail_osd *vjo = value;
	struct vbsd_coalition *vc;
	struct vbsd_member *vm;
	struct thread *td;
	int dtype;

	if (vjo == NULL)
		return;

	td = curthread;
	KASSERT(td != NULL, ("vbsd_jail_osd_dtor: NULL curthread"));
	KASSERT((td->td_pflags & TDP_ITHREAD) == 0,
	    ("vbsd_jail_osd_dtor: called from interrupt thread"));

	vc = vjo->vjo_coalition;
	vm = vjo->vjo_member;

	/*
	 * If this jail was enlisted as a member (not just for inheritance),
	 * remove it from the coalition now that the prison is being freed.
	 */
	if (vm != NULL) {
		dtype = vm->vm_dtype;

		sx_xlock(&vc->vc_sx);
		TAILQ_REMOVE(&vc->vc_members, vm, vm_link);
		sx_xunlock(&vc->vc_sx);

		atomic_subtract_int(&vc->vc_member_count, 1);
		vbsd_member_ops_release(dtype);

		/* Release file reference */
		if (vm->vm_fp != NULL)
			fdrop(vm->vm_fp, td);

		/* Free member data */
		if (vm->vm_data != NULL)
			free(vm->vm_data, M_VBSD_COALITION);

		uma_zfree(vbsd_member_zone, vm);

		/* Release member's coalition reference */
		vbsd_coalition_rel(vc);
	}

	/* Release inheritance coalition reference */
	vbsd_coalition_rel(vc);
	free(vjo, M_VBSD_COALITION);
}

/* ========================================================================
 * Generic Enlistment
 * ======================================================================== */

/*
 * Check if a file is already enlisted in this coalition.
 * Must be called with vc_sx held.
 */
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
		struct vbsd_coalition_file *nested_vcf = fp->f_data;
		struct vbsd_coalition *nested_vc = nested_vcf->vcf_coalition;

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
		/*
		 * Atomically acquire ops and increment member count.
		 * This prevents race with deregistration.
		 */
		ops = vbsd_member_ops_acquire(dtype);
		if (ops == NULL)
			return (EOPNOTSUPP);
	}

	/* Check resource limits before allocating */
	error = vbsd_check_member_limits(vc);
	if (error != 0) {
		if (!is_nested_coalition)
			vbsd_member_ops_release(dtype);
		return (error);
	}

	/*
	 * Take file reference early. This ensures the file (and for
	 * procdescs, the underlying proc) stays valid throughout.
	 */
	if (!fhold(fp)) {
		if (!is_nested_coalition)
			vbsd_member_ops_release(dtype);
		return (EBADF);
	}

	/* Allocate member */
	vm = uma_zalloc(vbsd_member_zone, M_WAITOK | M_ZERO);
	vm->vm_dtype = dtype;

	/* Type-specific setup */
	if (dtype == DTYPE_PROCDESC) {
		struct procdesc *pd = fp->f_data;
		struct vbsd_proc_data *vpd;
		struct proc *p;

		vpd = malloc(sizeof(*vpd), M_VBSD_COALITION, M_WAITOK);

		sx_slock(&proctree_lock);
		p = pd->pd_proc;
		if (p == NULL) {
			sx_sunlock(&proctree_lock);
			free(vpd, M_VBSD_COALITION);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			vbsd_member_ops_release(dtype);
			return (ESRCH);
		}
		vpd->vpd_proc = p;
		log(LOG_DEBUG, "vbsd_coalition: [%u] enlist_procdesc: pd=%p pid=%d\n",
		    VBSD_SEQ(), pd, p->p_pid);

		/*
		 * Take hash lock BEFORE releasing proctree_lock to close
		 * the race window where process could exit between getting
		 * the proc pointer and inserting into the hash table.
		 * If we released proctree_lock first, the process could exit
		 * (clearing pd->pd_proc), the exit handler wouldn't find us
		 * in hash (not inserted yet), then we'd insert a stale entry.
		 *
		 * Lock order: proctree_lock -> hash_lock -> vc_sx
		 */
		rw_wlock(&vbsd_proc_hash_lock);
		sx_sunlock(&proctree_lock);

		/* Check not already enlisted (any coalition) */
		if (vbsd_proc_hash_lookup_locked(p) != NULL) {
			rw_wunlock(&vbsd_proc_hash_lock);
			free(vpd, M_VBSD_COALITION);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			vbsd_member_ops_release(dtype);
			return (EBUSY);
		}

		vm->vm_data = vpd;

		sx_xlock(&vc->vc_sx);
		if (vc->vc_flags & VCF_TERMINATING) {
			sx_xunlock(&vc->vc_sx);
			rw_wunlock(&vbsd_proc_hash_lock);
			free(vpd, M_VBSD_COALITION);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			vbsd_member_ops_release(dtype);
			return (EINVAL);
		}

		/* Insert into hash table for exit handler */
		vbsd_proc_hash_insert_locked(vm, p);
		rw_wunlock(&vbsd_proc_hash_lock);

	} else if (dtype == DTYPE_JAILDESC) {
		struct jaildesc *jd = fp->f_data;
		struct vbsd_jail_data *vjd;
		struct prison *pr;
		int osd_error;

		vjd = malloc(sizeof(*vjd), M_VBSD_COALITION, M_WAITOK);

		JAILDESC_LOCK(jd);
		pr = jd->jd_prison;
		if (pr == NULL || !prison_isvalid(pr)) {
			JAILDESC_UNLOCK(jd);
			free(vjd, M_VBSD_COALITION);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			vbsd_member_ops_release(dtype);
			return (ENOENT);
		}
		prison_hold(pr);
		JAILDESC_UNLOCK(jd);

		vjd->vjd_prison = pr;
		vm->vm_data = vjd;

		sx_xlock(&vc->vc_sx);
		if (vc->vc_flags & VCF_TERMINATING) {
			sx_xunlock(&vc->vc_sx);
			prison_free(pr);
			free(vjd, M_VBSD_COALITION);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			vbsd_member_ops_release(dtype);
			return (EINVAL);
		}

		/*
		 * Atomically set up OSD for fork inheritance.
		 * This prevents TOCTOU race - the check and set are atomic.
		 */
		osd_error = vbsd_jail_set_coalition_atomic(pr, vc);
		if (osd_error != 0) {
			sx_xunlock(&vc->vc_sx);
			prison_free(pr);
			free(vjd, M_VBSD_COALITION);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			vbsd_member_ops_release(dtype);
			return (osd_error);  /* EBUSY if already enlisted */
		}
		vbsd_coalition_ref(vc);  /* OSD holds ref */
		/*
		 * Note: prison_free(pr) is deferred until after
		 * vbsd_jail_set_member() to prevent use-after-free.
		 */

	} else {
		/* Generic path for other types (sockets, shm, devices, coalitions, etc.) */
		sx_xlock(&vc->vc_sx);
		if (vc->vc_flags & VCF_TERMINATING) {
			sx_xunlock(&vc->vc_sx);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			if (!is_nested_coalition)
				vbsd_member_ops_release(dtype);
			return (EINVAL);
		}

		/* Check for duplicate enlistment of same fd */
		if (vbsd_coalition_has_member(vc, fp)) {
			sx_xunlock(&vc->vc_sx);
			uma_zfree(vbsd_member_zone, vm);
			fdrop(fp, td);
			if (!is_nested_coalition)
				vbsd_member_ops_release(dtype);
			return (EBUSY);
		}

		/*
		 * For nested coalitions, update the child's nesting depth.
		 */
		if (is_nested_coalition) {
			struct vbsd_coalition_file *nested_vcf = fp->f_data;
			struct vbsd_coalition *nested_vc = nested_vcf->vcf_coalition;
			nested_vc->vc_nesting_depth = vc->vc_nesting_depth + 1;
		}
	}

	/* Common member setup - we already hold fp from fhold above */
	vm->vm_fp = fp;
	vm->vm_ops = ops;
	vm->vm_coalition = vc;
	TAILQ_INSERT_TAIL(&vc->vc_members, vm, vm_link);
	log(LOG_WARNING, "vbsd_coalition: enlist: vc=%p added member dtype=%d fp=%p, count now %u\n",
	    vc, dtype, fp, vc->vc_member_count + 1);

	/*
	 * For jails, set the member back-pointer in the OSD so the
	 * destructor can remove the member when the prison is freed.
	 * Then release the prison reference we've been holding.
	 */
	if (dtype == DTYPE_JAILDESC) {
		struct vbsd_jail_data *vjd = vm->vm_data;
		vbsd_jail_set_member(vjd->vjd_prison, vm);
		prison_free(vjd->vjd_prison);
	}

	atomic_add_int(&vc->vc_member_count, 1);
	/* Note: member_count already incremented by vbsd_member_ops_acquire */

	vbsd_coalition_ref(vc);
	sx_xunlock(&vc->vc_sx);

	return (0);
}

/* ========================================================================
 * Self-Join (process joins its own coalition)
 * ======================================================================== */

static int
vbsd_coalition_join(struct vbsd_coalition *vc, struct thread *td)
{
	struct vbsd_member *vm;
	struct vbsd_proc_data *vpd;
	struct proc *p;
	int error;

	/* Check resource limits before allocating */
	error = vbsd_check_member_limits(vc);
	if (error != 0)
		return (error);

	p = td->td_proc;

	vm = uma_zalloc(vbsd_member_zone, M_WAITOK | M_ZERO);
	vpd = malloc(sizeof(*vpd), M_VBSD_COALITION, M_WAITOK);
	vpd->vpd_proc = p;

	rw_wlock(&vbsd_proc_hash_lock);

	if (vbsd_proc_hash_lookup_locked(p) != NULL) {
		rw_wunlock(&vbsd_proc_hash_lock);
		free(vpd, M_VBSD_COALITION);
		uma_zfree(vbsd_member_zone, vm);
		return (EBUSY);
	}

	sx_xlock(&vc->vc_sx);

	if (vc->vc_flags & VCF_TERMINATING) {
		sx_xunlock(&vc->vc_sx);
		rw_wunlock(&vbsd_proc_hash_lock);
		free(vpd, M_VBSD_COALITION);
		uma_zfree(vbsd_member_zone, vm);
		return (EINVAL);
	}

	vm->vm_data = vpd;
	vm->vm_fp = NULL;  /* Self-join has no external file ref */
	vm->vm_ops = &vbsd_proc_ops;
	vm->vm_coalition = vc;
	vm->vm_dtype = DTYPE_PROCDESC;  /* Logically a process member */

	vbsd_proc_hash_insert_locked(vm, p);
	TAILQ_INSERT_TAIL(&vc->vc_members, vm, vm_link);

	atomic_add_int(&vc->vc_member_count, 1);
	vbsd_member_count_inc_builtin(DTYPE_PROCDESC);

	vbsd_coalition_ref(vc);

	sx_xunlock(&vc->vc_sx);
	rw_wunlock(&vbsd_proc_hash_lock);

	return (0);
}

/* ========================================================================
 * Termination (calls mo_terminate on all members)
 * ======================================================================== */

/*
 * Terminate all members in the coalition.
 * Must be called with vc_sx held. Sets VCF_TERMINATING if not already set.
 */
static void
vbsd_coalition_terminate_members_locked(struct vbsd_coalition *vc,
    struct thread *td, bool skip_self)
{
	struct vbsd_member *vm;
	struct proc *self;
	int error;
	u_int count;

	sx_assert(&vc->vc_sx, SA_XLOCKED);

	if (vc->vc_flags & VCF_TERMINATING) {
		log(LOG_WARNING, "vbsd_coalition: terminate: already terminating (skipping)\n");
		return;
	}

	vc->vc_flags |= VCF_TERMINATING;
	count = vc->vc_member_count;
	log(LOG_WARNING, "vbsd_coalition: terminate: starting, %u members\n", count);

	/* Close path may need to avoid killing the closing process itself. */
	self = (skip_self && td != NULL) ? td->td_proc : NULL;

	/* Terminate all members via their ops */
	TAILQ_FOREACH(vm, &vc->vc_members, vm_link) {
		if (vm->vm_ops == NULL) {
			log(LOG_WARNING,
			    "vbsd_coalition: terminate: NULL vm_ops, skipping\n");
			continue;
		}

		/*
		 * Skip jail members - they must be terminated OUTSIDE the
		 * lock to avoid deadlock. prison_remove() can trigger the
		 * OSD destructor which tries to take vc_sx.
		 * Caller (fo_close) handles jail termination after unlocking.
		 */
		if (vm->vm_ops == &vbsd_jail_ops) {
			log(LOG_DEBUG, "vbsd_coalition: terminate: deferring jail termination\n");
			continue;
		}

		log(LOG_WARNING, "vbsd_coalition: terminate: member dtype=%d fp=%p ops=%s\n",
		    vm->vm_dtype, vm->vm_fp, vm->vm_ops->mo_name);

		if (vm->vm_fp != NULL && vm->vm_ops->mo_terminate != NULL) {
			log(LOG_WARNING, "vbsd_coalition: terminate: calling mo_terminate for %s\n",
			    vm->vm_ops->mo_name);
			error = vm->vm_ops->mo_terminate(vm->vm_fp, td);
			log(LOG_WARNING, "vbsd_coalition: terminate: mo_terminate returned %d\n",
			    error);
		} else if (vm->vm_data != NULL && vm->vm_ops == &vbsd_proc_ops) {
			/*
			 * Self-joined process - signal directly.
			 *
			 * Use atomic load with acquire semantics to read
			 * vpd_proc. The exit handler uses atomic store with
			 * release semantics to NULL it when the process exits.
			 * This avoids taking the hash lock here (which would
			 * violate lock ordering: we hold vc_sx, but fork
			 * handler takes hash lock before vc_sx).
			 *
			 * If we read non-NULL, the process is still alive and
			 * we take PROC_LOCK before signaling. Once we have
			 * PROC_LOCK, the process can't exit until we release.
			 */
			struct vbsd_proc_data *vpd = vm->vm_data;
			struct proc *p;

			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&vpd->vpd_proc);
			if (skip_self && self != NULL && p == self) {
				error = 0;
				continue;
			}
			if (p != NULL) {
				PROC_LOCK(p);
				kern_psignal(p, SIGKILL);
				PROC_UNLOCK(p);
			}
			/* Process already dead or now signaled - success */
			error = 0;
		} else {
			error = EINVAL;
		}

		if (error != 0) {
			log(LOG_WARNING,
			    "vbsd_coalition: %s terminate failed: %d\n",
			    vm->vm_ops->mo_name, error);
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
		log(LOG_DEBUG, "vbsd_coalition: terminate: terminating jail %d/%d\n",
		    i + 1, jail_count);
		(void)vbsd_jail_terminate(jail_fps[i], td);
		fdrop(jail_fps[i], td);
	}

	if (jail_fps != NULL)
		free(jail_fps, M_VBSD_COALITION);

	return (0);
}

/*
 * Signal all process members with a specific signal.
 * Used for graceful termination to send SIGTERM before SIGKILL.
 * Must be called with vc_sx held.
 */
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
			/*
			 * Self-joined process - use atomic read of vpd_proc.
			 * Exit handler atomically NULLs it when process exits.
			 */
			struct vbsd_proc_data *vpd = vm->vm_data;
			struct proc *p;

			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&vpd->vpd_proc);
			if (p != NULL) {
				PROC_LOCK(p);
				kern_psignal(p, sig);
				PROC_UNLOCK(p);
			}
		}
	}
}

/*
 * Count remaining live process members.
 * Must be called with vc_sx held.
 */
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
			/*
			 * Self-joined process - use atomic read of vpd_proc.
			 * Exit handler atomically NULLs it when process exits.
			 */
			struct vbsd_proc_data *vpd = vm->vm_data;
			struct proc *p;

			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&vpd->vpd_proc);
			if (p != NULL && (p->p_flag & P_WEXIT) == 0)
				count++;
		}
	}

	return (count);
}

/*
 * Graceful termination: send signal, wait for grace period, then SIGKILL.
 *
 * This is still a guaranteed kill switch - processes that don't exit
 * voluntarily during the grace period are forcefully terminated.
 */
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

	/* Phase 2: Wait for processes to exit, checking periodically */
	elapsed = 0;
	while (elapsed < timeout_ms) {
		remaining = vbsd_coalition_count_live_processes_locked(vc);
		if (remaining == 0)
			break;

		/* Release lock while sleeping to allow exit handlers to run */
		sx_xunlock(&vc->vc_sx);

		/* Sleep 100ms or remaining time, whichever is smaller */
		u_int sleep_ms = (timeout_ms - elapsed);
		if (sleep_ms > 100)
			sleep_ms = 100;

		error = pause_sbt("coalition_grace", SBT_1MS * sleep_ms,
		    0, C_HARDCLOCK);
		(void)error;  /* Ignore interrupts, continue waiting */

		elapsed += sleep_ms;
		sx_xlock(&vc->vc_sx);

		/* Check if someone else terminated while we slept */
		if (vc->vc_flags & VCF_TERMINATING) {
			sx_xunlock(&vc->vc_sx);
			return (0);  /* Already terminated */
		}
	}

	/* Phase 3: Force-kill any remaining members */
	vbsd_coalition_terminate_members_locked(vc, curthread, false);

	sx_xunlock(&vc->vc_sx);

	return (0);
}

/* ========================================================================
 * Process Exit Handler
 * ======================================================================== */

static void
vbsd_process_exit(void *arg __unused, struct proc *p)
{
	struct vbsd_member *vm;
	struct vbsd_coalition *vc;
	struct vbsd_proc_data *vpd;

	rw_wlock(&vbsd_proc_hash_lock);
	vm = vbsd_proc_hash_lookup_locked(p);
	if (vm == NULL) {
		rw_wunlock(&vbsd_proc_hash_lock);
		return;
	}

	log(LOG_DEBUG, "vbsd_coalition: [%u] process_exit: pid=%d fp=%p\n",
	    VBSD_SEQ(), p->p_pid, vm->vm_fp);
	SDT_PROBE1(coalition, , , member__exit, p->p_pid);

	vc = vm->vm_coalition;
	vbsd_coalition_ref(vc);  /* temp ref for safe access after unlock */

	/*
	 * Remove from hash so this process won't be found again.
	 * Mark le_prev as NULL so fo_close knows not to LIST_REMOVE again.
	 */
	LIST_REMOVE(vm, vm_hash);
	vm->vm_hash.le_prev = NULL;

	/*
	 * For self-joined processes (no file descriptor), NULL out the
	 * cached proc pointer to prevent use-after-free. The proc struct
	 * will be freed after we return, so terminate must not use it.
	 * For enlisted processes, we use pd->pd_proc which is properly
	 * NULLed by procdesc_exit().
	 *
	 * Use atomic store with release semantics to ensure the NULL is
	 * visible to terminate which reads with acquire semantics. This
	 * avoids needing to hold vc_sx in the exit handler (which would
	 * risk deadlock with terminate_members_locked).
	 */
	if (vm->vm_fp == NULL && vm->vm_data != NULL) {
		vpd = vm->vm_data;
		atomic_store_rel_ptr((uintptr_t *)&vpd->vpd_proc, (uintptr_t)NULL);
	}

	rw_wunlock(&vbsd_proc_hash_lock);

	/*
	 * Do NOT remove from TAILQ, do NOT free the member, do NOT fdrop.
	 * Leave vm in the coalition's member list for fo_close to clean up.
	 *
	 * This avoids races between exit handler and fo_close:
	 * - If we tried to TAILQ_REMOVE here, fo_close might have already
	 *   done so (double-remove corrupts list)
	 * - If we freed vm here, fo_close would access freed memory
	 * - If we fdrop here, we're in exit1() context which can interfere
	 *   with procdesc_close and zombie reaping
	 *
	 * The vm is now "orphaned" (process dead, but member still in list).
	 * When coalition fd is closed, fo_close will:
	 * - Remove vm from TAILQ
	 * - Release procdesc reference (fdrop) in safe context
	 * - Free vm
	 * - Release member's coalition reference
	 *
	 * The member's coalition reference keeps coalition alive until
	 * fo_close runs.
	 */

	/* Release only our temp reference */
	vbsd_coalition_rel(vc);
}

/* ========================================================================
 * Process Fork Handler (for inheritance)
 * ======================================================================== */

static void
vbsd_process_fork(void *arg __unused, struct proc *parent, struct proc *child,
    int flags __unused)
{
	struct vbsd_member *pvm, *cvm;
	struct vbsd_proc_data *vpd;
	struct vbsd_coalition *vc;

	/* Check if parent is in a coalition */
	rw_rlock(&vbsd_proc_hash_lock);
	pvm = vbsd_proc_hash_lookup_locked(parent);
	if (pvm != NULL) {
		vc = pvm->vm_coalition;
		vbsd_coalition_ref(vc);
		rw_runlock(&vbsd_proc_hash_lock);
	} else {
		struct prison *pr;
		struct ucred *cred;

		rw_runlock(&vbsd_proc_hash_lock);

		/* Check if child's jail is enlisted */
		cred = child->p_ucred;
		if (cred == NULL)
			return;
		pr = cred->cr_prison;
		if (pr == NULL)
			return;
		prison_hold(pr);
		vc = vbsd_jail_coalition(pr);
		if (vc == NULL) {
			prison_free(pr);
			return;
		}
		vbsd_coalition_ref(vc);
		prison_free(pr);
	}

	/*
	 * Check resource limits but don't fail - fork inheritance is
	 * security-critical.  Log warning if over limit but proceed.
	 */
	if (vbsd_check_member_limits(vc) != 0) {
		log(LOG_WARNING,
		    "vbsd_coalition: fork inheritance exceeds resource limits\n");
	}

	/*
	 * Use M_WAITOK to ensure child always inherits coalition membership.
	 * Allocation failure would allow child to escape supervision - this
	 * is a security violation.  M_WAITOK is safe here as we're in
	 * process context (fork handler).
	 */
	cvm = uma_zalloc(vbsd_member_zone, M_WAITOK | M_ZERO);
	vpd = malloc(sizeof(*vpd), M_VBSD_COALITION, M_WAITOK);

	vpd->vpd_proc = child;

	rw_wlock(&vbsd_proc_hash_lock);
	sx_xlock(&vc->vc_sx);

	if (vc->vc_flags & VCF_TERMINATING) {
		sx_xunlock(&vc->vc_sx);
		rw_wunlock(&vbsd_proc_hash_lock);
		free(vpd, M_VBSD_COALITION);
		uma_zfree(vbsd_member_zone, cvm);
		vbsd_coalition_rel(vc);
		return;
	}

	cvm->vm_data = vpd;
	cvm->vm_fp = NULL;
	cvm->vm_ops = &vbsd_proc_ops;
	cvm->vm_coalition = vc;
	cvm->vm_dtype = DTYPE_PROCDESC;

	vbsd_proc_hash_insert_locked(cvm, child);
	TAILQ_INSERT_TAIL(&vc->vc_members, cvm, vm_link);

	atomic_add_int(&vc->vc_member_count, 1);
	vbsd_member_count_inc_builtin(DTYPE_PROCDESC);

	vbsd_coalition_ref(vc);

	sx_xunlock(&vc->vc_sx);
	rw_wunlock(&vbsd_proc_hash_lock);

	SDT_PROBE2(coalition, , , fork__inherit, parent->p_pid, child->p_pid);

	vbsd_coalition_rel(vc);
}

/* ========================================================================
 * File Operations
 * ======================================================================== */

static int
vbsd_coalition_fo_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred __unused, struct thread *td)
{
	struct vbsd_coalition_file *vcf;
	struct vbsd_coalition *vc;
	struct file *target_fp;
	int error, target_fd;

	vcf = fp->f_data;
	vc = vcf->vcf_coalition;

	switch (cmd) {
	case VBSD_COALITION_ENLIST:
		target_fd = *(int *)data;
		AUDIT_ARG_FD(target_fd);
		error = fget(td, target_fd, &cap_no_rights, &target_fp);
		if (error != 0) {
			SDT_PROBE3(coalition, , , enlist, target_fd, -1, error);
			log(LOG_DEBUG, "vbsd_coalition: enlist fd %d fget failed: %d\n",
			    target_fd, error);
			return (error);
		}
		error = vbsd_coalition_enlist_generic(vc, td, target_fp);
		SDT_PROBE3(coalition, , , enlist, target_fd,
		    target_fp->f_type, error);
		if (error != 0) {
			log(LOG_DEBUG, "vbsd_coalition: enlist fd %d (dtype %d) failed: %d\n",
			    target_fd, target_fp->f_type, error);
		} else {
			log(LOG_DEBUG, "vbsd_coalition: enlist fd %d (dtype %d) succeeded\n",
			    target_fd, target_fp->f_type);
		}
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
		SDT_PROBE2(coalition, , , join, td->td_proc->p_pid, error);
		break;

	case VBSD_COALITION_TERMINATE:
		{
			u_int member_count;
			member_count = atomic_load_acq_int(&vc->vc_member_count);
			AUDIT_ARG_VALUE(member_count);
			error = vbsd_coalition_terminate(vc);
			SDT_PROBE2(coalition, , , terminate, member_count, error);
			(void)member_count;  /* suppress warning when probes disabled */
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
				SDT_PROBE3(coalition, , , enlist__set, 0, 0, 0);
				break;
			}
			if (es->count > vbsd_enlist_set_max) {
				SDT_PROBE3(coalition, , , enlist__set,
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
				SDT_PROBE3(coalition, , , enlist__set,
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

			SDT_PROBE3(coalition, , , enlist__set,
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
			u_int member_count;

			member_count = atomic_load_acq_int(&vc->vc_member_count);
			AUDIT_ARG_VALUE(member_count);
			error = vbsd_coalition_terminate_graceful(vc, g->vg_signal,
			    g->vg_timeout_ms);
			(void)member_count;
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
	struct vbsd_coalition_file *vcf;
	struct vbsd_coalition *vc;
	struct vbsd_member *vm, *vm_temp;
	u_int member_count;

	vcf = fp->f_data;
	if (vcf == NULL) {
		log(LOG_WARNING, "vbsd_coalition: fo_close: NULL vcf\n");
		return (0);
	}
	vc = vcf->vcf_coalition;
	if (vc == NULL) {
		log(LOG_WARNING, "vbsd_coalition: fo_close: NULL vc\n");
		return (0);
	}

	member_count = atomic_load_acq_int(&vc->vc_member_count);
	log(LOG_DEBUG, "vbsd_coalition: [%u] fo_close: member_count=%u\n",
	    VBSD_SEQ(), member_count);
	SDT_PROBE1(coalition, , , close, member_count);

	sx_xlock(&vc->vc_sx);

	/* Terminate all members if not already done */
	log(LOG_WARNING, "vbsd_coalition: fo_close: vc=%p flags=0x%x member_count=%u\n",
	    vc, vc->vc_flags, vc->vc_member_count);
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
			/* Collect jails separately for deferred termination */
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

	sx_xunlock(&vc->vc_sx);

	/*
	 * Now clean up collected members without holding vc_sx.
	 * This allows procdesc_close to acquire proctree_lock without
	 * risking deadlock with dying processes.
	 */
	for (vm = cleanup_list; vm != NULL; ) {
		struct vbsd_member *next = (struct vbsd_member *)vm->vm_link.tqe_next;

		atomic_subtract_int(&vc->vc_member_count, 1);
		vbsd_member_ops_release(vm->vm_dtype);

		/* Release file reference */
		if (vm->vm_fp != NULL)
			fdrop(vm->vm_fp, td);

		/* Free type-specific data */
		if (vm->vm_data != NULL)
			free(vm->vm_data, M_VBSD_COALITION);

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
		struct vbsd_jail_data *vjd;
		struct jaildesc *jd;
		struct prison *pr;
		struct vbsd_jail_osd *vjo;

		vjd = vm->vm_data;

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
		    vm->vm_ops->mo_terminate != NULL) {
			log(LOG_DEBUG, "vbsd_coalition: fo_close: terminating jail\n");
			(void)vm->vm_ops->mo_terminate(vm->vm_fp, td);
		}

		if (vjd != NULL)
			vjd->vjd_prison = NULL;

		atomic_subtract_int(&vc->vc_member_count, 1);
		vbsd_member_ops_release(vm->vm_dtype);

		/* Release file reference */
		if (vm->vm_fp != NULL)
			fdrop(vm->vm_fp, td);

		/* Free type-specific data */
		if (vm->vm_data != NULL)
			free(vm->vm_data, M_VBSD_COALITION);

		uma_zfree(vbsd_member_zone, vm);
		vbsd_coalition_rel(vc);

		vm = next;
	}

	vbsd_coalition_rel(vc);
	uma_zfree(vbsd_coalition_file_zone, vcf);
	return (0);
}

/* ========================================================================
 * Device and Module Init
 * ======================================================================== */

static struct cdev *vbsd_coalition_dev;

static int
vbsd_coalition_dev_fdopen(struct cdev *dev __unused, int oflags __unused,
    struct thread *td, struct file *fp)
{
	int error;

	error = vbsd_coalition_init_file(fp);
	if (error == 0)
		vbsd_coalition_mark_clofork(td, fp);
	return (error);
}

static struct cdevsw vbsd_coalition_cdevsw = {
	.d_version = D_VERSION,
	.d_fdopen = vbsd_coalition_dev_fdopen,
	.d_name = "coalition",
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
	return (0);
}

static void
vbsd_eventhandler_fini(void)
{
	EVENTHANDLER_DEREGISTER(process_fork, vbsd_fork_tag);
	EVENTHANDLER_DEREGISTER(process_exit, vbsd_exit_tag);
}

static int
vbsd_register_builtins(void)
{
	int error;

	mtx_init(&vbsd_ops_lock, "vbsd_ops", NULL, MTX_DEF);

	/* Register process and jail ops (custom terminate behavior) */
	error = vbsd_member_ops_register(DTYPE_PROCDESC, &vbsd_proc_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_JAILDESC, &vbsd_jail_ops);
	if (error != 0)
		goto fail;

	/* Register built-in generic types (just close on terminate) */
	error = vbsd_member_ops_register(DTYPE_VNODE, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_SOCKET, &vbsd_socket_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_PIPE, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_FIFO, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_SHM, &vbsd_shm_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_SEM, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_KQUEUE, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_EVENTFD, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_TIMERFD, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_INOTIFY, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	error = vbsd_member_ops_register(DTYPE_DEV, &vbsd_default_ops);
	if (error != 0)
		goto fail;

	return (0);

fail:
	/* Clean up any registered ops on failure */
	vbsd_member_ops_deregister(DTYPE_PROCDESC);
	vbsd_member_ops_deregister(DTYPE_JAILDESC);
	vbsd_member_ops_deregister(DTYPE_VNODE);
	vbsd_member_ops_deregister(DTYPE_SOCKET);
	vbsd_member_ops_deregister(DTYPE_PIPE);
	vbsd_member_ops_deregister(DTYPE_FIFO);
	vbsd_member_ops_deregister(DTYPE_SHM);
	vbsd_member_ops_deregister(DTYPE_SEM);
	vbsd_member_ops_deregister(DTYPE_KQUEUE);
	vbsd_member_ops_deregister(DTYPE_EVENTFD);
	vbsd_member_ops_deregister(DTYPE_TIMERFD);
	vbsd_member_ops_deregister(DTYPE_INOTIFY);
	vbsd_member_ops_deregister(DTYPE_DEV);
	mtx_destroy(&vbsd_ops_lock);
	return (error);
}

static void
vbsd_deregister_builtins(void)
{
	vbsd_member_ops_deregister(DTYPE_PROCDESC);
	vbsd_member_ops_deregister(DTYPE_JAILDESC);
	vbsd_member_ops_deregister(DTYPE_VNODE);
	vbsd_member_ops_deregister(DTYPE_SOCKET);
	vbsd_member_ops_deregister(DTYPE_PIPE);
	vbsd_member_ops_deregister(DTYPE_FIFO);
	vbsd_member_ops_deregister(DTYPE_SHM);
	vbsd_member_ops_deregister(DTYPE_SEM);
	vbsd_member_ops_deregister(DTYPE_KQUEUE);
	vbsd_member_ops_deregister(DTYPE_EVENTFD);
	vbsd_member_ops_deregister(DTYPE_TIMERFD);
	vbsd_member_ops_deregister(DTYPE_INOTIFY);
	vbsd_member_ops_deregister(DTYPE_DEV);
	mtx_destroy(&vbsd_ops_lock);
}

static int
vbsd_coalition_mod_init(void)
{
	int error;

	vbsd_coalition_zone = uma_zcreate("vbsd_coalition",
	    sizeof(struct vbsd_coalition), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	vbsd_coalition_file_zone = uma_zcreate("vbsd_coalition_file",
	    sizeof(struct vbsd_coalition_file), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	vbsd_member_zone = uma_zcreate("vbsd_member",
	    sizeof(struct vbsd_member), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	error = vbsd_register_builtins();
	if (error != 0)
		goto fail_ops;

	error = vbsd_proc_hash_init();
	if (error != 0)
		goto fail_hash;

	error = vbsd_jail_osd_init();
	if (error != 0)
		goto fail_osd;

	error = vbsd_eventhandler_init();
	if (error != 0)
		goto fail_event;

	vbsd_coalition_dev = make_dev(&vbsd_coalition_cdevsw, 0,
	    UID_ROOT, GID_WHEEL, 0600, "coalition");
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
	vbsd_proc_hash_fini();
fail_hash:
	vbsd_deregister_builtins();
fail_ops:
	uma_zdestroy(vbsd_member_zone);
	uma_zdestroy(vbsd_coalition_file_zone);
	uma_zdestroy(vbsd_coalition_zone);
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
		vbsd_proc_hash_fini();
		vbsd_deregister_builtins();

		uma_zdestroy(vbsd_member_zone);
		uma_zdestroy(vbsd_coalition_file_zone);
		uma_zdestroy(vbsd_coalition_zone);
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
