/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * vBSD KeyVault - Sample descriptor type with coalition integration
 *
 * This module demonstrates:
 *   1. Creating a custom file descriptor type
 *   2. Optional coalition integration (works with or without coalition)
 *   3. Interior revocation on coalition termination
 *   4. Proper cleanup and error handling
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/syslog.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include <vm/uma.h>

/*
 * Coalition integration (optional).
 * During development, use local header via Makefile -I path.
 * On installed systems, this would be <sys/vbsd_coalition.h>.
 * Note: <sys/module.h> already included above.
 */
#include <vbsd_coalition.h>

#include "vbsd_keyvault.h"

MALLOC_DEFINE(M_KEYVAULT, "keyvault", "KeyVault structures");

static uma_zone_t keyvault_zone;
static struct cdev *keyvault_dev;

/* Forward declarations */
static fo_close_t	keyvault_fo_close;
static fo_ioctl_t	keyvault_fo_ioctl;
static fo_stat_t	keyvault_fo_stat;

static struct fileops keyvault_fileops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = keyvault_fo_ioctl,
	.fo_poll = invfo_poll,
	.fo_kqfilter = invfo_kqfilter,
	.fo_stat = keyvault_fo_stat,
	.fo_close = keyvault_fo_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_flags = DFLAG_PASSABLE,
};

/* ========================================================================
 * Coalition Integration
 * ======================================================================== */

/*
 * Coalition terminate callback - securely zeros all keys when
 * the coalition containing this keyvault is terminated.
 */
static int
keyvault_coalition_terminate(struct file *fp, struct thread *td __unused)
{
	struct keyvault *kv;
	int i;

	if (fp == NULL || fp->f_data == NULL)
		return (EINVAL);

	kv = fp->f_data;

	KEYVAULT_LOCK(kv);
	kv->kv_revoked = true;
	for (i = 0; i < KEYVAULT_MAX_SLOTS; i++) {
		if (kv->kv_slots[i].ks_valid) {
			explicit_bzero(kv->kv_slots[i].ks_data,
			    kv->kv_slots[i].ks_len);
			kv->kv_slots[i].ks_valid = false;
			kv->kv_slots[i].ks_len = 0;
		}
	}
	wakeup(kv);
	KEYVAULT_UNLOCK(kv);

	return (0);
}

static struct vbsd_member_ops keyvault_coalition_ops = {
	.mo_terminate = keyvault_coalition_terminate,
	.mo_name = "keyvault",
};

/* ========================================================================
 * KeyVault Operations
 * ======================================================================== */

static struct keyvault *
keyvault_alloc(void)
{
	struct keyvault *kv;

	kv = uma_zalloc(keyvault_zone, M_WAITOK | M_ZERO);
	mtx_init(&kv->kv_lock, "keyvault", NULL, MTX_DEF);
	kv->kv_revoked = false;

	return (kv);
}

static void
keyvault_free(struct keyvault *kv)
{
	int i;

	/* Securely zero all keys before freeing */
	for (i = 0; i < KEYVAULT_MAX_SLOTS; i++) {
		if (kv->kv_slots[i].ks_valid) {
			explicit_bzero(kv->kv_slots[i].ks_data,
			    kv->kv_slots[i].ks_len);
		}
	}

	mtx_destroy(&kv->kv_lock);
	uma_zfree(keyvault_zone, kv);
}

static int
keyvault_store(struct keyvault *kv, struct keyvault_key *key)
{

	if (key->kk_slot >= KEYVAULT_MAX_SLOTS)
		return (EINVAL);
	if (key->kk_len > KEYVAULT_MAX_KEYLEN)
		return (EINVAL);

	KEYVAULT_LOCK(kv);

	if (kv->kv_revoked) {
		KEYVAULT_UNLOCK(kv);
		return (EBADF);
	}

	/* Zero old key if present */
	if (kv->kv_slots[key->kk_slot].ks_valid) {
		explicit_bzero(kv->kv_slots[key->kk_slot].ks_data,
		    kv->kv_slots[key->kk_slot].ks_len);
	}

	/* Store new key */
	bcopy(key->kk_data, kv->kv_slots[key->kk_slot].ks_data, key->kk_len);
	kv->kv_slots[key->kk_slot].ks_len = key->kk_len;
	kv->kv_slots[key->kk_slot].ks_valid = true;

	KEYVAULT_UNLOCK(kv);

	return (0);
}

static int
keyvault_load(struct keyvault *kv, struct keyvault_key *key)
{

	if (key->kk_slot >= KEYVAULT_MAX_SLOTS)
		return (EINVAL);

	KEYVAULT_LOCK(kv);

	if (kv->kv_revoked) {
		KEYVAULT_UNLOCK(kv);
		return (EBADF);
	}

	if (!kv->kv_slots[key->kk_slot].ks_valid) {
		KEYVAULT_UNLOCK(kv);
		return (ENOENT);
	}

	key->kk_len = kv->kv_slots[key->kk_slot].ks_len;
	bcopy(kv->kv_slots[key->kk_slot].ks_data, key->kk_data, key->kk_len);

	KEYVAULT_UNLOCK(kv);

	return (0);
}

static int
keyvault_delete(struct keyvault *kv, uint32_t slot)
{

	if (slot >= KEYVAULT_MAX_SLOTS)
		return (EINVAL);

	KEYVAULT_LOCK(kv);

	if (kv->kv_revoked) {
		KEYVAULT_UNLOCK(kv);
		return (EBADF);
	}

	if (kv->kv_slots[slot].ks_valid) {
		explicit_bzero(kv->kv_slots[slot].ks_data,
		    kv->kv_slots[slot].ks_len);
		kv->kv_slots[slot].ks_len = 0;
		kv->kv_slots[slot].ks_valid = false;
	}

	KEYVAULT_UNLOCK(kv);

	return (0);
}

static int
keyvault_revoke(struct keyvault *kv)
{
	int i;

	KEYVAULT_LOCK(kv);

	kv->kv_revoked = true;

	for (i = 0; i < KEYVAULT_MAX_SLOTS; i++) {
		if (kv->kv_slots[i].ks_valid) {
			explicit_bzero(kv->kv_slots[i].ks_data,
			    kv->kv_slots[i].ks_len);
			kv->kv_slots[i].ks_valid = false;
			kv->kv_slots[i].ks_len = 0;
		}
	}

	wakeup(kv);

	KEYVAULT_UNLOCK(kv);

	return (0);
}

/* ========================================================================
 * File Operations
 * ======================================================================== */

static int
keyvault_fo_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred __unused, struct thread *td __unused)
{
	struct keyvault *kv;

	kv = fp->f_data;

	switch (cmd) {
	case KEYVAULT_IOC_STORE:
		return (keyvault_store(kv, (struct keyvault_key *)data));

	case KEYVAULT_IOC_LOAD:
		return (keyvault_load(kv, (struct keyvault_key *)data));

	case KEYVAULT_IOC_DELETE:
		return (keyvault_delete(kv, *(uint32_t *)data));

	case KEYVAULT_IOC_REVOKE:
		return (keyvault_revoke(kv));

	default:
		return (ENOTTY);
	}
}

static int
keyvault_fo_stat(struct file *fp __unused, struct stat *sb,
    struct ucred *active_cred __unused)
{

	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFCHR | 0600;
	return (0);
}

static int
keyvault_fo_close(struct file *fp, struct thread *td __unused)
{
	struct keyvault *kv;

	kv = fp->f_data;
	keyvault_free(kv);
	return (0);
}

/* ========================================================================
 * Device Operations
 * ======================================================================== */

/* Assigned by coalition module at registration */
static int keyvault_dtype = DTYPE_NONE;

static int
keyvault_fdopen(struct cdev *dev __unused, int oflags __unused,
    struct thread *td __unused, struct file *fp)
{
	struct keyvault *kv;

	kv = keyvault_alloc();
	finit(fp, FREAD | FWRITE, keyvault_dtype, kv, &keyvault_fileops);

	return (0);
}

static struct cdevsw keyvault_cdevsw = {
	.d_version = D_VERSION,
	.d_fdopen = keyvault_fdopen,
	.d_name = "keyvault",
};

/* ========================================================================
 * Module Init/Fini
 * ======================================================================== */

static int
keyvault_modevent(module_t mod __unused, int type, void *arg __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		keyvault_zone = uma_zcreate("keyvault",
		    sizeof(struct keyvault), NULL, NULL, NULL, NULL,
		    UMA_ALIGN_PTR, 0);

		/* Register with coalition - get assigned dtype */
		if (vbsd_coalition_available()) {
			error = vbsd_member_ops_register(&keyvault_coalition_ops,
			    &keyvault_dtype);
			if (error != 0) {
				log(LOG_WARNING,
				    "keyvault: coalition register failed: %d\n",
				    error);
				uma_zdestroy(keyvault_zone);
				return (error);
			}
		}

		keyvault_dev = make_dev(&keyvault_cdevsw, 0,
		    UID_ROOT, GID_WHEEL, 0600, "keyvault");
		if (keyvault_dev == NULL) {
			vbsd_member_ops_deregister(keyvault_dtype);
			uma_zdestroy(keyvault_zone);
			return (ENXIO);
		}

		log(LOG_INFO, "keyvault: loaded (dtype %d)\n", keyvault_dtype);
		return (0);

	case MOD_UNLOAD:
		destroy_dev(keyvault_dev);
		vbsd_member_ops_deregister(keyvault_dtype);
		uma_zdestroy(keyvault_zone);
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t keyvault_mod = {
	"vbsd_keyvault",
	keyvault_modevent,
	NULL
};

DECLARE_MODULE(vbsd_keyvault, keyvault_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(vbsd_keyvault, 1);

/*
 * Optional dependency on vbsd_coalition.
 * If coalition is loaded, we integrate. If not, we still work.
 */
/* MODULE_DEPEND(vbsd_keyvault, vbsd_coalition, 1, 1, 1); */
