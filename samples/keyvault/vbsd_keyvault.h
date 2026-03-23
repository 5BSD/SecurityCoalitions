/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * vBSD KeyVault - Sample descriptor type with coalition integration
 *
 * This is a SAMPLE MODULE demonstrating how to integrate a custom
 * descriptor type with the vBSD Coalition system.
 *
 * KeyVault provides:
 *   - Secure key storage with kernel-managed lifecycle
 *   - Interior revocation via coalition termination
 *   - Capability-based access control
 */

#ifndef _SYS_VBSD_KEYVAULT_H_
#define _SYS_VBSD_KEYVAULT_H_

#include <sys/types.h>
#include <sys/ioccom.h>

/*
 * KeyVault ioctl commands
 */
#define KEYVAULT_IOC_STORE	_IOW('K', 1, struct keyvault_key)
#define KEYVAULT_IOC_LOAD	_IOWR('K', 2, struct keyvault_key)
#define KEYVAULT_IOC_DELETE	_IOW('K', 3, uint32_t)
#define KEYVAULT_IOC_REVOKE	_IO('K', 4)

/*
 * Key slot identifiers
 */
#define KEYVAULT_MAX_SLOTS	16
#define KEYVAULT_MAX_KEYLEN	256

/*
 * Key data structure for ioctl
 */
struct keyvault_key {
	uint32_t	kk_slot;		/* Key slot (0-15) */
	uint32_t	kk_len;			/* Key length in bytes */
	uint8_t		kk_data[KEYVAULT_MAX_KEYLEN];	/* Key material */
};

#ifdef _KERNEL

#include <sys/lock.h>
#include <sys/mutex.h>

/*
 * DTYPE is assigned dynamically by vbsd_coalition at registration.
 * No need for a static define - coalition manages dtype allocation.
 */

/*
 * Key slot
 */
struct keyvault_slot {
	bool		ks_valid;
	uint32_t	ks_len;
	uint8_t		ks_data[KEYVAULT_MAX_KEYLEN];
};

/*
 * KeyVault instance
 */
struct keyvault {
	struct mtx		kv_lock;
	bool			kv_revoked;	/* Set by coalition terminate */
	struct keyvault_slot	kv_slots[KEYVAULT_MAX_SLOTS];
};

#define KEYVAULT_LOCK(kv)	mtx_lock(&(kv)->kv_lock)
#define KEYVAULT_UNLOCK(kv)	mtx_unlock(&(kv)->kv_lock)

#endif /* _KERNEL */

#endif /* _SYS_VBSD_KEYVAULT_H_ */
