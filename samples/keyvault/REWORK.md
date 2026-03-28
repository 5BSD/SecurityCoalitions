# KeyVault Rework: Standard Device Model Migration

This document describes the changes needed to migrate KeyVault from the current
`finit()`/custom-dtype model to the standard FreeBSD device model using
`devfs_set_cdevpriv()`.

## Current Implementation

KeyVault currently integrates with coalitions using:

```c
/* At module load - get dtype from coalition */
static int keyvault_dtype = DTYPE_NONE;
vbsd_member_ops_register(&keyvault_coalition_ops, &keyvault_dtype);

/* In d_fdopen - use custom dtype */
finit(fp, FREAD | FWRITE, keyvault_dtype, kv, &keyvault_fileops);
```

**Problems:**
- Creates `DTYPE_DEV` file descriptors that bypass vnode layer
- No MACF label on the fd → CACL cannot protect keyvault fds
- Requires coalition to assign and track custom dtypes
- Custom fileops management

## Target Implementation

Use standard FreeBSD device model:

```c
/* At module load - register termination handler with coalition */
keyvault_cdev = make_dev(&keyvault_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "keyvault");
vbsd_terminate_ops_register(keyvault_cdev, &keyvault_terminate_ops);

/* In d_open - use devfs private data */
static int
keyvault_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
    struct keyvault *kv = keyvault_alloc();
    devfs_set_cdevpriv(kv, keyvault_dtor);
    return (0);
}
```

**Benefits:**
- Returns `DTYPE_VNODE` fd with full MACF label support
- CACL automatically protects keyvault fds
- Standard FreeBSD device semantics
- Coalition looks up termination handler by cdev, not dtype

## Code Changes Required

### 1. Remove Custom Fileops

**Delete** the `keyvault_fileops` structure and related functions:
- `keyvault_fo_close()` → becomes `keyvault_dtor()`
- `keyvault_fo_ioctl()` → becomes `keyvault_d_ioctl()`
- `keyvault_fo_stat()` → handled by devfs

### 2. Update cdevsw

**Before:**
```c
static struct cdevsw keyvault_cdevsw = {
    .d_version = D_VERSION,
    .d_fdopen = keyvault_fdopen,
    .d_name = "keyvault",
};
```

**After:**
```c
static struct cdevsw keyvault_cdevsw = {
    .d_version = D_VERSION,
    .d_open = keyvault_open,
    .d_close = keyvault_close,
    .d_ioctl = keyvault_ioctl,
    .d_name = "keyvault",
};
```

### 3. Replace finit() with devfs_set_cdevpriv()

**Before (d_fdopen):**
```c
static int
keyvault_fdopen(struct cdev *dev, int oflags, struct thread *td, struct file *fp)
{
    struct keyvault *kv = keyvault_alloc();
    kv->kv_fp = fp;
    finit(fp, FREAD | FWRITE, keyvault_dtype, kv, &keyvault_fileops);
    return (0);
}
```

**After (d_open):**
```c
static int
keyvault_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
    struct keyvault *kv = keyvault_alloc();
    kv->kv_cdev = dev;  /* Store for VBSD_LEADER_DIED */
    devfs_set_cdevpriv(kv, keyvault_dtor);
    return (0);
}

static void
keyvault_dtor(void *arg)
{
    struct keyvault *kv = arg;
    keyvault_free(kv);
}
```

### 4. Update ioctl Handler

**Before (fo_ioctl):**
```c
static int
keyvault_fo_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
    struct keyvault *kv = fp->f_data;
    ...
}
```

**After (d_ioctl):**
```c
static int
keyvault_ioctl(struct cdev *dev, u_long cmd, caddr_t data,
    int fflag, struct thread *td)
{
    struct keyvault *kv;
    int error;

    error = devfs_get_cdevpriv((void **)&kv);
    if (error != 0)
        return (error);
    ...
}
```

### 5. Update Termination Handler Registration

**Before:**
```c
static struct vbsd_member_ops keyvault_coalition_ops = {
    .mo_terminate = keyvault_coalition_terminate,
    .mo_name = "keyvault",
    .mo_flags = MOF_CAN_LEAD,
};

/* Registration */
vbsd_member_ops_register(&keyvault_coalition_ops, &keyvault_dtype);
```

**After:**
```c
static struct vbsd_terminate_ops keyvault_terminate_ops = {
    .vto_terminate = keyvault_terminate,
    .vto_name = "keyvault",
    .vto_flags = VTO_CAN_LEAD,
};

/* Registration */
vbsd_terminate_ops_register(keyvault_cdev, &keyvault_terminate_ops);
```

### 6. Update Termination Callback Signature

**Before:**
```c
static int
keyvault_coalition_terminate(struct file *fp, struct thread *td)
{
    struct keyvault *kv = fp->f_data;
    ...
}
```

**After:**
```c
static int
keyvault_terminate(void *priv, struct thread *td)
{
    struct keyvault *kv = priv;

    KEYVAULT_LOCK(kv);
    kv->kv_revoked = true;
    for (int i = 0; i < KEYVAULT_MAX_SLOTS; i++) {
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
```

### 7. Update Leader Death Notification

**Before:**
```c
/* In keyvault_revoke() */
if (fp != NULL && vbsd_coalition_available())
    VBSD_LEADER_DIED(fp);
```

**After:**
```c
/* Need new API since we don't have fp anymore */
if (kv->kv_cdev != NULL && vbsd_coalition_available())
    VBSD_LEADER_DIED_CDEV(kv->kv_cdev, priv);
```

This requires a new event handler in coalition that can look up leadership
by (cdev, priv) tuple instead of file pointer.

### 8. Update Header File

**Changes to vbsd_keyvault.h:**

```c
struct keyvault {
    struct mtx          kv_lock;
    bool                kv_revoked;
    struct cdev         *kv_cdev;    /* Was: struct file *kv_fp */
    struct keyvault_slot kv_slots[KEYVAULT_MAX_SLOTS];
};
```

### 9. Update Module Load/Unload

**Before:**
```c
case MOD_LOAD:
    keyvault_zone = uma_zcreate(...);

    if (vbsd_coalition_available()) {
        error = vbsd_member_ops_register(&keyvault_coalition_ops,
            &keyvault_dtype);
        if (error != 0) { ... }
    }

    keyvault_dev = make_dev(&keyvault_cdevsw, ...);
    break;

case MOD_UNLOAD:
    destroy_dev(keyvault_dev);
    vbsd_member_ops_deregister(keyvault_dtype);
    uma_zdestroy(keyvault_zone);
    break;
```

**After:**
```c
case MOD_LOAD:
    keyvault_zone = uma_zcreate(...);

    keyvault_dev = make_dev(&keyvault_cdevsw, ...);
    if (keyvault_dev == NULL) {
        uma_zdestroy(keyvault_zone);
        return (ENXIO);
    }

    if (vbsd_coalition_available()) {
        error = vbsd_terminate_ops_register(keyvault_dev,
            &keyvault_terminate_ops);
        if (error != 0) {
            destroy_dev(keyvault_dev);
            uma_zdestroy(keyvault_zone);
            return (error);
        }
    }
    break;

case MOD_UNLOAD:
    vbsd_terminate_ops_deregister(keyvault_dev);
    destroy_dev(keyvault_dev);
    uma_zdestroy(keyvault_zone);
    break;
```

## Coalition API Changes Required

The coalition module replaces the dtype-based API entirely:

**Remove:**
```c
/* DELETE - old dtype-based API */
struct vbsd_member_ops { ... };
int vbsd_member_ops_register(struct vbsd_member_ops *ops, int *dtype_out);
int vbsd_member_ops_deregister(int dtype);
```

**Add:**
```c
/* NEW - cdev-based API */
struct vbsd_terminate_ops {
    int         (*vto_terminate)(void *priv, struct thread *td);
    const char  *vto_name;
    uint32_t    vto_flags;
};

#define VTO_CAN_LEAD    0x0001  /* This device can be a coalition leader */

/* Register/deregister by cdev */
int vbsd_terminate_ops_register(struct cdev *dev, struct vbsd_terminate_ops *ops);
int vbsd_terminate_ops_deregister(struct cdev *dev);

/* Lookup ops by cdev */
struct vbsd_terminate_ops *vbsd_terminate_ops_lookup(struct cdev *dev);

/* Leader death for cdev-based devices */
typedef void (*vbsd_leader_died_cdev_fn)(void *arg, struct cdev *dev, void *priv);
EVENTHANDLER_DECLARE(vbsd_leader_died_cdev, vbsd_leader_died_cdev_fn);

#define VBSD_LEADER_DIED_CDEV(dev, priv) \
    EVENTHANDLER_INVOKE(vbsd_leader_died_cdev, dev, priv)
```

## Enlistment Changes

When a DTYPE_VNODE fd is enlisted in a coalition:

1. Check if `vp->v_type == VCHR`
2. Get `cdev = vp->v_rdev`
3. Look up `ops = vbsd_terminate_ops_lookup(cdev)`
4. Get private data via `devfs_get_cdevpriv(&priv)`
5. Store (cdev, priv, ops) tuple in member structure

## Summary Checklist

- [ ] Replace `d_fdopen` with `d_open`
- [ ] Replace `finit()` with `devfs_set_cdevpriv()`
- [ ] Replace `fo_close` with dtor callback
- [ ] Replace `fo_ioctl` with `d_ioctl`
- [ ] Update terminate callback signature: `(void *priv, td)` instead of `(fp, td)`
- [ ] Replace `kv_fp` with `kv_cdev` in struct
- [ ] Update module init to use `vbsd_terminate_ops_register()`
- [ ] Update module fini to use `vbsd_terminate_ops_deregister()`
- [ ] Update leader death to use `VBSD_LEADER_DIED_CDEV()`
- [ ] Delete `keyvault_fileops` structure
- [ ] Delete `keyvault_dtype` variable
