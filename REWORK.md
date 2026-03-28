# SecurityCoalitions Rework: Standard Device Model

## Problem

Current implementation uses `DTYPE_DEV` with `finit()`, bypassing the vnode layer. This prevents CACL (and other MACF-based systems) from protecting coalition fds since there's no vnode label.

## Solution

Use standard FreeBSD device model. All devices use `cdevsw` and return `DTYPE_VNODE` fds, which have MACF labels.

### Coalition Device

```c
static struct cdevsw vbsd_coalition_cdevsw = {
    .d_version  = D_VERSION,
    .d_open     = vbsd_coalition_open,
    .d_close    = vbsd_coalition_close,
    .d_ioctl    = vbsd_coalition_ioctl,
    .d_kqfilter = vbsd_coalition_kqfilter,
    .d_name     = "vbsd_coalition",
};

static int
vbsd_coalition_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
    struct vbsd_coalition *vc;

    vc = vbsd_coalition_alloc();
    devfs_set_cdevpriv(vc, vbsd_coalition_dtor);
    return (0);
}

static void
vbsd_coalition_dtor(void *arg)
{
    struct vbsd_coalition *vc = arg;
    vbsd_coalition_terminate_and_free(vc);
}
```

### Logical Termination for Custom Devices

Register termination handlers by `struct cdev *`:

```c
struct vbsd_terminate_ops {
    int         (*vto_terminate)(void *priv, struct thread *td);
    const char  *vto_name;
    uint32_t    vto_flags;  /* VTO_CAN_LEAD */
};

int vbsd_terminate_ops_register(struct cdev *dev, struct vbsd_terminate_ops *ops);
int vbsd_terminate_ops_deregister(struct cdev *dev);
```

**Third-party module usage:**

```c
static int
keyvault_terminate(void *priv, struct thread *td)
{
    struct keyvault_data *kd = priv;
    explicit_bzero(kd->key, kd->keylen);  /* Wipe keys */
    kd->revoked = true;
    wakeup(kd);
    return (0);
}

static struct vbsd_terminate_ops keyvault_ops = {
    .vto_terminate = keyvault_terminate,
    .vto_name      = "keyvault",
    .vto_flags     = VTO_CAN_LEAD,
};

// At module load:
keyvault_cdev = make_dev(&keyvault_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "keyvault");
vbsd_terminate_ops_register(keyvault_cdev, &keyvault_ops);
```

### Coalition Termination Logic

```c
static void
vbsd_terminate_member(struct file *fp, struct thread *td)
{
    struct vnode *vp;
    struct cdev *cdev;
    struct vbsd_terminate_ops *ops;
    void *priv;

    switch (fp->f_type) {
    case DTYPE_PROCDESC:
        kern_psignal(proc, SIGKILL);
        break;
    case DTYPE_JAILDESC:
        prison_remove(prison);
        break;
    case DTYPE_SOCKET:
        soshutdown(so, SHUT_RDWR);
        break;
    case DTYPE_SHM:
        shm_truncate(shmfd, 0);
        break;
    case DTYPE_VNODE:
        vp = fp->f_vnode;
        if (vp->v_type == VCHR) {
            cdev = vp->v_rdev;
            ops = vbsd_terminate_ops_lookup(cdev);
            if (ops != NULL) {
                devfs_get_cdevpriv(&priv);
                ops->vto_terminate(priv, td);
            }
        }
        break;
    }
}
```

## Changes Required

1. **Coalition module**: Replace `finit()` with `cdevsw` + `devfs_set_cdevpriv()`

2. **New API**: Add `vbsd_terminate_ops_register(cdev, ops)`

3. **Remove**: `vbsd_member_ops_register()` DTYPE-based API

4. **Update samples**: keyvault uses new pattern

## Result

- All fds are `DTYPE_VNODE` with MACF labels
- CACL protects coalition and custom device fds automatically
- Logical termination preserved via cdev-based handler registry
- Standard FreeBSD device model throughout
