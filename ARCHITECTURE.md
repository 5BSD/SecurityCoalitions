# vBSD Coalition Architecture

## Overview

Coalitions provide capability-based resource group management for FreeBSD. A coalition groups file descriptors representing capabilities (processes, jails, sockets, devices, etc.) that should be terminated together when the coalition is closed.

## Comparison with Apple's Coalitions

Apple's macOS/iOS also has a feature called "coalitions" (introduced in OS X 10.10). While the name is similar, the goals differ:

| Aspect | Apple Coalitions (XNU) | vBSD Coalition |
|--------|------------------------|----------------|
| **Primary Purpose** | Resource accounting & memory management | Kill switch / coordinated termination |
| **Focus** | CPU/memory tracking, jetsam, app grouping | Authority to revoke/terminate resources |
| **Member Types** | Processes only | Processes, jails, sockets, SHM, devices, custom types |
| **Authority Model** | Kernel-managed, launchd-driven | Capability-based (fd = authority) |
| **Resource Limits** | Per-coalition CPU/memory limits | No resource accounting |

**Apple's coalitions** group apps with their XPC services for resource accounting, memory pressure responses (jetsam), and background app management.

**vBSD Coalition** implements a supervisor pattern where closing a file descriptor terminates all enlisted resources. Authority is a capability (fd) that can be passed, duplicated, or restricted with Capsicum.

## Core Philosophy

**Capabilities are file descriptors.** In Capsicum, authority is held via file descriptors. Coalitions extend this: the authority to terminate/revoke a resource is also a capability, held via the coalition fd.

**The Pattern:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SUPERVISOR PROCESS                          │
│                                                                      │
│   1. Create coalition                                                │
│      coalition_fd = open("/dev/coalition", O_RDWR);                 │
│                                                                      │
│   2. Enlist resources                                                │
│      ioctl(coalition_fd, VBSD_COALITION_ENLIST, &proc_fd);          │
│      ioctl(coalition_fd, VBSD_COALITION_ENLIST, &jail_fd);          │
│      ioctl(coalition_fd, VBSD_COALITION_ENLIST, &socket_fd);        │
│                                                                      │
│   3. Close coalition → terminates all enlisted resources            │
│      close(coalition_fd);                                           │
│      // Process killed (SIGKILL)                                    │
│      // Jail destroyed (prison_remove)                              │
│      // Socket shutdown (RST sent)                                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Key insight:** The supervisor holds termination authority via the coalition. Closing the coalition terminates all members.

## Lifecycle

```
                    ┌──────────────────┐
                    │  Create Coalition │
                    │ open(/dev/coalition)
                    └────────┬─────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │     Enlist Members           │
              │  ioctl(VBSD_COALITION_ENLIST)│
              │                              │
              │  - Coalition takes fhold()   │
              │  - Caller KEEPS their fd     │
              │  - Member tracked in list    │
              │  - One-way: no unenlist      │
              └──────────────┬───────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │     Coalition Active         │
              │                              │
              │  Members can exit naturally: │
              │  - Process dies → removed    │
              │  - Jail destroyed → removed  │
              │  - Generic fds: stay         │
              └──────────────┬───────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │     Close Coalition          │
              │     close(coalition_fd)      │
              │                              │
              │  For each member:            │
              │    1. mo_terminate(fp)       │
              │    2. fdrop(fp)              │
              └──────────────────────────────┘
```

## API

### User-Space API

```c
#include <sys/vbsd_coalition.h>

/* Create a coalition */
int coalition_fd = open("/dev/coalition", O_RDWR);

/* Enlist a single member (one-way, cannot unenlist) */
int member_fd = ...;  /* procdesc, jaildesc, socket, device, coalition, etc. */
ioctl(coalition_fd, VBSD_COALITION_ENLIST, &member_fd);

/* Enlist multiple members at once */
int fds[] = {fd1, fd2, fd3};
struct vbsd_enlist_set es = { .fds = fds, .count = 3 };
if (ioctl(coalition_fd, VBSD_COALITION_ENLIST_SET, &es) < 0) {
    /* es.enlisted = count of successful enlistments before error */
}

/* Self-join: calling process joins the coalition */
ioctl(coalition_fd, VBSD_COALITION_JOIN, NULL);

/* Query coalition status */
struct vbsd_coalition_stat st;
ioctl(coalition_fd, VBSD_COALITION_STAT, &st);
printf("members: %u, processes: %u, nested: %u\n",
    st.vcs_member_count, st.vcs_process_count, st.vcs_nested_count);

/* Set termination signal (default is SIGKILL) */
int sig = SIGTERM;
ioctl(coalition_fd, VBSD_COALITION_SET_SIGNAL, &sig);

/* Graceful termination: SIGTERM first, then SIGKILL after timeout */
struct vbsd_graceful g = {
    .vg_signal = SIGTERM,
    .vg_timeout_ms = 5000,  /* 5 second grace period */
};
ioctl(coalition_fd, VBSD_COALITION_TERMINATE_GRACEFUL, &g);

/* Immediate terminate (SIGKILL) */
ioctl(coalition_fd, VBSD_COALITION_TERMINATE);

/* Set deadline - automatic termination after timeout */
struct vbsd_deadline d = {
    .vd_timeout_ms = 30000,   /* 30 seconds */
    .vd_signal = SIGTERM,     /* Try graceful first */
    .vd_grace_ms = 5000,      /* 5 second grace period */
};
ioctl(coalition_fd, VBSD_COALITION_SET_DEADLINE, &d);

/* Cancel deadline (timeout = 0) */
d.vd_timeout_ms = 0;
ioctl(coalition_fd, VBSD_COALITION_SET_DEADLINE, &d);

/* Or just close - also terminates all members */
close(coalition_fd);
```

### Kernel API (for module authors)

```c
#include <sys/vbsd_coalition.h>

/*
 * Member operations - implement these for your resource type.
 */
struct vbsd_member_ops {
    /*
     * Terminate the resource. Called when the coalition is closed.
     *
     * For types with interior revocation (opt-in):
     *   - Process: kern_psignal(SIGKILL)
     *   - Jail: prison_remove()
     *   - Socket: soshutdown(SHUT_RDWR)
     *   - Custom: set a "revoked" flag, invalidate keys, etc.
     *
     * For types without interior revocation:
     *   - Return 0 (no-op). Coalition will fdrop() afterward.
     *
     * Returns 0 on success. Errors are logged but don't stop
     * termination of other members.
     */
    int     (*mo_terminate)(struct file *fp, struct thread *td);

    /* Name for logging/debugging */
    const char *mo_name;
};

/*
 * Register ops for a file descriptor type.
 *
 * Call this at module load time. The dtype must be a valid DTYPE_*
 * constant (DTYPE_PROCDESC, DTYPE_JAILDESC, or a custom type).
 *
 * Returns:
 *   0        - success
 *   EEXIST   - ops already registered for this dtype
 *   EINVAL   - invalid dtype or ops
 */
int vbsd_member_ops_register(int dtype, struct vbsd_member_ops *ops);

/*
 * Deregister ops for a file descriptor type.
 *
 * Call this at module unload.
 *
 * Returns:
 *   0        - success
 */
int vbsd_member_ops_deregister(int dtype);
```

## Implementing Coalition Support in Your Module

Most built-in types (files, pipes, sockets, etc.) are already supported. You only
need to implement custom ops if you want **interior revocation** - the ability to
invalidate a resource so that ALL holders of any fd to it see the revocation.

### Interior Revocation (Opt-In)

Interior revocation means the resource itself is invalidated, not just the coalition's
reference. This is appropriate for:

- **Processes**: SIGKILL kills the process; all procdescs see it as dead
- **Jails**: prison_remove() destroys the jail; all jaildescs become invalid
- **Sockets**: soshutdown() kills the connection; all socket fds get errors
- **Custom resources**: Set a revoked flag; all operations fail

For simple fd types (files, pipes), interior revocation isn't needed - closing
the coalition's reference is sufficient.

### Implementing Custom Ops

```c
static int
your_terminate(struct file *fp, struct thread *td)
{
    struct your_data *yd = fp->f_data;

    /*
     * Interior revocation: invalidate the resource itself.
     * After this, ANY fd pointing to this resource should fail.
     */
    YOUR_LOCK(yd);
    yd->revoked = true;
    wakeup(yd);  /* Wake waiters so they see revocation */
    YOUR_UNLOCK(yd);

    return (0);
}

static struct vbsd_member_ops your_ops = {
    .mo_terminate = your_terminate,
    .mo_name      = "yourtype",
};

/* Register at module load */
vbsd_member_ops_register(DTYPE_YOURTYPE, &your_ops);
```

### Checking Revocation in Operations

If you implement interior revocation, every operation must check:

```c
static int
your_do_operation(struct your_data *yd, ...)
{
    YOUR_LOCK(yd);
    if (yd->revoked) {
        YOUR_UNLOCK(yd);
        return (EBADF);
    }
    /* ... do the operation ... */
    YOUR_UNLOCK(yd);
    return (0);
}
```

## Handling Natural Exit

Some resources have a natural lifecycle (processes die, jails are removed). The coalition tracks these exits automatically.

### Processes

Handled via `EVENTHANDLER(process_exit, ...)`:
- Exit handler removes process from coalition
- Coalition's reference dropped

### Jails

Handled via prison OSD destructor:
- When prison is freed, OSD destructor fires
- Removes jail from coalition

### Generic Fds

These don't have natural exit events:
- Stay enlisted until coalition closes
- mo_terminate called, then fdrop()

## Capability Restriction Pattern (Optional)

This pattern is useful when you want workers to use a resource but not be able to
revoke it directly. The supervisor holds revocation authority via the coalition.

**The pattern:**
1. Create resource with full capabilities
2. Duplicate the fd
3. Restrict the duplicate (remove direct revoke capability)
4. Enlist the original in a coalition
5. Pass the restricted fd to worker

**Example restriction ioctl:**

```c
#define YOUR_IOC_RESTRICT    _IOW('Y', 1, uint32_t)

#define YOUR_CAP_READ        0x0001
#define YOUR_CAP_WRITE       0x0002
#define YOUR_CAP_REVOKE      0x0004  /* Direct revoke via ioctl */
#define YOUR_CAP_ALL         0x0007

static int
your_ioctl_restrict(struct your_data *yd, uint32_t newcaps)
{
    /* Can only remove capabilities, never add */
    if ((newcaps & ~yd->caps) != 0)
        return (ENOTCAPABLE);

    yd->caps = newcaps;
    return (0);
}
```

**Note:** The coalition bypasses capability restrictions - it calls mo_terminate
directly in kernel space. This is intentional: the supervisor holds revocation
authority via the coalition, not via the fd's capabilities.

## Lock Order

```
vbsd_proc_hash_lock (rwlock)
    → vc_sx (coalition sx lock)
```

When acquiring multiple locks, always follow this order to prevent deadlock.

## Error Handling

| Error | Meaning |
|-------|---------|
| EOPNOTSUPP | No ops registered for this file type (only for invalid dtype) |
| EBUSY | Resource already enlisted in a coalition; or ops deregister with active members |
| EINVAL | Coalition is terminating, cannot enlist; or batch count exceeds limit |
| EBADF | File descriptor invalid or already closed |
| ESRCH | Process/jail no longer exists |
| ESHUTDOWN | Coalition already terminated (second terminate call) |
| ENOMEM | Resource limit exceeded (max coalitions or max members) |

**Note:** On successful enlistment, the caller retains their fd (reference semantics).
The coalition holds its own reference via `fhold()`. Caller can continue using the fd
(e.g., `waitpid()` on processes, query jail status) and must close it when done.

## Built-in Types

The coalition module registers ops for these types at load:

| DTYPE | Resource | mo_terminate | Interior Revocation |
|-------|----------|--------------|---------------------|
| DTYPE_PROCDESC | Process descriptor | `kern_psignal(SIGKILL)` | Yes - process killed |
| DTYPE_JAILDESC | Jail descriptor | `prison_remove()` | Yes - jail destroyed |
| DTYPE_SOCKET | Socket | `soshutdown(SHUT_RDWR)` | Yes - connection killed |
| DTYPE_SHM | POSIX shared memory | `fo_truncate(0)` | Yes - SIGBUS on access |
| DTYPE_VNODE | File/vnode | no-op | No |
| DTYPE_PIPE | Pipe | no-op | No |
| DTYPE_FIFO | Named pipe (FIFO) | no-op | No |
| DTYPE_SEM | POSIX semaphore | no-op | No |
| DTYPE_KQUEUE | Kqueue | no-op | No |
| DTYPE_EVENTFD | Eventfd | no-op | No |
| DTYPE_TIMERFD | Timerfd | no-op | No |
| DTYPE_INOTIFY | Inotify | no-op | No |
| DTYPE_DEV | Device | no-op | No (custom ops can override) |

### Interior Revocation

Types with interior revocation invalidate the resource for ALL holders:
- **Process**: SIGKILL kills the process; all procdescs see zombie
- **Jail**: prison_remove destroys the jail; all jaildescs become invalid
- **Socket**: soshutdown kills the connection; all socket fds get errors
- **SHM**: truncate to 0; any access to mapped region triggers SIGBUS

Types without interior revocation just have their coalition reference dropped.
Other holders are unaffected.

**DTYPE_DEV** is registered with default (no-op) ops. Device drivers that want
interior revocation can register their own ops at module load time.

### Fallback Behavior

Any fd type can be enlisted. Types without registered ops use default behavior:
- Terminate: no-op (just close the fd)
- The coalition holds a reference via `fhold()` and releases via `fdrop()` on close

External modules can register custom ops using `vbsd_member_ops_register()` for
types that need interior revocation (invalidating the resource for all holders).

## Nested Coalitions

Coalitions can be enlisted in other coalitions, enabling hierarchical supervision:

```
Coalition A (outer - top-level supervisor)
├── member: Coalition B (inner - delegated supervisor)
│   ├── member: process 1
│   └── member: socket 1
├── member: Coalition C (another inner)
│   └── member: jail 1
└── member: process 2
```

**Cascade Termination**: Terminating the outer coalition cascades to all nested
coalitions and their members. The entire tree is terminated.

**Nesting Depth Limit**: Maximum nesting depth is `VBSD_MAX_NESTING_DEPTH` (16)
to prevent infinite loops. Attempting to exceed this returns `ELOOP`.

**Self-Enlistment Prevention**: A coalition cannot be enlisted in itself (returns `EINVAL`).

**Use Case - Delegation Pattern**:
1. Top-level supervisor creates outer coalition
2. Creates inner coalition, enlists resources for sub-task
3. Passes inner coalition fd to sub-supervisor process
4. Sub-supervisor manages its members independently
5. Top-level can still terminate everything via outer coalition

## Graceful Termination

For processes that need cleanup time, use graceful termination:

```c
struct vbsd_graceful g = {
    .vg_signal = SIGTERM,      /* Signal to send first */
    .vg_timeout_ms = 5000,     /* 5 second grace period */
};
ioctl(coalition_fd, VBSD_COALITION_TERMINATE_GRACEFUL, &g);
```

**Behavior**:
1. Send configured signal (e.g., SIGTERM) to all process members
2. Wait up to `vg_timeout_ms` for processes to exit voluntarily
3. Send SIGKILL to any surviving processes (guaranteed termination)
4. Terminate other members (jails, sockets, nested coalitions)

**Guarantees**: Graceful termination is still a kill switch - all members
are terminated. Processes that don't exit during the grace period are
forcefully killed.

## Deadline Termination

Automatically terminate the coalition after a timeout. Useful for batch jobs,
serverless functions, or sandboxing untrusted code with hard time limits.

```c
struct vbsd_deadline d = {
    .vd_timeout_ms = 30000,   /* 30 seconds until termination */
    .vd_signal = SIGTERM,     /* Signal to send first (0 = immediate SIGKILL) */
    .vd_grace_ms = 5000,      /* Grace period after signal before SIGKILL */
};
ioctl(coalition_fd, VBSD_COALITION_SET_DEADLINE, &d);
```

**Behavior**:
1. After `vd_timeout_ms`, send `vd_signal` to all process members
2. Wait `vd_grace_ms` for processes to exit voluntarily
3. Send SIGKILL to any remaining processes
4. Terminate all other members (jails, sockets, etc.)

**Cancellation**: Set `vd_timeout_ms = 0` to cancel a pending deadline.

**Resetting**: Setting a new deadline replaces any existing one.

**Use cases**:
- Batch job timeout: "Kill everything if job takes > 1 hour"
- Sandbox timeout: "WebAssembly module gets 30 seconds max"
- Serverless function timeout: "Lambda must complete in 15 minutes"

## Project Structure

```
SecurityCoalitions/
├── Makefile                    # Top-level build orchestration
├── ARCHITECTURE.md             # This file
├── README.md
├── sys/
│   ├── vbsd/
│   │   ├── vbsd_coalition.h    # Public header
│   │   └── vbsd_coalition.c    # Implementation
│   └── modules/
│       └── vbsd_coalition/
│           └── Makefile        # Kernel module Makefile
└── tests/
    ├── Makefile
    ├── test_harness.h
    ├── test_harness.c
    ├── coalition_test.c        # Test suite
    └── test_helper.c           # Helper binary
```

## Test Matrix

| Feature | Test | Expected |
|---------|------|----------|
| Coalition creation | `test_create_coalition` | fd returned |
| Multiple coalitions | `test_create_multiple_coalitions` | distinct fds |
| Fd passing | `test_coalition_fd_passable` | SCM_RIGHTS works |
| Process enlistment | `test_enlist_process` | success |
| Double enlistment | `test_enlist_process_twice_fails` | EBUSY (already enlisted) |
| Invalid fd | `test_enlist_invalid_fd` | error |
| Self-join | `test_self_join` | success |
| Double self-join | `test_self_join_twice_fails` | EBUSY |
| Fork inheritance | `test_fork_inheritance` | child in coalition |
| Terminate signals | `test_terminate_signals_members` | all signaled |
| Terminate idempotent | `test_terminate_idempotent` | ESHUTDOWN |
| Batch enlist basic | `test_enlist_set_basic` | all enlisted |
| Batch enlist empty | `test_enlist_set_empty` | success (0 enlisted) |
| Batch enlist partial | `test_enlist_set_partial_failure` | stops on error |
| Batch enlist max | `test_enlist_set_exceeds_max` | EINVAL |
| Batch enlist mixed | `test_enlist_set_mixed_types` | success |
| Join after terminate | `test_join_after_terminate_fails` | EINVAL |
| Close terminates | `test_close_terminates` | members signaled |
| Jail enlistment | `test_enlist_jail` | success |
| Jail double enlist | `test_enlist_jail_twice_fails` | EBUSY |
| Jail different coalition | `test_enlist_jail_different_coalition` | success |
| Multiple jails | `test_enlist_multiple_jails` | multiple jails |
| Jail after terminate | `test_enlist_jail_after_terminate_fails` | EINVAL |
| Terminate removes jails | `test_terminate_removes_jails` | jails removed |
| Jail fork inheritance | `test_jail_fork_inheritance` | child inherits |
| Socket shutdown | `test_socket_shutdown_on_terminate` | socket shutdown |
| SHM truncate | `test_shm_truncate_on_terminate` | SHM size 0 |
| Device enlistment | `test_enlist_device` | success |
| Pipe enlistment | `test_enlist_pipe` | success |
| Resource limit (coalitions) | `test_max_coalitions_limit` | ENOMEM |
| Resource limit (members) | `test_max_members_limit` | ENOMEM |
| Process exit removal | `test_process_exit_removes_member` | member removed |
| Enlist dead process | `test_enlist_dead_process` | ESRCH |
| Reference semantics | `test_reference_semantics` | fd valid, process killed |
| Invalid ioctl | `test_invalid_ioctl_command` | ENOTTY |
| Wrong fd type | `test_ioctl_on_wrong_fd_type` | error |
| Negative fd | `test_enlist_negative_fd` | EBADF |
| Enlist self | `test_enlist_self` | error |
| Bad pointer | `test_enlist_set_bad_pointer` | EFAULT |
| First fd fails batch | `test_enlist_set_first_fails` | EBADF, 0 enlisted |
| Duplicate fd in batch | `test_enlist_set_duplicate_fd` | EBUSY |
| Two coalitions | `test_enlist_in_two_coalitions` | EBUSY |
| Self-join when enlisted | `test_self_join_when_already_enlisted` | EBUSY |
| Use after close | `test_use_after_close` | EBADF |
| Enlist after terminate | `test_enlist_after_terminate_fails` | EINVAL |
| Jail different desc | `test_enlist_jail_via_different_desc` | EBUSY |
| Fork during terminate | `test_fork_during_terminate` | no crash |
| Concurrent enlist | `test_concurrent_enlist` | success |
| Batch at exact limit | `test_enlist_set_at_limit` | success |
| Terminate empty | `test_terminate_empty_coalition` | success |
| Close empty | `test_close_empty_coalition` | success |
| Limit zero unlimited | `test_limit_zero_unlimited` | success |
| Dup before enlist | `test_dup_before_enlist` | EBUSY |
| Fd passing both close | `test_fd_passing_both_close` | terminates |
| Stat empty coalition | `test_stat_empty_coalition` | all fields zero |
| Stat with members | `test_stat_with_members` | counts match |
| Stat after terminate | `test_stat_after_terminate` | TERMINATING flag |
| Set valid signal | `test_set_signal_valid` | success |
| Set signal zero | `test_set_signal_invalid_zero` | EINVAL |
| Set signal negative | `test_set_signal_invalid_negative` | EINVAL |
| Set signal after terminate | `test_set_signal_after_terminate` | ESHUTDOWN |
| Graceful process exits | `test_graceful_process_exits` | SIGTERM kill |
| Graceful stubborn | `test_graceful_stubborn_process` | SIGKILL after timeout |
| Graceful invalid signal | `test_graceful_invalid_signal` | EINVAL |
| Deadline basic | `test_deadline_basic` | process killed after timeout |
| Deadline cancel | `test_deadline_cancel` | process survives cancelled deadline |
| Deadline with grace | `test_deadline_with_grace` | SIGTERM then SIGKILL |
| Deadline after terminate | `test_deadline_after_terminate` | ESHUTDOWN |
| Deadline invalid signal | `test_deadline_invalid_signal` | EINVAL |
| Nested basic | `test_nested_coalition_basic` | success |
| Nested cascade terminate | `test_nested_coalition_cascade_terminate` | all killed |
| Nested depth tracking | `test_nested_coalition_depth` | depth correct |
| Nested self-enlist | `test_nested_coalition_self_enlist` | EINVAL |
| Nested depth limit | `test_nested_coalition_depth_limit` | ELOOP at limit |

## Build & Test

```sh
# Build everything
make

# Build module only
make module

# Build tests only
make tests

# Load module
sudo kldload ./sys/modules/vbsd_coalition/vbsd_coalition.ko

# Run tests (requires root)
sudo ./tests/bin/coalition_test

# Check module loaded
kldstat | grep vbsd_coalition

# Check memory usage
vmstat -m | grep vbsd

# Check coalition statistics
sysctl kern.coalition

# Adjust resource limits (example)
sysctl kern.coalition.max_coalitions=8192

# Unload module
sudo kldunload vbsd_coalition

# Clean
make clean
```

## FreeBSD API Usage

| Mechanism | API | Notes |
|-----------|-----|-------|
| Procdesc | `procdesc_find(td, fd, &cap, &p)` | Returns proc with PROC_LOCK held |
| Jaildesc | `jaildesc_find(td, fd, &pr, &ucredp)` | Returns prison held |
| Jail removal | `prison_remove(pr)` | Kills all jail processes |
| Jail OSD | `osd_jail_get/set(pr, slot, value)` | Per-jail object data |
| Fork hook | `EVENTHANDLER(process_fork)` | `fn(void*, parent, child, flags)` |
| Exit hook | `EVENTHANDLER(process_exit)` | `fn(void*, proc)` |

## Resource Limits

Coalition implements tunable resource limits via sysctl:

| Sysctl | Default | Description |
|--------|---------|-------------|
| `kern.coalition.max_coalitions` | 0 | Maximum concurrent coalitions (0 = unlimited) |
| `kern.coalition.max_members` | 0 | Maximum total members across all coalitions (0 = unlimited) |
| `kern.coalition.max_members_per_coalition` | 0 | Maximum members per coalition (0 = unlimited) |
| `kern.coalition.enlist_set_max` | 1024 | Maximum fds per VBSD_COALITION_ENLIST_SET call |

Resource limit checks return `ENOMEM` when exceeded. Fork inheritance is exempt
from limits (security takes precedence) but logs a warning when over limit.

## Observability

### Audit Subsystem Integration

Coalition integrates with the FreeBSD audit subsystem (BSM) for security
auditing. Audit events are generated for:

| Operation | Audit Arguments |
|-----------|-----------------|
| Enlist | `AUDIT_ARG_FD(target_fd)` - fd being enlisted |
| Join | `AUDIT_ARG_PID(pid)` - process joining |
| Terminate | `AUDIT_ARG_VALUE(member_count)` - members at termination |
| Enlist Set | `AUDIT_ARG_VALUE(count)` - number of fds in batch |

To enable audit logging:
```sh
# Ensure audit is enabled
service auditd start

# Configure audit_control to capture ioctl events
# Add 'io' class to flags in /etc/security/audit_control
```

### DTrace SDT Probes

Coalition defines a DTrace SDT provider `coalition` with the following probes:

| Probe | Arguments | Description |
|-------|-----------|-------------|
| `coalition:::create` | `pid_t pid` | Coalition fd created |
| `coalition:::enlist` | `int fd, int dtype, int error` | Single fd enlisted |
| `coalition:::enlist__set` | `u_int count, u_int enlisted, int error` | Batch enlist |
| `coalition:::join` | `pid_t pid, int error` | Process self-joined |
| `coalition:::terminate` | `u_int member_count, int error` | Explicit terminate |
| `coalition:::close` | `u_int member_count` | Coalition fd closed |
| `coalition:::member__exit` | `pid_t pid` | Process member exited |
| `coalition:::fork__inherit` | `pid_t parent, pid_t child` | Child inherited coalition |

**DTrace Usage Examples:**

```sh
# Trace all coalition activity
dtrace -n 'coalition::: { printf("%s: %d", probename, arg0); }'

# Trace coalition creation with process info
dtrace -n 'coalition:::create { printf("pid=%d comm=%s", arg0, execname); }'

# Trace enlistments with descriptor type
dtrace -n 'coalition:::enlist {
    printf("fd=%d dtype=%d err=%d", arg0, arg1, arg2);
}'

# Trace terminations
dtrace -n 'coalition:::terminate {
    printf("members=%d err=%d pid=%d", arg0, arg1, pid);
}'

# Count enlistments by type
dtrace -n 'coalition:::enlist /arg2 == 0/ { @[arg1] = count(); }'

# Track fork inheritance chains
dtrace -n 'coalition:::fork__inherit {
    printf("parent=%d -> child=%d", arg0, arg1);
}'

# Monitor batch enlistments
dtrace -n 'coalition:::enlist__set {
    printf("requested=%d enlisted=%d err=%d", arg0, arg1, arg2);
}'
```

**DTYPE Values (arg1 in enlist probe):**

| Value | Type | Description |
|-------|------|-------------|
| 1 | `DTYPE_VNODE` | File/vnode |
| 2 | `DTYPE_SOCKET` | Socket |
| 3 | `DTYPE_PIPE` | Pipe |
| 4 | `DTYPE_FIFO` | Named pipe (FIFO) |
| 5 | `DTYPE_KQUEUE` | Kqueue |
| 11 | `DTYPE_SHM` | POSIX shared memory |
| 12 | `DTYPE_SEM` | POSIX semaphore |
| 13 | `DTYPE_PROCDESC` | Process descriptor |
| 20 | `DTYPE_DEV` | Device |
| 23 | `DTYPE_JAILDESC` | Jail descriptor |
| 32+ | Custom | External module types |

## Limitations

1. **No jail_attach interception**: Processes that `jail_attach()` keep their
   existing coalition membership. Fork inheritance catches new processes.

2. **Global hash lock**: Process lookup requires rwlock. Acceptable for most
   workloads but could be contention point under extreme fork rates.

## References

- FreeBSD `osd(9)` - Object-Specific Data
- FreeBSD `procdesc(4)` - Process descriptors
- FreeBSD `jaildesc(4)` - Jail descriptors (FreeBSD 15+)
- FreeBSD `jail(2)` - Jail management
- FreeBSD `eventhandler(9)` - Event handler framework
