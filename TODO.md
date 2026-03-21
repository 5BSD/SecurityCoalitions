# SecurityCoalitions TODO

## Jail Termination Issue (Deferred)

The `prison_remove()` call crashes in FreeBSD 15 with a page fault at offset 0x20 in `prison_deref`. This needs investigation into FreeBSD 15's jail/prison API changes.

### Current Workaround
- Jails are cleaned up via `fdrop()` on the jaildesc file descriptor
- The OSD member pointer is cleared before cleanup to prevent double-free
- Jails are NOT actively terminated (processes inside not killed)

### Failing Jail Tests
- `test_enlist_jail_twice_fails` - Failed to get second jaildesc
- `test_terminate_removes_jails` - Failed to get jail ID before enlistment
- `test_jail_fork_inheritance` - Failed to get jail ID
- `test_enlist_jail_via_different_desc` - Failed to get second jaildesc

### Investigation Notes
- Crash occurs in `prison_deref` called from `prison_remove`
- Stack trace shows `__mtx_unlock_sleep` trying to unlock a mutex
- Fault address 0x20 suggests NULL pointer + offset access
- May be related to jaildesc/prison reference counting changes in FreeBSD 15

### Next Steps
1. Review FreeBSD 15 jail.h and prison struct changes
2. Check if `prison_remove` semantics changed
3. Consider using jail(2) syscall instead of direct prison_* calls
4. Test with simpler jail creation/destruction outside coalition context
