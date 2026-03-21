# SecurityCoalitions TODO

## Completed

### Jail Termination (Fixed)

All jail tests now pass. The following issues were resolved:

1. **Missing locks on `prison_remove()`** - Fixed by acquiring `allprison_lock` (exclusive) and `pr->pr_mtx` before calling `prison_remove()`. These locks are required by the FreeBSD jail API.

2. **Jails not being terminated** - Fixed by adding jail termination calls in both `vbsd_coalition_terminate()` (for explicit TERMINATE ioctl) and `fo_close()` (for implicit termination on close).

3. **OSD destructor race condition** - Fixed by clearing `vjo->vjo_member = NULL` BEFORE calling `prison_remove()`. This prevents the OSD destructor from doing a duplicate `TAILQ_REMOVE` on an already-removed member.

4. **Test EFAULT errors** - Fixed by using stack buffers for `jail_get()` parameters instead of const string literals. FreeBSD 15's kernel had issues reading const pointers.

## Known Issues

### Lingering Test Processes

Some tests may leave zombie or orphaned processes. These are typically:
- Zombie children waiting to be reaped (`<defunct>`)
- Orphaned children blocked in `pause()`

Workaround: `pkill -9 coalition_test` after test runs.

Root cause: Tests using `pdfork()` with `PD_DAEMON` flag reparent children to init. If the coalition termination doesn't kill them before the test exits, they become orphans.

## Future Enhancements

- Consider reducing LOG_WARNING messages to LOG_DEBUG for production
- Add more comprehensive jail + process interaction tests
- Test jail termination with active processes inside the jail
