# SecurityCoalitions TODO

## Completed

### Code Cleanup (Latest)

1. **Removed excessive LOG_WARNING messages** - Converted debug logging to LOG_DEBUG or removed entirely. Only essential warnings remain (resource limits, module load/unload).

2. **Removed debug sequence counter** - VBSD_SEQ was debugging-only, now removed.

3. **Defensive NULL checks → KASSERTs** - NULL checks in `fo_close` that should never happen are now KASSERTs.

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

Root cause: Tests using `pdfork()` can leave orphans if coalition termination doesn't kill them before the test exits.

## Future Enhancements

- Add more comprehensive jail + process interaction tests
- Test jail termination with active processes inside the jail
- Consider splitting vbsd_coalition.c into separate files if it grows further
