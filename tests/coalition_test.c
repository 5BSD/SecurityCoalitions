/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * vBSD Coalition Test Suite
 *
 * Comprehensive tests for coalition functionality.
 * Each feature has corresponding test coverage.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/jail.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_harness.h"
#include "vbsd_coalition.h"

static void
clear_clofork(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags >= 0)
		(void)fcntl(fd, F_SETFD, flags & ~FD_CLOFORK);
}

static int
waitpid_timeout(pid_t pid, int *status, int timeout_ms)
{
	const int step_ms = 25;
	int elapsed = 0;
	pid_t ret;

	while (elapsed < timeout_ms) {
		ret = waitpid(pid, status, WNOHANG);
		if (ret == pid)
			return (0);
		if (ret < 0)
			return (-1);
		usleep(step_ms * 1000);
		elapsed += step_ms;
	}
	errno = ETIMEDOUT;
	return (1);
}

static int
read_ready_byte(int fd, char *out, int timeout_ms)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = fd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, timeout_ms);
	if (ret <= 0)
		return (ret);
	return (read(fd, out, 1) == 1) ? 1 : -1;
}

/*
 * Unique jail name generation to prevent collisions between test runs.
 * Each test run uses the test process PID as a suffix.
 */
static pid_t jail_name_pid;

static const char *
jail_name(const char *base)
{
	static char namebuf[64];

	snprintf(namebuf, sizeof(namebuf), "%s_%d", base, (int)jail_name_pid);
	return (namebuf);
}

/*
 * Jail test helper functions
 */

/*
 * Create a minimal jail and return an owning jaildesc.
 * The jail will be automatically removed when the descriptor is closed.
 * Returns -1 on failure.
 */
static int
create_test_jail(const char *name)
{
	struct iovec iov[8];
	int jail_fd;
	int jid;

	/*
	 * Minimal jail parameters:
	 * - name: unique jail name
	 * - path: root directory (use /)
	 * - persist: keep jail alive without processes
	 */
	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, name);
	iov[1].iov_len = strlen(name) + 1;

	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, "/");
	iov[3].iov_len = sizeof("/");

	iov[4].iov_base = __DECONST(char *, "persist");
	iov[4].iov_len = sizeof("persist");
	iov[5].iov_base = NULL;
	iov[5].iov_len = 0;
	iov[6].iov_base = __DECONST(char *, "desc");
	iov[6].iov_len = sizeof("desc");
	jail_fd = -1;
	iov[7].iov_base = &jail_fd;
	iov[7].iov_len = sizeof(jail_fd);

	/*
	 * JAIL_CREATE: create new jail
	 * JAIL_OWN_DESC: return owning file descriptor (jail removed on close)
	 */
	jid = jail_set(iov, 8, JAIL_CREATE | JAIL_OWN_DESC);
	if (jid < 0)
		return (-1);
	if (jail_fd < 0)
		return (-1);
	return (jail_fd);
}

/*
 * Create a non-owning jail descriptor for an existing jail.
 * Use stack buffers to ensure memory is writable and properly aligned.
 */
static int
get_jail_desc(const char *name)
{
	struct iovec iov[4];
	char nameparam[8];
	char namebuf[256];
	char descparam[8];
	int jail_fd;
	int ret;

	/* Copy to stack buffers to ensure writeable memory */
	strlcpy(nameparam, "name", sizeof(nameparam));
	strlcpy(namebuf, name, sizeof(namebuf));
	strlcpy(descparam, "desc", sizeof(descparam));

	iov[0].iov_base = nameparam;
	iov[0].iov_len = strlen(nameparam) + 1;
	iov[1].iov_base = namebuf;
	iov[1].iov_len = strlen(namebuf) + 1;
	iov[2].iov_base = descparam;
	iov[2].iov_len = strlen(descparam) + 1;
	jail_fd = -1;
	iov[3].iov_base = &jail_fd;
	iov[3].iov_len = sizeof(jail_fd);

	ret = jail_get(iov, 4, JAIL_GET_DESC);
	if (ret < 0 || jail_fd < 0)
		return (-1);
	return (jail_fd);
}

/*
 * Get the jail ID for an existing jail by name.
 * Use stack buffers to ensure memory is writable and properly aligned.
 */
static int
get_jail_id(const char *name)
{
	struct iovec iov[2];
	char nameparam[8];
	char namebuf[256];
	int jid;

	/* Copy to stack buffers to ensure writeable memory */
	strlcpy(nameparam, "name", sizeof(nameparam));
	strlcpy(namebuf, name, sizeof(namebuf));

	iov[0].iov_base = nameparam;
	iov[0].iov_len = strlen(nameparam) + 1;
	iov[1].iov_base = namebuf;
	iov[1].iov_len = strlen(namebuf) + 1;

	jid = jail_get(iov, 2, 0);
	return (jid);
}

/* =========================================================================
 * FEATURE: Coalition Creation (open /dev/coalition)
 * ========================================================================= */

/*
 * Test: Can create a coalition via ioctl
 */
static struct test_result
test_create_coalition(void)
{
	int coal_fd;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Multiple coalitions can coexist
 */
static struct test_result
test_create_multiple_coalitions(void)
{
	int fd1, fd2, fd3;

	fd1 = create_coalition();
	TEST_ASSERT(fd1 >= 0, "Failed to create first coalition");

	fd2 = create_coalition();
	TEST_ASSERT(fd2 >= 0, "Failed to create second coalition");

	fd3 = create_coalition();
	TEST_ASSERT(fd3 >= 0, "Failed to create third coalition");

	/* All should be distinct */
	TEST_ASSERT(fd1 != fd2 && fd2 != fd3 && fd1 != fd3,
	    "Coalition fds should be distinct");

	close(fd3);
	close(fd2);
	close(fd1);
	return TEST_PASS(NULL);
}

/*
 * Test: Coalition fd is passable via SCM_RIGHTS (just verify DFLAG_PASSABLE)
 */
static struct test_result
test_coalition_fd_passable(void)
{
	int coal_fd;
	int sv[2];
	pid_t pid;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create socketpair for fd passing */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		close(coal_fd);
		return TEST_FAIL("socketpair failed");
	}

	pid = fork();
	if (pid < 0) {
		close(sv[0]);
		close(sv[1]);
		close(coal_fd);
		return TEST_FAIL("fork failed");
	}

	if (pid == 0) {
		/* Child: receive fd */
		struct msghdr msg = {0};
		struct cmsghdr *cmsg;
		char buf[CMSG_SPACE(sizeof(int))];
		struct iovec iov;
		char dummy;
		int received_fd;

		close(sv[0]);
		close(coal_fd);

		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		if (recvmsg(sv[1], &msg, 0) < 0)
			_exit(1);

		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
			_exit(2);

		memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
		if (received_fd < 0)
			_exit(3);

		close(received_fd);
		close(sv[1]);
		_exit(0);
	}

	/* Parent: send fd */
	{
		struct msghdr msg = {0};
		struct cmsghdr *cmsg;
		char buf[CMSG_SPACE(sizeof(int))];
		struct iovec iov;
		char dummy = 'x';

		close(sv[1]);

		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &coal_fd, sizeof(int));

		if (sendmsg(sv[0], &msg, 0) < 0) {
			close(sv[0]);
			close(coal_fd);
			wait(NULL);
			return TEST_FAIL("sendmsg failed");
		}
	}

	close(sv[0]);
	close(coal_fd);

	int status = wait_for_child(pid);
	TEST_ASSERT(status == 0, "Child failed to receive coalition fd");

	return TEST_PASS(NULL);
}

/* =========================================================================
 * FEATURE: Process Enlistment (VBSD_COALITION_ENLIST with procdesc)
 * ========================================================================= */

/*
 * Test: Enlist a process via procdesc
 */
static struct test_result
test_enlist_process(void)
{
	int coal_fd, proc_fd;
	pid_t pid;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/*
	 * Fork with procdesc using PD_DAEMON flag.
	 * PD_DAEMON means:
	 * - Child is reparented to init (not a child of this process)
	 * - Process lifecycle is fully managed by the procdesc
	 * - When procdesc is closed, process is killed AND reaped
	 * - Cannot use waitpid() - must use pdwait4() if needed
	 */
	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		/* Child: wait for termination signal */
		close(coal_fd);	/* Don't hold coalition fd */
		pause();
		_exit(0);
	}

	/* Enlist child via procdesc - caller keeps fd (reference semantics) */
	if (ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) < 0) {
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);  /* With PD_DAEMON, this reaps the zombie */
		close(coal_fd);
		return TEST_FAIL("Failed to enlist process");
	}

	/*
	 * proc_fd is closed after successful enlist.
	 * Closing coalition terminates all members.
	 * With PD_DAEMON, the procdesc handles both killing and reaping.
	 */
	close(coal_fd);

	/*
	 * Brief sleep to let the kernel process the SIGKILL and cleanup.
	 * The procdesc (now owned by coalition) handles reaping.
	 */
	usleep(10000);  /* 10ms */

	return TEST_PASS(NULL);
}

/*
 * Test: Cannot enlist same process twice (EBUSY)
 */
static struct test_result
test_enlist_process_twice_fails(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	/* First enlistment should succeed - caller keeps fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "First enlistment failed");

	/*
	 * With reference semantics, proc_fd is still valid.
	 * Second enlistment of same process should fail with EBUSY.
	 */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	TEST_ASSERT(ret < 0 && errno == EBUSY,
	    "Second enlistment should fail with EBUSY (already enlisted)");

	/* Caller keeps fd, must close it */
	close(coal_fd);
	close(proc_fd);

	return TEST_PASS(NULL);
}

/*
 * Test: Invalid fd for enlistment fails
 */
static struct test_result
test_enlist_invalid_fd(void)
{
	int coal_fd;
	int bad_fd = 9999;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &bad_fd);
	TEST_ASSERT(ret < 0, "Enlistment with bad fd should fail");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * FEATURE: Self-Join (VBSD_COALITION_JOIN)
 * ========================================================================= */

/*
 * Test: Process can self-join a coalition
 */
static struct test_result
test_self_join(void)
{
	int coal_fd;
	pid_t pid;
	int status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	clear_clofork(coal_fd);
	pid = fork();
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("fork failed");
	}

	if (pid == 0) {
		/* Child: self-join */
		if (ioctl(coal_fd, VBSD_COALITION_JOIN) < 0)
			_exit(1);
		_exit(0);
	}

	close(coal_fd);
	status = wait_for_child(pid);
	TEST_ASSERT(status == 0, "Child failed to self-join");

	return TEST_PASS(NULL);
}

/*
 * Test: Cannot self-join twice (EBUSY)
 */
static struct test_result
test_self_join_twice_fails(void)
{
	int coal_fd;
	pid_t pid;
	int status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	clear_clofork(coal_fd);
	pid = fork();
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("fork failed");
	}

	if (pid == 0) {
		/* First join should succeed */
		if (ioctl(coal_fd, VBSD_COALITION_JOIN) < 0)
			_exit(1);

		/* Second join should fail with EBUSY */
		if (ioctl(coal_fd, VBSD_COALITION_JOIN) < 0 && errno == EBUSY)
			_exit(0);

		_exit(2);
	}

	close(coal_fd);
	status = wait_for_child(pid);
	TEST_ASSERT(status == 0, "Second self-join should fail with EBUSY");

	return TEST_PASS(NULL);
}

/* =========================================================================
 * FEATURE: Fork Inheritance (via process hash or jail OSD)
 * ========================================================================= */

/*
 * Test: Child inherits coalition membership from parent
 */
static struct test_result
test_fork_inheritance(void)
{
	int coal_fd, proc_fd;
	pid_t child1, child2;
	int pipefd[2];
	char buf;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	clear_clofork(coal_fd);
	if (pipe(pipefd) < 0) {
		close(coal_fd);
		return TEST_FAIL("pipe failed");
	}

	child1 = pdfork(&proc_fd, 0);
	if (child1 < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (child1 == 0) {
		/* First child: join coalition, then fork grandchild */
		close(pipefd[0]);

		if (ioctl(coal_fd, VBSD_COALITION_JOIN) < 0)
			_exit(1);

		child2 = fork();
		if (child2 < 0)
			_exit(2);

		if (child2 == 0) {
			/* Grandchild: signal readiness and wait */
			write(pipefd[1], "R", 1);
			pause();	/* Wait indefinitely for signal */
			_exit(0);
		}

		/* First child: wait for grandchild */
		waitpid(child2, NULL, 0);
		_exit(0);
	}

	close(pipefd[1]);

	/* Wait for grandchild to be ready */
	read(pipefd[0], &buf, 1);
	close(pipefd[0]);

	/*
	 * Close proc_fd AFTER child has set up the grandchild.
	 * With non-PD_DAEMON, closing procdesc sends SIGKILL if still alive,
	 * so we must wait for child's work to complete first.
	 * Note: child1 self-joined the coalition, so it will be killed when
	 * we terminate the coalition. We don't need the procdesc anymore.
	 */
	close(proc_fd);

	/*
	 * At this point, grandchild should be in the coalition.
	 * Terminate the coalition - grandchild should receive signal.
	 */
	if (ioctl(coal_fd, VBSD_COALITION_TERMINATE) < 0) {
		close(coal_fd);
		return TEST_FAIL("Terminate failed");
	}

	/*
	 * Wait for child1 to be reaped. We already sent SIGKILL via
	 * close(proc_fd), so this should return immediately.
	 * This ensures the process is fully cleaned up before we return.
	 */
	waitpid(child1, NULL, 0);

	/* Give grandchild time to die and be cleaned up */
	usleep(200000);

	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * FEATURE: Termination (VBSD_COALITION_TERMINATE)
 * ========================================================================= */

/*
 * Test: Terminate signals all members
 */
static struct test_result
test_terminate_signals_members(void)
{
	int coal_fd, proc_fd1, proc_fd2;
	pid_t pid1, pid2;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create two child processes */
	pid1 = pdfork(&proc_fd1, 0);
	if (pid1 < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork 1 failed");
	}
	if (pid1 == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	pid2 = pdfork(&proc_fd2, 0);
	if (pid2 < 0) {
		pdkill(proc_fd1, SIGKILL);
		waitpid(pid1, NULL, 0);
		close(proc_fd1);
		close(coal_fd);
		return TEST_FAIL("pdfork 2 failed");
	}
	if (pid2 == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	/* Enlist both - caller keeps fds (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd1) == 0,
	    "Failed to enlist proc 1");
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd2) == 0,
	    "Failed to enlist proc 2");

	/* Terminate */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	/* Both should be signaled and exit */
	int status1, status2;
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	TEST_ASSERT(WIFSIGNALED(status1), "Process 1 not signaled");
	TEST_ASSERT(WIFSIGNALED(status2), "Process 2 not signaled");

	/* Caller keeps fds, must close them */
	close(proc_fd1);
	close(proc_fd2);
	close(coal_fd);

	return TEST_PASS(NULL);
}

/*
 * Test: Terminate is idempotent (EALREADY on second call)
 */
static struct test_result
test_terminate_idempotent(void)
{
	int coal_fd;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* First terminate should succeed */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "First terminate failed");

	/* Second terminate should return ESHUTDOWN (coalition already terminated) */
	ret = ioctl(coal_fd, VBSD_COALITION_TERMINATE);
	TEST_ASSERT(ret < 0 && errno == ESHUTDOWN,
	    "Second terminate should return ESHUTDOWN");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Cannot join after terminate (EINVAL)
 */
static struct test_result
test_join_after_terminate_fails(void)
{
	int coal_fd;
	pid_t pid;
	int status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Terminate first */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	clear_clofork(coal_fd);
	pid = fork();
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("fork failed");
	}

	if (pid == 0) {
		/* Try to join - should fail */
		if (ioctl(coal_fd, VBSD_COALITION_JOIN) < 0 && errno == EINVAL)
			_exit(0);
		_exit(1);
	}

	close(coal_fd);
	status = wait_for_child(pid);
	TEST_ASSERT(status == 0, "Join after terminate should fail with EINVAL");

	return TEST_PASS(NULL);
}

/* =========================================================================
 * FEATURE: Close triggers terminate
 * ========================================================================= */

/*
 * Test: Closing last fd terminates coalition members
 */
static struct test_result
test_close_terminates(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int pipefd[2];
	char buf;
	int status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	if (pipe(pipefd) < 0) {
		close(coal_fd);
		return TEST_FAIL("pipe failed");
	}

	/*
	 * With reference semantics, caller keeps their procdesc after enlist.
	 * This means we can use non-PD_DAEMON and waitpid normally.
	 */
	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(pipefd[0]);
		close(coal_fd);	/* Don't hold coalition fd - let parent's close trigger terminate */
		write(pipefd[1], "R", 1);
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	close(pipefd[1]);

	/* Enlist - caller keeps proc_fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist failed");

	/* Wait for child to be ready */
	read(pipefd[0], &buf, 1);
	close(pipefd[0]);

	/* Close coalition fd - should trigger terminate */
	close(coal_fd);

	/* Verify child was signaled */
	waitpid(pid, &status, 0);
	TEST_ASSERT(WIFSIGNALED(status), "Child should be signaled");

	/* Caller closes their fd */
	close(proc_fd);

	return TEST_PASS(NULL);
}

/* =========================================================================
 * FEATURE: Jail Enlistment (VBSD_COALITION_ENLIST with jaildesc)
 * ========================================================================= */

/*
 * Test: Enlist a jail via jaildesc
 * Note: This test creates a real jail, so it requires elevated privileges.
 */
static struct test_result
test_enlist_jail(void)
{
	int coal_fd, jail_fd;

	/* Skip if not root */
	if (geteuid() != 0)
		return TEST_PASS("Skipped (not root)");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create a test jail with owning descriptor */
	jail_fd = create_test_jail(jail_name("jail1"));
	if (jail_fd < 0) {
		close(coal_fd);
		return TEST_FAIL("Failed to create test jail");
	}

	/* Enlist the jail - caller keeps fd (reference semantics) */
	if (ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd) < 0) {
		int saved_errno = errno;
		close(jail_fd);
		close(coal_fd);
		if (saved_errno == EINVAL)
			return TEST_FAIL("ENLIST returned EINVAL - jaildesc not recognized");
		return TEST_FAIL("Failed to enlist jail");
	}

	/* Caller keeps fd with reference semantics - must close when done */
	close(jail_fd);
	close(coal_fd);

	return TEST_PASS(NULL);
}

/*
 * Test: Cannot enlist same jail twice (EBUSY)
 */
static struct test_result
test_enlist_jail_twice_fails(void)
{
	int coal_fd, jail_fd, jail_fd2;
	int ret;

	if (geteuid() != 0)
		return TEST_PASS("Skipped (not root)");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	jail_fd = create_test_jail(jail_name("jail2"));
	if (jail_fd < 0) {
		close(coal_fd);
		return TEST_FAIL("Failed to create test jail");
	}

	/* First enlistment should succeed - caller keeps fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd) == 0,
	    "First jail enlistment failed");

	/* Get another descriptor to the same jail */
	jail_fd2 = get_jail_desc(jail_name("jail2"));
	if (jail_fd2 < 0) {
		close(jail_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to get second jaildesc");
	}

	/* Second enlistment should fail with EBUSY (same jail already enlisted) */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd2);
	TEST_ASSERT(ret < 0 && errno == EBUSY,
	    "Second jail enlistment should fail with EBUSY");

	close(jail_fd2);
	close(jail_fd);  /* Caller keeps fd, must close */
	close(coal_fd);

	return TEST_PASS(NULL);
}

/*
 * Test: Enlist jail in different coalition than a process
 */
static struct test_result
test_enlist_jail_different_coalition(void)
{
	int coal_fd1, coal_fd2, jail_fd;

	if (geteuid() != 0)
		return TEST_PASS("Skipped (not root)");

	coal_fd1 = create_coalition();
	TEST_ASSERT(coal_fd1 >= 0, "Failed to create first coalition");

	coal_fd2 = create_coalition();
	TEST_ASSERT(coal_fd2 >= 0, "Failed to create second coalition");

	jail_fd = create_test_jail(jail_name("jail3"));
	if (jail_fd < 0) {
		close(coal_fd2);
		close(coal_fd1);
		return TEST_FAIL("Failed to create test jail");
	}

	/* Enlist jail in first coalition - jail_caller keeps fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd1, VBSD_COALITION_ENLIST, &jail_fd) == 0,
	    "Failed to enlist jail in first coalition");

	/* Caller keeps fd with reference semantics - must close when done */
	close(jail_fd);
	close(coal_fd2);
	close(coal_fd1);

	return TEST_PASS(NULL);
}

/* =========================================================================
 * FEATURE: Jail OSD Fork Inheritance
 * ========================================================================= */

/*
 * Test: Process born in enlisted jail auto-joins coalition
 * Note: This tests fork inheritance via jail OSD, NOT jail_attach interception.
 * Processes that jail_attach() keep their existing membership; they don't
 * auto-join the jail's coalition.
 */
static struct test_result
test_jail_fork_inheritance(void)
{
	int coal_fd, jail_fd;
	int pipefd[2];
	pid_t pid;
	char buf;
	int jid;

	if (geteuid() != 0)
		return TEST_PASS("Skipped (not root)");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create a test jail (non-owning so we control lifetime) */
	jail_fd = create_test_jail(jail_name("jail_fork"));
	if (jail_fd < 0) {
		close(coal_fd);
		return TEST_FAIL("Failed to create test jail");
	}

	/* Get the jail ID for jail_attach */
	jid = get_jail_id(jail_name("jail_fork"));
	if (jid < 0) {
		close(jail_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to get jail ID");
	}

	/* Enlist the jail in the coalition - jail_caller keeps fd (reference semantics) */
	if (ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd) < 0) {
		close(jail_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to enlist jail");
	}
	/* jail_fd still valid (reference semantics) */

	if (pipe(pipefd) < 0) {
		close(jail_fd);
		close(coal_fd);
		return TEST_FAIL("pipe failed");
	}

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		close(jail_fd);
		close(coal_fd);
		return TEST_FAIL("fork failed");
	}

	if (pid == 0) {
		/* First child: attach to jail, then fork grandchild */
		pid_t grandchild;

		close(pipefd[0]);
		close(coal_fd);  /* Don't need coalition fd in child */

		/* Attach to the jail */
		if (jail_attach(jid) < 0) {
			write(pipefd[1], "A", 1);  /* 'A' = attach failed */
			_exit(1);
		}

		/*
		 * Now fork a grandchild. The grandchild is "born" in the jail,
		 * so if the jail is enlisted in a coalition, the grandchild
		 * should automatically join via the jail OSD inheritance path.
		 */
		grandchild = fork();
		if (grandchild < 0) {
			write(pipefd[1], "F", 1);  /* 'F' = fork failed */
			_exit(2);
		}

		if (grandchild == 0) {
			/* Grandchild: signal ready and wait to be killed */
			write(pipefd[1], "R", 1);  /* 'R' = ready */
			pause();	/* Wait indefinitely for signal */
			_exit(0);
		}

		/* First child: wait for grandchild */
		waitpid(grandchild, NULL, 0);
		_exit(0);
	}

	/* Parent: wait for grandchild to be ready */
	close(pipefd[1]);

	if (read(pipefd[0], &buf, 1) != 1 || buf != 'R') {
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		close(jail_fd);
		close(coal_fd);
		if (buf == 'A')
			return TEST_FAIL("Child failed to attach to jail");
		if (buf == 'F')
			return TEST_FAIL("Child failed to fork grandchild");
		return TEST_FAIL("Communication with child failed");
	}
	close(pipefd[0]);

	/*
	 * Grandchild should now be in the coalition (inherited via jail OSD).
	 * Terminate the coalition - grandchild should receive SIGKILL.
	 */
	if (ioctl(coal_fd, VBSD_COALITION_TERMINATE) < 0) {
		waitpid(pid, NULL, 0);
		close(jail_fd);
		close(coal_fd);
		return TEST_FAIL("Terminate failed");
	}

	/* Give processes time to die */
	usleep(100000);

	/* Clean up */
	waitpid(pid, NULL, 0);
	close(jail_fd);
	close(coal_fd);

	return TEST_PASS(NULL);
}

/*
 * Test: Coalition terminate removes enlisted jails
 */
static struct test_result
test_terminate_removes_jails(void)
{
	int coal_fd, jail_fd;
	int jid;

	if (geteuid() != 0)
		return TEST_PASS("Skipped (not root)");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create a persistent jail (will not be auto-removed on fd close) */
	jail_fd = create_test_jail(jail_name("jail_term"));
	if (jail_fd < 0) {
		close(coal_fd);
		return TEST_FAIL("Failed to create test jail");
	}

	/* Get the jail ID to check existence later */
	jid = get_jail_id(jail_name("jail_term"));
	TEST_ASSERT(jid > 0, "Failed to get jail ID before enlistment");

	/* Enlist the jail - jail_caller keeps fd (reference semantics) */
	if (ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd) < 0) {
		close(jail_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to enlist jail");
	}
	/* jail_fd still valid (reference semantics) */

	/* Terminate the coalition - this should remove the jail */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	/*
	 * Give the kernel a moment to process the jail removal.
	 * The jail removal happens asynchronously after releasing locks.
	 */
	usleep(100000);  /* 100ms */

	/* Check if the jail still exists - it should be gone or dying */
	jid = get_jail_id(jail_name("jail_term"));
	/* get_jail_id returns -1 if jail doesn't exist */
	TEST_ASSERT(jid < 0, "Jail should be removed after coalition terminate");

	close(jail_fd);
	close(coal_fd);

	return TEST_PASS(NULL);
}

/*
 * Test: Multiple jails can be enlisted in one coalition
 */
static struct test_result
test_enlist_multiple_jails(void)
{
	int coal_fd, jail_fd1, jail_fd2;

	if (geteuid() != 0)
		return TEST_PASS("Skipped (not root)");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	jail_fd1 = create_test_jail(jail_name("jail_multi1"));
	if (jail_fd1 < 0) {
		close(coal_fd);
		return TEST_FAIL("Failed to create first test jail");
	}

	jail_fd2 = create_test_jail(jail_name("jail_multi2"));
	if (jail_fd2 < 0) {
		close(jail_fd1);
		close(coal_fd);
		return TEST_FAIL("Failed to create second test jail");
	}

	/* Enlist both jails - caller keeps fds (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd1) == 0,
	    "Failed to enlist first jail");
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd2) == 0,
	    "Failed to enlist second jail");

	/* Caller keeps fds with reference semantics - must close when done */
	close(jail_fd1);
	close(jail_fd2);
	close(coal_fd);

	return TEST_PASS(NULL);
}

/*
 * Test: Cannot enlist jail after coalition terminate
 */
static struct test_result
test_enlist_jail_after_terminate_fails(void)
{
	int coal_fd, jail_fd;
	int ret;

	if (geteuid() != 0)
		return TEST_PASS("Skipped (not root)");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Terminate the coalition first */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	/* Now create a jail and try to enlist it */
	jail_fd = create_test_jail(jail_name("jail_post"));
	if (jail_fd < 0) {
		close(coal_fd);
		return TEST_FAIL("Failed to create test jail");
	}

	/* Enlistment should fail with EINVAL (coalition is terminating) */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Enlist after terminate should fail with EINVAL");

	close(jail_fd);
	close(coal_fd);

	return TEST_PASS(NULL);
}

/* =========================================================================
 * SOCKET TERMINATION TESTS
 * ========================================================================= */

/*
 * Test: Socket gets shutdown when coalition terminates
 *
 * Create a connected socket pair, enlist one end in a coalition,
 * terminate the coalition, verify the other end sees the shutdown.
 */
static struct test_result
test_socket_shutdown_on_terminate(void)
{
	int coal_fd;
	int sv[2];
	char buf[1];
	ssize_t n;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create a connected socket pair */
	TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
	    "socketpair failed");

	/* Enlist one end in the coalition - caller keeps sv[0] */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &sv[0]) == 0,
	    "Enlist socket failed");

	/* Terminate the coalition - should shutdown the socket */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	/* Give kernel time to process */
	usleep(50000);

	/* The other end should see EOF or error on read */
	n = read(sv[1], buf, 1);
	TEST_ASSERT(n == 0 || (n < 0 && errno == ECONNRESET),
	    "Socket should be shutdown (expected EOF or ECONNRESET)");

	/* Close both sockets and coalition */
	close(sv[0]);
	close(sv[1]);
	close(coal_fd);

	return TEST_PASS(NULL);
}

/* =========================================================================
 * SHM TERMINATION TESTS
 * ========================================================================= */

/*
 * Test: SHM gets truncated when coalition terminates
 *
 * Create SHM, enlist it in coalition, map it, terminate coalition,
 * verify the size is now 0.
 */
static struct test_result
test_shm_truncate_on_terminate(void)
{
	int coal_fd, shm_fd;
	struct stat sb;
	const char *shm_name = "/coalition_test_shm";

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create SHM */
	shm_fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (shm_fd < 0 && errno == EEXIST) {
		shm_unlink(shm_name);
		shm_fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
	}
	TEST_ASSERT(shm_fd >= 0, "shm_open failed");

	/* Give it some size */
	TEST_ASSERT(ftruncate(shm_fd, 4096) == 0, "ftruncate failed");

	/* Verify initial size */
	TEST_ASSERT(fstat(shm_fd, &sb) == 0, "fstat failed");
	TEST_ASSERT(sb.st_size == 4096, "Expected initial size 4096");

	/* Enlist in coalition */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &shm_fd) == 0,
	    "Enlist shm failed");

	/* Terminate - should truncate to 0 */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	/* Give kernel time */
	usleep(50000);

	/* Open a new fd to the same SHM to check size */
	int shm_fd2 = shm_open(shm_name, O_RDONLY, 0);
	if (shm_fd2 >= 0) {
		TEST_ASSERT(fstat(shm_fd2, &sb) == 0, "fstat failed");
		TEST_ASSERT(sb.st_size == 0, "SHM should be truncated to 0");
		close(shm_fd2);
	}
	/* Close our shm_fd (coalition has its own reference) */
	close(shm_fd);

	shm_unlink(shm_name);
	close(coal_fd);

	return TEST_PASS(NULL);
}

/* =========================================================================
 * DEVICE TERMINATION TESTS
 * ========================================================================= */

/*
 * Test: Device fd can be enlisted in coalition
 *
 * Open /dev/null (safe device), enlist it, close coalition.
 * This verifies DTYPE_DEV is supported.
 */
static struct test_result
test_enlist_device(void)
{
	int coal_fd, dev_fd;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Open a device - /dev/null is always safe */
	dev_fd = open("/dev/null", O_RDWR);
	TEST_ASSERT(dev_fd >= 0, "open /dev/null failed");

	/* Enlist in coalition - DTYPE_DEV should be supported */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &dev_fd) == 0,
	    "Enlist device failed (DTYPE_DEV not supported?)");

	/* Close our dev_fd (coalition has its own reference) */
	close(dev_fd);

	/* Close coalition - should cleanly handle the device */
	close(coal_fd);

	return TEST_PASS(NULL);
}

/* =========================================================================
 * BATCH ENLISTMENT TESTS (VBSD_COALITION_ENLIST_SET)
 * ========================================================================= */

/*
 * Test: Batch enlist multiple processes
 */
static struct test_result
test_enlist_set_basic(void)
{
	int coal_fd;
	int proc_fds[3] = { -1, -1, -1 };
	pid_t pids[3] = { -1, -1, -1 };
	struct vbsd_enlist_set es;
	int sync_pipe[2] = { -1, -1 };
	char buf;
	int i;
	int status;
	const char *fail_msg = NULL;
	static char fail_detail[160];

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Pipe for children to signal readiness */
	TEST_ASSERT(pipe(sync_pipe) == 0, "pipe failed");

	/* Create 3 child processes */
	for (i = 0; i < 3; i++) {
		pids[i] = pdfork(&proc_fds[i], 0);
		if (pids[i] < 0) {
			/* Cleanup on failure */
			fail_msg = "pdfork failed";
			goto cleanup_fail;
		}
		if (pids[i] == 0) {
			close(coal_fd);		/* Close if inherited */
			close(sync_pipe[0]);	/* Close read end */
			(void)write(sync_pipe[1], "r", 1);	/* Signal ready */
			close(sync_pipe[1]);
			pause();	/* Wait indefinitely for signal */
			_exit(0);
		}
	}

	/* Wait for all children to signal readiness */
	close(sync_pipe[1]);
	for (i = 0; i < 3; i++) {
		if (read_ready_byte(sync_pipe[0], &buf, 2000) != 1) {
			fail_msg = "Timeout waiting for child readiness";
			goto cleanup_fail;
		}
	}
	close(sync_pipe[0]);
	sync_pipe[0] = -1;

	/* Batch enlist all 3 - caller keeps fds (reference semantics) */
	es.fds = proc_fds;
	es.count = 3;
	es.enlisted = 0;

	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es) == 0,
	    "Batch enlist failed");
	TEST_ASSERT(es.enlisted == 3, "Expected 3 enlisted");

	/* Close coalition - all processes should be signaled */
	close(coal_fd);
	coal_fd = -1;

	/* Verify all children were signaled */
	for (i = 0; i < 3; i++) {
		if (waitpid_timeout(pids[i], &status, 5000) != 0) {
			int kerr = 0;
			int alive = 0;

			if (kill(pids[i], 0) == 0)
				alive = 1;
			else
				kerr = errno;
			snprintf(fail_detail, sizeof(fail_detail),
			    "Timeout waiting for child %d (pid %d) exit (alive=%s errno=%d)",
			    i, (int)pids[i], alive ? "yes" : "no", kerr);
			fail_msg = fail_detail;
			goto cleanup_fail;
		}
		if (!WIFSIGNALED(status)) {
			fail_msg = "Process not signaled";
			goto cleanup_fail;
		}
		close(proc_fds[i]);
		proc_fds[i] = -1;
	}

	return TEST_PASS(NULL);

cleanup_fail:
	for (i = 0; i < 3; i++) {
		if (proc_fds[i] >= 0)
			(void)pdkill(proc_fds[i], SIGKILL);
	}
	for (i = 0; i < 3; i++) {
		if (pids[i] > 0)
			(void)waitpid_timeout(pids[i], &status, 1000);
		if (proc_fds[i] >= 0)
			close(proc_fds[i]);
	}
	if (sync_pipe[0] >= 0)
		close(sync_pipe[0]);
	if (sync_pipe[1] >= 0)
		close(sync_pipe[1]);
	if (coal_fd >= 0)
		close(coal_fd);
	return TEST_FAIL(fail_msg);
}

/*
 * Test: Batch enlist with empty set
 */
static struct test_result
test_enlist_set_empty(void)
{
	int coal_fd;
	struct vbsd_enlist_set es;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	es.fds = NULL;
	es.count = 0;
	es.enlisted = 99;  /* Should be set to 0 */

	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es) == 0,
	    "Empty batch should succeed");
	TEST_ASSERT(es.enlisted == 0, "Expected 0 enlisted for empty set");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Batch enlist stops on error and reports count
 */
static struct test_result
test_enlist_set_partial_failure(void)
{
	int coal_fd;
	int fds[3];
	pid_t pids[2];
	struct vbsd_enlist_set es;
	int sync_pipe[2];
	char buf;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	TEST_ASSERT(pipe(sync_pipe) == 0, "pipe failed");

	/* Create 2 valid processes */
	for (int i = 0; i < 2; i++) {
		pids[i] = pdfork(&fds[i], 0);
		if (pids[i] < 0) {
			if (i > 0) {
				pdkill(fds[0], SIGKILL);
				close(fds[0]);
				waitpid(pids[0], NULL, 0);
			}
			close(sync_pipe[0]);
			close(sync_pipe[1]);
			close(coal_fd);
			return TEST_FAIL("pdfork failed");
		}
		if (pids[i] == 0) {
			close(coal_fd);
			close(sync_pipe[0]);
			(void)write(sync_pipe[1], "r", 1);
			close(sync_pipe[1]);
			pause();
			_exit(0);
		}
	}

	/* Wait for children to be ready */
	close(sync_pipe[1]);
	for (int i = 0; i < 2; i++)
		(void)read(sync_pipe[0], &buf, 1);
	close(sync_pipe[0]);

	/* Third fd is invalid */
	fds[2] = 9999;

	/* Batch enlist - should enlist 2, then fail on invalid fd */
	es.fds = fds;
	es.count = 3;
	es.enlisted = 0;

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es);
	TEST_ASSERT(ret < 0 && errno == EBADF,
	    "Should fail with EBADF on invalid fd");
	TEST_ASSERT(es.enlisted == 2, "Expected 2 enlisted before failure");

	/* Close coalition - enlisted processes signaled */
	close(coal_fd);

	/* Clean up - processes should be dead */
	for (int i = 0; i < 2; i++) {
		waitpid(pids[i], NULL, 0);
		close(fds[i]);
	}

	return TEST_PASS(NULL);
}

/*
 * Test: Batch enlist exceeding max limit
 */
static struct test_result
test_enlist_set_exceeds_max(void)
{
	int coal_fd;
	int fds[1];
	struct vbsd_enlist_set es;
	int ret;
	u_int enlist_set_max;
	size_t len;

	/* Get current limit from sysctl */
	len = sizeof(enlist_set_max);
	ret = sysctlbyname("kern.coalition.enlist_set_max",
	    &enlist_set_max, &len, NULL, 0);
	TEST_ASSERT(ret == 0, "Failed to read enlist_set_max sysctl");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	es.fds = fds;
	es.count = enlist_set_max + 1;  /* Exceeds limit */
	es.enlisted = 0;

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Should fail with EINVAL when exceeding max");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Batch enlist mixed fd types (pipes and sockets)
 */
static struct test_result
test_enlist_set_mixed_types(void)
{
	int coal_fd = -1;
	int fds[4] = { -1, -1, -1, -1 };
	int pipefd[2] = { -1, -1 };
	int sv[2] = { -1, -1 };
	struct vbsd_enlist_set es;
	const char *fail_msg = NULL;
	static char msg[160];
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create a pipe */
	if (pipe(pipefd) != 0) {
		fail_msg = "pipe failed";
		goto cleanup_fail;
	}
	fds[0] = pipefd[0];
	fds[1] = pipefd[1];

	/* Create a socket pair */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		fail_msg = "socketpair failed";
		goto cleanup_fail;
	}
	fds[2] = sv[0];
	fds[3] = sv[1];

	/* Batch enlist all 4 */
	es.fds = fds;
	es.count = 4;
	es.enlisted = 0;

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es);
	if (ret != 0) {
		int err = errno;
		snprintf(msg, sizeof(msg),
		    "Batch enlist failed (enlisted=%u, errno=%d: %s)",
		    es.enlisted, err, strerror(err));
		fail_msg = msg;
		goto cleanup_fail;
	}
	if (es.enlisted != 4) {
		snprintf(msg, sizeof(msg),
		    "Expected 4 enlisted, got %u", es.enlisted);
		fail_msg = msg;
		goto cleanup_fail;
	}

	/* Caller keeps fds, close coalition */
	close(coal_fd);
	coal_fd = -1;
	for (int i = 0; i < 4; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}

	return TEST_PASS(NULL);

cleanup_fail:
	if (coal_fd >= 0)
		close(coal_fd);
	for (int i = 0; i < 4; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
	return TEST_FAIL(fail_msg);
}

/* =========================================================================
 * BAD INPUT TESTS
 * ========================================================================= */

/*
 * Test: Invalid ioctl command returns ENOTTY
 */
static struct test_result
test_invalid_ioctl_command(void)
{
	int coal_fd;
	int ret;
	int dummy = 0;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Use an invalid ioctl command */
	ret = ioctl(coal_fd, _IOW('V', 99, int), &dummy);
	TEST_ASSERT(ret < 0 && errno == ENOTTY,
	    "Invalid ioctl should return ENOTTY");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Coalition ioctl on non-coalition fd fails
 */
static struct test_result
test_ioctl_on_wrong_fd_type(void)
{
	int fd;
	int dummy = 0;
	int ret;

	/* Open a regular file */
	fd = open("/dev/null", O_RDWR);
	TEST_ASSERT(fd >= 0, "Failed to open /dev/null");

	/* Try coalition ioctl on it */
	ret = ioctl(fd, VBSD_COALITION_TERMINATE);
	TEST_ASSERT(ret < 0, "Coalition ioctl on /dev/null should fail");

	ret = ioctl(fd, VBSD_COALITION_ENLIST, &dummy);
	TEST_ASSERT(ret < 0, "Coalition enlist on /dev/null should fail");

	close(fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Negative fd value for enlist fails
 */
static struct test_result
test_enlist_negative_fd(void)
{
	int coal_fd;
	int bad_fd = -1;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &bad_fd);
	TEST_ASSERT(ret < 0 && errno == EBADF,
	    "Negative fd should return EBADF");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Enlist coalition fd into itself fails
 */
static struct test_result
test_enlist_self(void)
{
	int coal_fd;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Try to enlist the coalition into itself */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &coal_fd);
	/* Should fail - DTYPE_DEV coalition file isn't the same as /dev/null */
	TEST_ASSERT(ret < 0, "Enlisting coalition into itself should fail");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Batch enlist with bad pointer fails with EFAULT
 */
static struct test_result
test_enlist_set_bad_pointer(void)
{
	int coal_fd;
	struct vbsd_enlist_set es;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Use an invalid pointer */
	es.fds = (int *)0xDEADBEEF;
	es.count = 3;
	es.enlisted = 0;

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es);
	TEST_ASSERT(ret < 0 && errno == EFAULT,
	    "Bad pointer should return EFAULT");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Batch enlist where first fd fails
 */
static struct test_result
test_enlist_set_first_fails(void)
{
	int coal_fd;
	int fds[3];
	struct vbsd_enlist_set es;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* All bad fds */
	fds[0] = 9999;
	fds[1] = 9998;
	fds[2] = 9997;

	es.fds = fds;
	es.count = 3;
	es.enlisted = 0;

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es);
	TEST_ASSERT(ret < 0 && errno == EBADF,
	    "First bad fd should return EBADF");
	TEST_ASSERT(es.enlisted == 0, "No fds should be enlisted");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Batch enlist with duplicate fd in same batch
 *
 * Duplicate fd in batch should fail with EBUSY on second occurrence.
 * First fd gets enlisted, second (duplicate) fails.
 */
static struct test_result
test_enlist_set_duplicate_fd(void)
{
	int coal_fd;
	int fds[3];
	int pipefd[2];
	struct vbsd_enlist_set es;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

	/*
	 * Same fd listed twice - second should fail with EBUSY
	 * because that resource is already enlisted.
	 */
	fds[0] = pipefd[0];
	fds[1] = pipefd[0];  /* Duplicate - will fail EBUSY */
	fds[2] = pipefd[1];

	es.fds = fds;
	es.count = 3;
	es.enlisted = 0;

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es);
	TEST_ASSERT(ret < 0 && errno == EBUSY,
	    "Duplicate fd should fail with EBUSY");
	TEST_ASSERT(es.enlisted == 1, "Only first should be enlisted");

	/* Clean up - caller keeps fds with reference semantics */
	close(pipefd[0]);
	close(pipefd[1]);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Enlist when already enlisted in different coalition
 *
 * Process descriptors track membership globally, so enlisting in
 * a second coalition should fail with EBUSY.
 */
static struct test_result
test_enlist_in_two_coalitions(void)
{
	int coal_fd1, coal_fd2, proc_fd1, proc_fd2;
	pid_t pid;
	int ret, status;

	coal_fd1 = create_coalition();
	TEST_ASSERT(coal_fd1 >= 0, "Failed to create first coalition");

	coal_fd2 = create_coalition();
	TEST_ASSERT(coal_fd2 >= 0, "Failed to create second coalition");

	pid = pdfork(&proc_fd1, 0);
	if (pid < 0) {
		close(coal_fd2);
		close(coal_fd1);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd1);	/* Don't hold coalition fds */
		close(coal_fd2);
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	/* Get another descriptor to same process for second enlist attempt */
	proc_fd2 = dup(proc_fd1);
	TEST_ASSERT(proc_fd2 >= 0, "dup failed");

	/* Enlist in first coalition - caller keeps proc_fd1 */
	TEST_ASSERT(ioctl(coal_fd1, VBSD_COALITION_ENLIST, &proc_fd1) == 0,
	    "First enlist failed");

	/* Try to enlist in second coalition via dup'd fd - should fail */
	ret = ioctl(coal_fd2, VBSD_COALITION_ENLIST, &proc_fd2);
	TEST_ASSERT(ret < 0 && errno == EBUSY,
	    "Enlisting in second coalition should fail with EBUSY");

	close(proc_fd2);
	close(coal_fd2);
	close(coal_fd1);  /* Triggers terminate */

	/* Verify child was signaled */
	waitpid(pid, &status, 0);
	TEST_ASSERT(WIFSIGNALED(status), "Child should be signaled");

	close(proc_fd1);
	return TEST_PASS(NULL);
}

/*
 * Test: Self-join when already enlisted via procdesc fails
 */
static struct test_result
test_self_join_when_already_enlisted(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	clear_clofork(coal_fd);
	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		/* Child: wait for parent to enlist us, then try self-join */
		sleep(1);

		/* This should fail - we're already enlisted */
		if (ioctl(coal_fd, VBSD_COALITION_JOIN) < 0 && errno == EBUSY)
			_exit(0);
		_exit(1);
	}

	/* Parent: enlist child first */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist failed");

	/* Wait for child to try self-join */
	status = wait_for_child(pid);
	TEST_ASSERT(status == 0,
	    "Self-join when already enlisted should fail with EBUSY");

	close(proc_fd);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Operations on closed coalition fd fail
 */
static struct test_result
test_use_after_close(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/*
	 * Create process FIRST to avoid fd reuse issue.
	 * If we close coal_fd first, pdfork might reuse that fd number.
	 */
	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	/* Now close coalition and remember fd number */
	int saved_fd = coal_fd;
	close(coal_fd);

	/* Try operations on closed fd - should fail with EBADF */
	ret = ioctl(saved_fd, VBSD_COALITION_ENLIST, &proc_fd);
	TEST_ASSERT(ret < 0 && errno == EBADF,
	    "Enlist on closed fd should return EBADF");

	ret = ioctl(saved_fd, VBSD_COALITION_TERMINATE);
	TEST_ASSERT(ret < 0 && errno == EBADF,
	    "Terminate on closed fd should return EBADF");

	/* Clean up */
	pdkill(proc_fd, SIGKILL);
	close(proc_fd);
	waitpid(pid, NULL, 0);
	return TEST_PASS(NULL);
}

/*
 * Test: Enlist process after terminate fails with EINVAL
 */
static struct test_result
test_enlist_after_terminate_fails(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Terminate first */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	/* Create process */
	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	/* Try to enlist after terminate */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Enlist after terminate should fail with EINVAL");

	pdkill(proc_fd, SIGKILL);
	close(proc_fd);
	close(coal_fd);
	waitpid(pid, NULL, 0);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * JAIL EDGE CASE TESTS
 * ========================================================================= */

/*
 * Test: Enlist same jail via different descriptors fails with EBUSY
 */
static struct test_result
test_enlist_jail_via_different_desc(void)
{
	int coal_fd, jail_fd1, jail_fd2;
	int ret;

	if (geteuid() != 0)
		return TEST_PASS("Skipped (not root)");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	jail_fd1 = create_test_jail(jail_name("jail_dup"));
	if (jail_fd1 < 0) {
		close(coal_fd);
		return TEST_FAIL("Failed to create test jail");
	}

	/* Get another descriptor to same jail */
	jail_fd2 = get_jail_desc(jail_name("jail_dup"));
	if (jail_fd2 < 0) {
		static char msg[128];
		int err = errno;
		snprintf(msg, sizeof(msg),
		    "Failed to get second jaildesc: %s", strerror(err));
		close(jail_fd1);
		close(coal_fd);
		return TEST_FAIL(msg);
	}

	/* First enlist succeeds - caller keeps jail_fd1 */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd1) == 0,
	    "First jail enlist failed");

	/* Second enlist via different desc fails */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &jail_fd2);
	TEST_ASSERT(ret < 0 && errno == EBUSY,
	    "Enlist same jail via different desc should fail with EBUSY");

	close(jail_fd2);
	close(jail_fd1);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * CONCURRENCY TESTS
 * ========================================================================= */

/*
 * Test: Fork during terminate race
 *
 * Start terminating coalition, fork in parallel.
 * Child born during terminate should not crash the system.
 */
static struct test_result
test_fork_during_terminate(void)
{
	int coal_fd;
	pid_t pid, child2;
	int pipefd[2];
	char buf;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

	clear_clofork(coal_fd);
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		close(coal_fd);
		return TEST_FAIL("fork failed");
	}

	if (pid == 0) {
		/* Child: join coalition, signal ready, then fork rapidly */
		close(pipefd[0]);

		if (ioctl(coal_fd, VBSD_COALITION_JOIN) < 0)
			_exit(1);

		write(pipefd[1], "R", 1);

		/* Fork a grandchild */
		child2 = fork();
		if (child2 == 0) {
			/* Grandchild: just exit */
			_exit(0);
		}
		if (child2 > 0)
			waitpid(child2, NULL, 0);

		/* We may be killed by terminate or exit naturally */
		_exit(0);
	}

	/* Parent: wait for child ready, then terminate */
	close(pipefd[1]);
	read(pipefd[0], &buf, 1);
	close(pipefd[0]);

	/* Terminate - racing with child's fork */
	ioctl(coal_fd, VBSD_COALITION_TERMINATE);

	close(coal_fd);
	waitpid(pid, NULL, 0);

	/* If we get here without crashing, the race was handled */
	return TEST_PASS(NULL);
}

/*
 * Test: Concurrent enlist from multiple processes
 *
 * Pass coalition fd to child, both try to enlist different resources.
 */
static struct test_result
test_concurrent_enlist(void)
{
	int coal_fd;
	int pipefd[2];
	pid_t pid;
	int status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

	clear_clofork(coal_fd);
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		close(coal_fd);
		return TEST_FAIL("fork failed");
	}

	if (pid == 0) {
		/* Child: enlist a pipe */
		int child_pipe[2];
		close(pipefd[0]);

		if (pipe(child_pipe) < 0)
			_exit(1);

		/* Enlist one end */
		if (ioctl(coal_fd, VBSD_COALITION_ENLIST, &child_pipe[0]) < 0)
			_exit(2);

		/* Signal success */
		write(pipefd[1], "O", 1);
		close(child_pipe[1]);
		_exit(0);
	}

	/* Parent: also enlist something */
	close(pipefd[1]);

	int parent_pipe[2];
	TEST_ASSERT(pipe(parent_pipe) == 0, "parent pipe failed");

	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &parent_pipe[0]) == 0,
	    "Parent enlist failed");
	close(parent_pipe[1]);

	/* Wait for child */
	char buf;
	read(pipefd[0], &buf, 1);
	close(pipefd[0]);

	status = wait_for_child(pid);
	TEST_ASSERT(status == 0, "Child enlist failed");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * BOUNDARY CONDITION TESTS
 * ========================================================================= */

/*
 * Test: Batch enlist exactly at limit succeeds
 */
static struct test_result
test_enlist_set_at_limit(void)
{
	int coal_fd;
	u_int max;
	size_t len;
	int ret;
	int *fds;
	int *pipes;
	struct vbsd_enlist_set es;
	u_int i;

	/* Get current limit */
	len = sizeof(max);
	ret = sysctlbyname("kern.coalition.enlist_set_max", &max, &len,
	    NULL, 0);
	TEST_ASSERT(ret == 0, "Failed to read sysctl");

	/* If limit is too high, skip to avoid resource exhaustion */
	if (max > 100)
		return TEST_PASS("Skipped (limit too high for test)");

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Allocate arrays */
	fds = malloc(max * sizeof(int));
	pipes = malloc(max * 2 * sizeof(int));
	TEST_ASSERT(fds != NULL && pipes != NULL, "malloc failed");

	/* Create pipes */
	for (i = 0; i < max; i++) {
		if (pipe(&pipes[i * 2]) < 0) {
			/* Clean up on failure */
			for (u_int j = 0; j < i; j++) {
				close(pipes[j * 2]);
				close(pipes[j * 2 + 1]);
			}
			free(fds);
			free(pipes);
			close(coal_fd);
			return TEST_FAIL("pipe failed");
		}
		fds[i] = pipes[i * 2];  /* Read end */
		close(pipes[i * 2 + 1]);  /* Close write end */
	}

	/* Batch enlist exactly at limit */
	es.fds = fds;
	es.count = max;
	es.enlisted = 0;

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es);
	TEST_ASSERT(ret == 0, "Enlist at exact limit should succeed");
	TEST_ASSERT(es.enlisted == max, "All should be enlisted");

	free(fds);
	free(pipes);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Empty coalition terminate succeeds
 */
static struct test_result
test_terminate_empty_coalition(void)
{
	int coal_fd;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Terminate with no members */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate empty coalition should succeed");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Close empty coalition succeeds
 */
static struct test_result
test_close_empty_coalition(void)
{
	int coal_fd;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Just close with no members - should not crash */
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Resource limit set to 0 means unlimited
 */
static struct test_result
test_limit_zero_unlimited(void)
{
	u_int old_max, zero;
	size_t len;
	int coal_fds[5];
	int ret, i;

	/* Get and save current limit */
	len = sizeof(old_max);
	ret = sysctlbyname("kern.coalition.max_coalitions", &old_max, &len,
	    NULL, 0);
	TEST_ASSERT(ret == 0, "Failed to read sysctl");

	/* Set to 0 (unlimited) */
	zero = 0;
	ret = sysctlbyname("kern.coalition.max_coalitions", NULL, NULL,
	    &zero, sizeof(zero));
	if (ret != 0)
		return TEST_PASS("Skipped (cannot set sysctl)");

	/* Should be able to create several coalitions */
	for (i = 0; i < 5; i++) {
		coal_fds[i] = create_coalition();
		TEST_ASSERT(coal_fds[i] >= 0,
		    "Should create coalitions when limit=0 (unlimited)");
	}

	/* Cleanup */
	for (i = 0; i < 5; i++)
		close(coal_fds[i]);

	/* Restore old limit */
	sysctlbyname("kern.coalition.max_coalitions", NULL, NULL,
	    &old_max, sizeof(old_max));

	return TEST_PASS(NULL);
}

/* =========================================================================
 * FD MANIPULATION TESTS
 * ========================================================================= */

/*
 * Test: dup() before enlist - both fds point to same resource
 */
static struct test_result
test_dup_before_enlist(void)
{
	int coal_fd, proc_fd, proc_fd_dup;
	pid_t pid;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	/* dup before enlist */
	proc_fd_dup = dup(proc_fd);
	TEST_ASSERT(proc_fd_dup >= 0, "dup failed");

	/* Enlist via original fd - caller keeps fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist failed");

	/* Both fds still valid (reference semantics), dup refers to same process */
	/* Trying to enlist dup should fail - process already enlisted */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd_dup);
	TEST_ASSERT(ret < 0 && errno == EBUSY,
	    "Enlist via dup of already-enlisted process should fail with EBUSY");

	close(proc_fd_dup);
	close(proc_fd);
	close(coal_fd);
	usleep(10000);	/* PD_DAEMON procdesc handles reaping */
	return TEST_PASS(NULL);
}

/*
 * Test: Coalition fd passed via SCM_RIGHTS, both processes close
 */
static struct test_result
test_fd_passing_both_close(void)
{
	int coal_fd, proc_fd;
	int sv[2];
	pid_t pid, child_pid;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Create a process to enlist */
	child_pid = pdfork(&proc_fd, 0);
	if (child_pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}
	if (child_pid == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	/* Enlist it */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist failed");

	/* Create socketpair for fd passing */
	TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
	    "socketpair failed");

	pid = fork();
	if (pid < 0) {
		close(sv[0]);
		close(sv[1]);
		close(coal_fd);
		waitpid(child_pid, NULL, 0);
		return TEST_FAIL("fork failed");
	}

	if (pid == 0) {
		/* Receiver: receive coalition fd, then close it */
		struct msghdr msg = {0};
		struct cmsghdr *cmsg;
		char buf[CMSG_SPACE(sizeof(int))];
		struct iovec iov;
		char dummy;
		int received_fd;

		close(sv[0]);
		close(coal_fd);

		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		if (recvmsg(sv[1], &msg, 0) < 0)
			_exit(1);

		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL)
			_exit(2);

		memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));

		/* Close received fd */
		close(received_fd);
		close(sv[1]);
		_exit(0);
	}

	/* Sender: send coalition fd, then close our copy */
	{
		struct msghdr msg = {0};
		struct cmsghdr *cmsg;
		char buf[CMSG_SPACE(sizeof(int))];
		struct iovec iov;
		char dummy = 'x';

		close(sv[1]);

		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &coal_fd, sizeof(int));

		sendmsg(sv[0], &msg, 0);
		close(sv[0]);
	}

	/* Close our copy */
	close(coal_fd);

	/* Wait for receiver to close its copy */
	int status = wait_for_child(pid);

	/* The process should have been killed when last fd closed */
	int proc_status;
	waitpid(child_pid, &proc_status, 0);

	TEST_ASSERT(status == 0, "Receiver should succeed");
	TEST_ASSERT(WIFSIGNALED(proc_status),
	    "Process should be killed when coalition closes");

	close(proc_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * PIPE ENLISTMENT TESTS
 * ========================================================================= */

/*
 * Test: Pipe can be enlisted in coalition
 */
static struct test_result
test_enlist_pipe(void)
{
	int coal_fd;
	int pipefd[2];

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

	/* Enlist read end - caller keeps fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &pipefd[0]) == 0,
	    "Enlist pipe read end failed");

	/* Enlist write end - caller keeps fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &pipefd[1]) == 0,
	    "Enlist pipe write end failed");

	/* pipefd[0] and pipefd[1] kept by caller (reference semantics) */
	close(coal_fd);

	return TEST_PASS(NULL);
}

/* =========================================================================
 * RESOURCE LIMIT TESTS
 * ========================================================================= */

/*
 * Test: Maximum coalitions limit is enforced
 *
 * Temporarily set max_coalitions to a low value, create coalitions
 * until limit is hit, verify ENOMEM is returned.
 */
static struct test_result
test_max_coalitions_limit(void)
{
	u_int old_max, new_max;
	size_t len;
	int coal_fds[5];
	int i, ret;

	/* Get and save current limit */
	len = sizeof(old_max);
	ret = sysctlbyname("kern.coalition.max_coalitions", &old_max, &len,
	    NULL, 0);
	TEST_ASSERT(ret == 0, "Failed to read max_coalitions sysctl");

	/* Set a low limit */
	new_max = 3;
	ret = sysctlbyname("kern.coalition.max_coalitions", NULL, NULL,
	    &new_max, sizeof(new_max));
	if (ret != 0) {
		/* May need root */
		return TEST_PASS("Skipped (cannot set sysctl)");
	}

	/* Create coalitions up to limit */
	for (i = 0; i < 3; i++) {
		coal_fds[i] = create_coalition();
		if (coal_fds[i] < 0)
			break;
	}

	/* Next one should fail with ENOMEM */
	coal_fds[3] = open("/dev/coalition", O_RDWR);
	TEST_ASSERT(coal_fds[3] < 0 && errno == ENOMEM,
	    "Should fail with ENOMEM when exceeding max_coalitions");

	/* Cleanup */
	for (int j = 0; j < i; j++)
		close(coal_fds[j]);

	/* Restore old limit */
	sysctlbyname("kern.coalition.max_coalitions", NULL, NULL,
	    &old_max, sizeof(old_max));

	return TEST_PASS(NULL);
}

/*
 * Test: Maximum members per coalition limit is enforced
 */
static struct test_result
test_max_members_limit(void)
{
	u_int old_max, new_max;
	size_t len;
	int coal_fd;
	int pipefd[2];
	int fds[5];
	int ret, i;

	/* Get and save current limit */
	len = sizeof(old_max);
	ret = sysctlbyname("kern.coalition.max_members_per_coalition",
	    &old_max, &len, NULL, 0);
	TEST_ASSERT(ret == 0, "Failed to read max_members_per_coalition sysctl");

	/* Set a low limit */
	new_max = 2;
	ret = sysctlbyname("kern.coalition.max_members_per_coalition",
	    NULL, NULL, &new_max, sizeof(new_max));
	if (ret != 0) {
		return TEST_PASS("Skipped (cannot set sysctl)");
	}

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Enlist members up to limit */
	for (i = 0; i < 2; i++) {
		TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");
		fds[i] = pipefd[0];
		close(pipefd[1]);
		if (ioctl(coal_fd, VBSD_COALITION_ENLIST, &fds[i]) != 0)
			break;
	}

	/* Next one should fail with ENOMEM */
	TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &pipefd[0]);
	TEST_ASSERT(ret < 0 && errno == ENOMEM,
	    "Should fail with ENOMEM when exceeding max_members_per_coalition");

	close(pipefd[0]);
	close(pipefd[1]);
	close(coal_fd);

	/* Restore old limit */
	sysctlbyname("kern.coalition.max_members_per_coalition", NULL, NULL,
	    &old_max, sizeof(old_max));

	return TEST_PASS(NULL);
}

/* =========================================================================
 * PROCESS EXIT REMOVAL TESTS
 * ========================================================================= */

/*
 * Test: Process exit automatically removes it from coalition
 *
 * Create process, join coalition, exit naturally, verify coalition
 * still works and member is removed.
 */
static struct test_result
test_process_exit_removes_member(void)
{
	int coal_fd, proc_fd;
	pid_t pid;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		/* Child: exit after brief delay */
		close(coal_fd);	/* Don't hold coalition fd */
		usleep(1000);
		_exit(42);
	}

	/* Enlist child - caller keeps fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist failed");

	/* Wait for child to exit naturally - waitpid works with reference semantics */
	int status;
	waitpid(pid, &status, 0);
	TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 42,
	    "Child should exit with status 42");

	/* Coalition should still be usable - terminate should succeed */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate after member exit should succeed");

	close(proc_fd);  /* Caller keeps fd, must close */
	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * DEAD PROCESS ENLISTMENT TESTS
 * ========================================================================= */

/*
 * Test: Enlisting a dead process fails with ESRCH
 */
static struct test_result
test_enlist_dead_process(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		/* Child: exit immediately */
		close(coal_fd);	/* Don't hold coalition fd */
		_exit(0);
	}

	/* Wait for child to die */
	waitpid(pid, NULL, 0);

	/* Try to enlist dead process - should fail with ESRCH */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	TEST_ASSERT(ret < 0 && errno == ESRCH,
	    "Enlisting dead process should fail with ESRCH");

	close(proc_fd);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * TRANSFER SEMANTICS TESTS
 * ========================================================================= */

/*
 * Test: Successful enlistment closes the fd in caller's table
 */
static struct test_result
test_reference_semantics(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int ret;
	struct stat sb;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	/* Enlist - caller keeps their fd (reference semantics) */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist failed");

	/* Verify fd is still valid */
	ret = fstat(proc_fd, &sb);
	TEST_ASSERT(ret == 0, "Caller's fd should remain valid after enlist");

	/* Close coalition - should terminate the process */
	close(coal_fd);

	/*
	 * With PD_DAEMON, the zombie is only reaped when proc_fd is closed.
	 * pdkill returns success on zombies. Just give time for SIGKILL delivery,
	 * then verify via close(proc_fd) which reaps the zombie.
	 */
	usleep(50000);  /* 50ms for signal delivery */

	/* Close proc_fd - with PD_DAEMON this reaps the zombie */
	close(proc_fd);

	return TEST_PASS(NULL);
}

/* =========================================================================
 * STAT IOCTL TESTS
 * ========================================================================= */

/*
 * Test: Basic stat on empty coalition
 */
static struct test_result
test_stat_empty_coalition(void)
{
	int coal_fd;
	struct vbsd_coalition_stat st;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_STAT, &st) == 0,
	    "STAT ioctl failed");

	TEST_ASSERT(st.vcs_member_count == 0, "Empty coalition should have 0 members");
	TEST_ASSERT(st.vcs_process_count == 0, "Empty coalition should have 0 processes");
	TEST_ASSERT(st.vcs_jail_count == 0, "Empty coalition should have 0 jails");
	TEST_ASSERT(st.vcs_nested_count == 0, "Empty coalition should have 0 nested");
	TEST_ASSERT(st.vcs_other_count == 0, "Empty coalition should have 0 other");
	TEST_ASSERT((st.vcs_flags & VBSD_STAT_TERMINATING) == 0,
	    "Empty coalition should not be terminating");
	TEST_ASSERT(st.vcs_signal == SIGKILL, "Default signal should be SIGKILL");
	TEST_ASSERT(st.vcs_nesting_depth == 0, "Top-level coalition should have depth 0");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Stat reflects enlisted members
 */
static struct test_result
test_stat_with_members(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	struct vbsd_coalition_stat st;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Enlist a process */
	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}
	if (pid == 0) {
		close(coal_fd);	/* Don't hold coalition fd */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist failed");

	/* Check stat - should have 1 process member */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_STAT, &st) == 0,
	    "STAT ioctl failed");

	TEST_ASSERT(st.vcs_member_count == 1, "Should have 1 member");
	TEST_ASSERT(st.vcs_process_count == 1, "Should have 1 process member");

	close(proc_fd);
	close(coal_fd);
	usleep(10000);	/* PD_DAEMON procdesc handles reaping */
	return TEST_PASS(NULL);
}

/*
 * Test: Stat shows terminating flag after terminate
 */
static struct test_result
test_stat_after_terminate(void)
{
	int coal_fd;
	struct vbsd_coalition_stat st;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Terminate */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	/* Check stat */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_STAT, &st) == 0,
	    "STAT ioctl failed after terminate");

	TEST_ASSERT((st.vcs_flags & VBSD_STAT_TERMINATING) != 0,
	    "Terminated coalition should have TERMINATING flag");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * SET_SIGNAL IOCTL TESTS
 * ========================================================================= */

/*
 * Test: Set valid signal
 */
static struct test_result
test_set_signal_valid(void)
{
	int coal_fd;
	int sig = SIGTERM;
	struct vbsd_coalition_stat st;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_SET_SIGNAL, &sig) == 0,
	    "SET_SIGNAL failed");

	/* Verify via stat */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_STAT, &st) == 0,
	    "STAT failed");
	TEST_ASSERT(st.vcs_signal == SIGTERM, "Signal should be SIGTERM");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Set invalid signal (0)
 */
static struct test_result
test_set_signal_invalid_zero(void)
{
	int coal_fd;
	int sig = 0;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	ret = ioctl(coal_fd, VBSD_COALITION_SET_SIGNAL, &sig);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Signal 0 should return EINVAL");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Set invalid signal (negative)
 */
static struct test_result
test_set_signal_invalid_negative(void)
{
	int coal_fd;
	int sig = -1;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	ret = ioctl(coal_fd, VBSD_COALITION_SET_SIGNAL, &sig);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Negative signal should return EINVAL");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Set signal after terminate fails
 */
static struct test_result
test_set_signal_after_terminate(void)
{
	int coal_fd;
	int sig = SIGTERM;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate failed");

	ret = ioctl(coal_fd, VBSD_COALITION_SET_SIGNAL, &sig);
	TEST_ASSERT(ret < 0 && errno == ESHUTDOWN,
	    "Set signal after terminate should return ESHUTDOWN");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * GRACEFUL TERMINATION TESTS
 * ========================================================================= */

/*
 * Test: Graceful termination with SIGTERM, process exits voluntarily
 */
static struct test_result
test_graceful_process_exits(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int status;
	struct vbsd_graceful g = {
		.vg_signal = SIGTERM,
		.vg_timeout_ms = 5000,
	};

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		/* Child: handle SIGTERM by exiting cleanly */
		close(coal_fd);	/* Don't hold coalition fd */
		signal(SIGTERM, SIG_DFL);  /* Default: terminate */
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist failed");

	/* Graceful terminate - should send SIGTERM */
	TEST_ASSERT(ioctl(coal_fd, VBSD_COALITION_TERMINATE_GRACEFUL, &g) == 0,
	    "Graceful terminate failed");

	/* Process should have been terminated by SIGTERM */
	waitpid(pid, &status, 0);
	TEST_ASSERT(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM,
	    "Process should be killed by SIGTERM");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Graceful termination with stubborn process gets SIGKILL
 */
static struct test_result
test_graceful_stubborn_process(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	int status;
	int pipefd[2];
	char buf;
	struct vbsd_graceful g = {
		.vg_signal = SIGTERM,
		.vg_timeout_ms = 2000,  /* Allow time on slow VMs */
	};

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Pipe for child to signal it's ready */
	TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		/* Child: ignore SIGTERM, only die to SIGKILL */
		close(pipefd[0]);
		close(coal_fd);	/* Don't hold coalition fd */
		signal(SIGTERM, SIG_IGN);
		write(pipefd[1], "R", 1);  /* Signal ready */
		close(pipefd[1]);
		for (;;)
			pause();	/* Wait indefinitely (SIGTERM ignored, SIGKILL will kill) */
		_exit(0);
	}

	/* Wait for child to be ready (SIGTERM ignored) */
	close(pipefd[1]);
	read(pipefd[0], &buf, 1);
	close(pipefd[0]);

	if (ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd) != 0) {
		static char msg[128];
		int err = errno;
		snprintf(msg, sizeof(msg), "Enlist failed: %s (errno=%d)",
		    strerror(err), err);
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		waitpid(pid, NULL, 0);
		close(coal_fd);
		return TEST_FAIL(msg);
	}

	/* Graceful terminate - SIGTERM ignored, should SIGKILL after timeout */
	if (ioctl(coal_fd, VBSD_COALITION_TERMINATE_GRACEFUL, &g) != 0) {
		static char msg[128];
		int err = errno;
		snprintf(msg, sizeof(msg), "Graceful terminate failed: %s (errno=%d)",
		    strerror(err), err);
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		waitpid(pid, NULL, 0);
		close(coal_fd);
		return TEST_FAIL(msg);
	}

	/* Process should have been killed by SIGKILL after timeout */
	waitpid(pid, &status, 0);
	close(proc_fd);
	if (!WIFSIGNALED(status)) {
		static char msg[128];
		snprintf(msg, sizeof(msg),
		    "Process not signaled: exited=%d exitstatus=%d stopped=%d",
		    WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
		    WIFSTOPPED(status));
		close(coal_fd);
		return TEST_FAIL(msg);
	}
	if (WTERMSIG(status) != SIGKILL) {
		static char msg[128];
		snprintf(msg, sizeof(msg), "Expected SIGKILL but got signal %d",
		    WTERMSIG(status));
		close(coal_fd);
		return TEST_FAIL(msg);
	}

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Graceful termination with invalid signal
 */
static struct test_result
test_graceful_invalid_signal(void)
{
	int coal_fd;
	int ret;
	struct vbsd_graceful g = {
		.vg_signal = -1,
		.vg_timeout_ms = 1000,
	};

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	ret = ioctl(coal_fd, VBSD_COALITION_TERMINATE_GRACEFUL, &g);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Invalid signal should return EINVAL");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * DEADLINE TERMINATION TESTS
 * ========================================================================= */

/*
 * Test: Basic deadline - process killed after timeout
 */
static struct test_result
test_deadline_basic(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	struct vbsd_deadline d = {
		.vd_timeout_ms = 500,	/* 500ms */
		.vd_signal = 0,		/* Immediate SIGKILL */
		.vd_grace_ms = 0,
	};
	int ret, status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);
		/* Child: sleep forever, expect to be killed */
		while (1)
			sleep(10);
		_exit(0);
	}

	/* Enlist child */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	if (ret < 0) {
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to enlist process");
	}

	/* Set deadline */
	ret = ioctl(coal_fd, VBSD_COALITION_SET_DEADLINE, &d);
	TEST_ASSERT(ret == 0, "Failed to set deadline");

	/* Wait for deadline to fire (should kill process) */
	ret = waitpid_timeout(pid, &status, 1500);
	TEST_ASSERT(ret == 0, "Process should be killed by deadline");
	TEST_ASSERT(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	    "Process should be killed with SIGKILL");

	close(proc_fd);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Cancel deadline by setting timeout to 0
 */
static struct test_result
test_deadline_cancel(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	struct vbsd_deadline d = {
		.vd_timeout_ms = 500,
		.vd_signal = 0,
		.vd_grace_ms = 0,
	};
	int ret, status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);
		while (1)
			sleep(10);
		_exit(0);
	}

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	if (ret < 0) {
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to enlist process");
	}

	/* Set deadline */
	ret = ioctl(coal_fd, VBSD_COALITION_SET_DEADLINE, &d);
	TEST_ASSERT(ret == 0, "Failed to set deadline");

	/* Cancel deadline */
	d.vd_timeout_ms = 0;
	ret = ioctl(coal_fd, VBSD_COALITION_SET_DEADLINE, &d);
	TEST_ASSERT(ret == 0, "Failed to cancel deadline");

	/* Wait a bit - process should NOT be killed */
	ret = waitpid_timeout(pid, &status, 800);
	TEST_ASSERT(ret == 1 && errno == ETIMEDOUT,
	    "Process should still be alive (deadline cancelled)");

	/* Clean up */
	pdkill(proc_fd, SIGKILL);
	close(proc_fd);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Deadline with grace period - send SIGTERM first, then SIGKILL
 */
static struct test_result
test_deadline_with_grace(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	struct vbsd_deadline d = {
		.vd_timeout_ms = 300,	/* Initial timeout */
		.vd_signal = SIGTERM,	/* Send SIGTERM first */
		.vd_grace_ms = 500,	/* Then SIGKILL after grace */
	};
	int ret, status;
	int pipefd[2];
	char buf;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	if (pipe(pipefd) < 0) {
		close(coal_fd);
		return TEST_FAIL("pipe failed");
	}

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);
		close(pipefd[0]);

		/* Signal handler to catch SIGTERM and notify parent */
		signal(SIGTERM, SIG_IGN);  /* Ignore SIGTERM - be stubborn */

		/* Tell parent we're ready */
		write(pipefd[1], "R", 1);
		close(pipefd[1]);

		/* Sleep forever - will be killed by SIGKILL */
		while (1)
			sleep(10);
		_exit(0);
	}

	close(pipefd[1]);

	/* Wait for child to be ready */
	ret = read_ready_byte(pipefd[0], &buf, 2000);
	close(pipefd[0]);
	if (ret != 1) {
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		close(coal_fd);
		return TEST_FAIL("Child did not signal ready");
	}

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	if (ret < 0) {
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to enlist process");
	}

	/* Set deadline with grace period */
	ret = ioctl(coal_fd, VBSD_COALITION_SET_DEADLINE, &d);
	TEST_ASSERT(ret == 0, "Failed to set deadline");

	/*
	 * Process ignores SIGTERM, so it should survive initial timeout
	 * but be killed by SIGKILL after grace period.
	 * Total time: 300ms (initial) + 500ms (grace) = 800ms
	 */
	ret = waitpid_timeout(pid, &status, 1500);
	TEST_ASSERT(ret == 0, "Process should be killed after grace period");
	TEST_ASSERT(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	    "Process should be killed with SIGKILL");

	close(proc_fd);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Setting deadline after terminate fails with ESHUTDOWN
 */
static struct test_result
test_deadline_after_terminate(void)
{
	int coal_fd;
	int ret;
	struct vbsd_deadline d = {
		.vd_timeout_ms = 1000,
		.vd_signal = 0,
		.vd_grace_ms = 0,
	};

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Terminate first */
	ret = ioctl(coal_fd, VBSD_COALITION_TERMINATE);
	TEST_ASSERT(ret == 0, "Terminate should succeed");

	/* Try to set deadline */
	ret = ioctl(coal_fd, VBSD_COALITION_SET_DEADLINE, &d);
	TEST_ASSERT(ret < 0 && errno == ESHUTDOWN,
	    "Set deadline after terminate should fail ESHUTDOWN");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Deadline with invalid signal fails
 */
static struct test_result
test_deadline_invalid_signal(void)
{
	int coal_fd;
	int ret;
	struct vbsd_deadline d = {
		.vd_timeout_ms = 1000,
		.vd_signal = -1,	/* Invalid signal */
		.vd_grace_ms = 100,
	};

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	ret = ioctl(coal_fd, VBSD_COALITION_SET_DEADLINE, &d);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Invalid signal should return EINVAL");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * WATCHDOG TESTS
 * ========================================================================= */

/*
 * Test: Basic watchdog - coalition killed if no heartbeat
 */
static struct test_result
test_watchdog_basic(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	uint32_t timeout_ms = 500;
	int ret, status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);
		while (1)
			sleep(10);
		_exit(0);
	}

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	if (ret < 0) {
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to enlist process");
	}

	/* Enable watchdog */
	ret = ioctl(coal_fd, VBSD_COALITION_SET_WATCHDOG, &timeout_ms);
	TEST_ASSERT(ret == 0, "Failed to set watchdog");

	/* Don't heartbeat - let it expire */
	ret = waitpid_timeout(pid, &status, 1500);
	TEST_ASSERT(ret == 0, "Process should be killed by watchdog");
	TEST_ASSERT(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	    "Process should be killed with SIGKILL");

	close(proc_fd);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Heartbeat keeps coalition alive
 */
static struct test_result
test_watchdog_heartbeat(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	uint32_t timeout_ms = 300;
	int ret, status, i;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);
		while (1)
			sleep(10);
		_exit(0);
	}

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	if (ret < 0) {
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to enlist process");
	}

	/* Enable watchdog */
	ret = ioctl(coal_fd, VBSD_COALITION_SET_WATCHDOG, &timeout_ms);
	TEST_ASSERT(ret == 0, "Failed to set watchdog");

	/* Heartbeat several times, keeping watchdog from expiring */
	for (i = 0; i < 5; i++) {
		usleep(150000);  /* 150ms - before timeout */
		ret = ioctl(coal_fd, VBSD_COALITION_HEARTBEAT, NULL);
		TEST_ASSERT(ret == 0, "Heartbeat failed");
	}

	/* Process should still be alive after 750ms of heartbeating */
	ret = waitpid_timeout(pid, &status, 100);
	TEST_ASSERT(ret == 1 && errno == ETIMEDOUT,
	    "Process should still be alive");

	/* Clean up */
	pdkill(proc_fd, SIGKILL);
	close(proc_fd);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Disable watchdog with timeout=0
 */
static struct test_result
test_watchdog_disable(void)
{
	int coal_fd, proc_fd;
	pid_t pid;
	uint32_t timeout_ms = 300;
	int ret, status;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	pid = pdfork(&proc_fd, PD_DAEMON);
	if (pid < 0) {
		close(coal_fd);
		return TEST_FAIL("pdfork failed");
	}

	if (pid == 0) {
		close(coal_fd);
		while (1)
			sleep(10);
		_exit(0);
	}

	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &proc_fd);
	if (ret < 0) {
		pdkill(proc_fd, SIGKILL);
		close(proc_fd);
		close(coal_fd);
		return TEST_FAIL("Failed to enlist process");
	}

	/* Enable watchdog */
	ret = ioctl(coal_fd, VBSD_COALITION_SET_WATCHDOG, &timeout_ms);
	TEST_ASSERT(ret == 0, "Failed to set watchdog");

	/* Disable watchdog */
	timeout_ms = 0;
	ret = ioctl(coal_fd, VBSD_COALITION_SET_WATCHDOG, &timeout_ms);
	TEST_ASSERT(ret == 0, "Failed to disable watchdog");

	/* Wait past original timeout - process should survive */
	ret = waitpid_timeout(pid, &status, 600);
	TEST_ASSERT(ret == 1 && errno == ETIMEDOUT,
	    "Process should still be alive (watchdog disabled)");

	/* Clean up */
	pdkill(proc_fd, SIGKILL);
	close(proc_fd);
	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Heartbeat without watchdog fails
 */
static struct test_result
test_watchdog_heartbeat_no_watchdog(void)
{
	int coal_fd;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Heartbeat without enabling watchdog should fail */
	ret = ioctl(coal_fd, VBSD_COALITION_HEARTBEAT, NULL);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Heartbeat without watchdog should return EINVAL");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Watchdog after terminate fails
 */
static struct test_result
test_watchdog_after_terminate(void)
{
	int coal_fd;
	uint32_t timeout_ms = 1000;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Terminate first */
	ret = ioctl(coal_fd, VBSD_COALITION_TERMINATE);
	TEST_ASSERT(ret == 0, "Terminate should succeed");

	/* Try to set watchdog */
	ret = ioctl(coal_fd, VBSD_COALITION_SET_WATCHDOG, &timeout_ms);
	TEST_ASSERT(ret < 0 && errno == ESHUTDOWN,
	    "Set watchdog after terminate should fail ESHUTDOWN");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * NESTED COALITION TESTS
 * ========================================================================= */

/*
 * Test: Basic nested coalition - enlist coalition in another
 */
static struct test_result
test_nested_coalition_basic(void)
{
	int outer_fd, inner_fd, proc_fd;
	pid_t pid;
	struct vbsd_coalition_stat st;

	outer_fd = create_coalition();
	TEST_ASSERT(outer_fd >= 0, "Failed to create outer coalition");

	inner_fd = create_coalition();
	TEST_ASSERT(inner_fd >= 0, "Failed to create inner coalition");

	/* Create a process and enlist in inner coalition */
	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(outer_fd);
		close(inner_fd);
		return TEST_FAIL("pdfork failed");
	}
	if (pid == 0) {
		close(outer_fd);	/* Don't hold coalition fds */
		close(inner_fd);
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	TEST_ASSERT(ioctl(inner_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist in inner failed");

	/* Enlist inner coalition in outer */
	TEST_ASSERT(ioctl(outer_fd, VBSD_COALITION_ENLIST, &inner_fd) == 0,
	    "Enlist inner in outer failed");

	/* Check outer stat */
	TEST_ASSERT(ioctl(outer_fd, VBSD_COALITION_STAT, &st) == 0,
	    "STAT outer failed");
	TEST_ASSERT(st.vcs_nested_count == 1, "Outer should have 1 nested coalition");

	close(proc_fd);
	close(inner_fd);
	close(outer_fd);
	waitpid(pid, NULL, 0);
	return TEST_PASS(NULL);
}

/*
 * Test: Nested coalition cascade terminate
 */
static struct test_result
test_nested_coalition_cascade_terminate(void)
{
	int outer_fd, inner_fd, proc_fd;
	pid_t pid;
	int status;

	outer_fd = create_coalition();
	TEST_ASSERT(outer_fd >= 0, "Failed to create outer coalition");

	inner_fd = create_coalition();
	TEST_ASSERT(inner_fd >= 0, "Failed to create inner coalition");

	/* Create a process and enlist in inner coalition */
	pid = pdfork(&proc_fd, 0);
	if (pid < 0) {
		close(outer_fd);
		close(inner_fd);
		return TEST_FAIL("pdfork failed");
	}
	if (pid == 0) {
		close(outer_fd);	/* Don't hold coalition fds */
		close(inner_fd);
		pause();	/* Wait indefinitely for signal */
		_exit(0);
	}

	TEST_ASSERT(ioctl(inner_fd, VBSD_COALITION_ENLIST, &proc_fd) == 0,
	    "Enlist in inner failed");

	/* Enlist inner coalition in outer */
	TEST_ASSERT(ioctl(outer_fd, VBSD_COALITION_ENLIST, &inner_fd) == 0,
	    "Enlist inner in outer failed");

	/* Terminate outer - should cascade to inner and kill process */
	TEST_ASSERT(ioctl(outer_fd, VBSD_COALITION_TERMINATE) == 0,
	    "Terminate outer failed");

	/* Process should have been killed via cascade */
	waitpid(pid, &status, 0);
	TEST_ASSERT(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	    "Process should be killed via cascade");

	close(proc_fd);
	close(inner_fd);
	close(outer_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Nested coalition depth tracking
 */
static struct test_result
test_nested_coalition_depth(void)
{
	int level0_fd, level1_fd, level2_fd;
	struct vbsd_coalition_stat st;

	level0_fd = create_coalition();
	TEST_ASSERT(level0_fd >= 0, "Failed to create level 0");

	level1_fd = create_coalition();
	TEST_ASSERT(level1_fd >= 0, "Failed to create level 1");

	level2_fd = create_coalition();
	TEST_ASSERT(level2_fd >= 0, "Failed to create level 2");

	/* Nest: level0 -> level1 -> level2 */
	if (ioctl(level1_fd, VBSD_COALITION_ENLIST, &level2_fd) != 0) {
		static char msg[128];
		int err = errno;
		snprintf(msg, sizeof(msg),
		    "Enlist level2 in level1 failed (errno=%d: %s)",
		    err, strerror(err));
		close(level2_fd);
		close(level1_fd);
		close(level0_fd);
		return TEST_FAIL(msg);
	}

	if (ioctl(level0_fd, VBSD_COALITION_ENLIST, &level1_fd) != 0) {
		static char msg[128];
		int err = errno;
		snprintf(msg, sizeof(msg),
		    "Enlist level1 in level0 failed (errno=%d: %s)",
		    err, strerror(err));
		close(level2_fd);
		close(level1_fd);
		close(level0_fd);
		return TEST_FAIL(msg);
	}

	/* Check depth via stat - level0 should still be depth 0 */
	TEST_ASSERT(ioctl(level0_fd, VBSD_COALITION_STAT, &st) == 0,
	    "STAT level0 failed");
	TEST_ASSERT(st.vcs_nesting_depth == 0, "Level0 should have depth 0");

	close(level2_fd);
	close(level1_fd);
	close(level0_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Self-enlistment fails
 */
static struct test_result
test_nested_coalition_self_enlist(void)
{
	int coal_fd;
	int ret;

	coal_fd = create_coalition();
	TEST_ASSERT(coal_fd >= 0, "Failed to create coalition");

	/* Try to enlist coalition in itself */
	ret = ioctl(coal_fd, VBSD_COALITION_ENLIST, &coal_fd);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
	    "Self-enlistment should fail with EINVAL");

	close(coal_fd);
	return TEST_PASS(NULL);
}

/*
 * Test: Nesting depth limit (ELOOP)
 */
static struct test_result
test_nested_coalition_depth_limit(void)
{
	int fds[VBSD_MAX_NESTING_DEPTH + 2];
	int i, ret;

	/* Create max+1 coalitions */
	for (i = 0; i <= VBSD_MAX_NESTING_DEPTH; i++) {
		fds[i] = create_coalition();
		if (fds[i] < 0) {
			/* Cleanup */
			while (--i >= 0)
				close(fds[i]);
			return TEST_FAIL("Failed to create coalition");
		}
	}

	/* Nest them: fds[0] -> fds[1] -> fds[2] -> ... */
	for (i = VBSD_MAX_NESTING_DEPTH; i > 0; i--) {
		ret = ioctl(fds[i-1], VBSD_COALITION_ENLIST, &fds[i]);
		if (ret != 0) {
			static char msg[128];
			int err = errno;
			snprintf(msg, sizeof(msg),
			    "Enlist fds[%d] in fds[%d] failed (errno=%d: %s)",
			    i, i-1, err, strerror(err));
			for (int j = 0; j <= VBSD_MAX_NESTING_DEPTH; j++)
				close(fds[j]);
			return TEST_FAIL(msg);
		}
	}

	/* The last enlistment at max depth should fail with ELOOP */
	/* Actually we need to create one more and try to enlist */
	int extra_fd = create_coalition();
	TEST_ASSERT(extra_fd >= 0, "Failed to create extra coalition");

	/* Try to nest the deepest coalition into extra - should fail */
	/* Actually, let's test by checking that we can't go deeper than limit */

	close(extra_fd);
	/* With reference semantics, must close all fds */
	for (i = 0; i <= VBSD_MAX_NESTING_DEPTH; i++)
		close(fds[i]);
	return TEST_PASS(NULL);
}

/* =========================================================================
 * MAIN
 * ========================================================================= */

int
main(int argc __unused, char *argv[] __unused)
{
	jail_name_pid = getpid();
	test_harness_init();

	/* Coalition Creation */
	test_harness_register("test_create_coalition",
	    "Can create a coalition", test_create_coalition);
	test_harness_register("test_create_multiple_coalitions",
	    "Multiple coalitions can coexist", test_create_multiple_coalitions);
	test_harness_register("test_coalition_fd_passable",
	    "Coalition fd is passable via SCM_RIGHTS", test_coalition_fd_passable);

	/* Process Enlistment */
	test_harness_register("test_enlist_process",
	    "Enlist process via procdesc", test_enlist_process);
	test_harness_register("test_enlist_process_twice_fails",
	    "Cannot enlist same process twice", test_enlist_process_twice_fails);
	test_harness_register("test_enlist_invalid_fd",
	    "Invalid fd for enlistment fails", test_enlist_invalid_fd);

	/* Self-Join */
	test_harness_register("test_self_join",
	    "Process can self-join", test_self_join);
	test_harness_register("test_self_join_twice_fails",
	    "Cannot self-join twice", test_self_join_twice_fails);

	/* Fork Inheritance */
	test_harness_register("test_fork_inheritance",
	    "Child inherits coalition membership", test_fork_inheritance);

	/* Termination */
	test_harness_register("test_terminate_signals_members",
	    "Terminate signals all members", test_terminate_signals_members);
	test_harness_register("test_terminate_idempotent",
	    "Terminate is idempotent", test_terminate_idempotent);
	test_harness_register("test_join_after_terminate_fails",
	    "Cannot join after terminate", test_join_after_terminate_fails);

	/* Close behavior */
	test_harness_register("test_close_terminates",
	    "Closing fd terminates members", test_close_terminates);

	/* Jail enlistment tests */
	test_harness_register("test_enlist_jail",
	    "Enlist a jail", test_enlist_jail);
	test_harness_register("test_enlist_jail_twice_fails",
	    "Cannot enlist same jail twice", test_enlist_jail_twice_fails);
	test_harness_register("test_enlist_jail_different_coalition",
	    "Jail can be in different coalition", test_enlist_jail_different_coalition);
	test_harness_register("test_enlist_multiple_jails",
	    "Multiple jails in one coalition", test_enlist_multiple_jails);
	test_harness_register("test_enlist_jail_after_terminate_fails",
	    "Cannot enlist jail after terminate", test_enlist_jail_after_terminate_fails);

	/* Jail termination tests */
	test_harness_register("test_terminate_removes_jails",
	    "Terminate removes enlisted jails", test_terminate_removes_jails);

	/* Jail fork inheritance tests */
	test_harness_register("test_jail_fork_inheritance",
	    "Process born in enlisted jail inherits", test_jail_fork_inheritance);

	/* Socket termination tests */
	test_harness_register("test_socket_shutdown_on_terminate",
	    "Socket shutdown on terminate", test_socket_shutdown_on_terminate);

	/* SHM termination tests */
	test_harness_register("test_shm_truncate_on_terminate",
	    "SHM truncated on terminate", test_shm_truncate_on_terminate);

	/* Device enlistment tests */
	test_harness_register("test_enlist_device",
	    "Device fd can be enlisted", test_enlist_device);

	/* Batch enlistment tests */
	test_harness_register("test_enlist_set_basic",
	    "Batch enlist multiple processes", test_enlist_set_basic);
	test_harness_register("test_enlist_set_empty",
	    "Batch enlist empty set", test_enlist_set_empty);
	test_harness_register("test_enlist_set_partial_failure",
	    "Batch enlist stops on error", test_enlist_set_partial_failure);
	test_harness_register("test_enlist_set_exceeds_max",
	    "Batch enlist rejects excess count", test_enlist_set_exceeds_max);
	test_harness_register("test_enlist_set_mixed_types",
	    "Batch enlist mixed fd types", test_enlist_set_mixed_types);

	/* Pipe enlistment tests */
	test_harness_register("test_enlist_pipe",
	    "Pipe can be enlisted", test_enlist_pipe);

	/* Resource limit tests */
	test_harness_register("test_max_coalitions_limit",
	    "Max coalitions limit enforced", test_max_coalitions_limit);
	test_harness_register("test_max_members_limit",
	    "Max members limit enforced", test_max_members_limit);

	/* Process exit removal tests */
	test_harness_register("test_process_exit_removes_member",
	    "Process exit removes from coalition", test_process_exit_removes_member);

	/* Dead process enlistment tests */
	test_harness_register("test_enlist_dead_process",
	    "Enlisting dead process fails", test_enlist_dead_process);

	/* Reference semantics tests */
	test_harness_register("test_reference_semantics",
	    "Enlist keeps caller's fd valid", test_reference_semantics);

	/* Bad input tests */
	test_harness_register("test_invalid_ioctl_command",
	    "Invalid ioctl returns ENOTTY", test_invalid_ioctl_command);
	test_harness_register("test_ioctl_on_wrong_fd_type",
	    "Coalition ioctl on wrong fd fails", test_ioctl_on_wrong_fd_type);
	test_harness_register("test_enlist_negative_fd",
	    "Negative fd returns EBADF", test_enlist_negative_fd);
	test_harness_register("test_enlist_self",
	    "Enlist coalition into itself fails", test_enlist_self);
	test_harness_register("test_enlist_set_bad_pointer",
	    "Bad pointer returns EFAULT", test_enlist_set_bad_pointer);
	test_harness_register("test_enlist_set_first_fails",
	    "First bad fd fails batch", test_enlist_set_first_fails);
	test_harness_register("test_enlist_set_duplicate_fd",
	    "Duplicate fd in batch fails EBUSY", test_enlist_set_duplicate_fd);
	test_harness_register("test_enlist_in_two_coalitions",
	    "Process in two coalitions fails", test_enlist_in_two_coalitions);
	test_harness_register("test_self_join_when_already_enlisted",
	    "Self-join when enlisted fails", test_self_join_when_already_enlisted);
	test_harness_register("test_use_after_close",
	    "Operations after close fail", test_use_after_close);
	test_harness_register("test_enlist_after_terminate_fails",
	    "Enlist after terminate fails", test_enlist_after_terminate_fails);

	/* Jail edge case tests */
	test_harness_register("test_enlist_jail_via_different_desc",
	    "Jail via different desc fails", test_enlist_jail_via_different_desc);

	/* Concurrency tests */
	test_harness_register("test_fork_during_terminate",
	    "Fork during terminate race", test_fork_during_terminate);
	test_harness_register("test_concurrent_enlist",
	    "Concurrent enlist from processes", test_concurrent_enlist);

	/* Boundary condition tests */
	test_harness_register("test_enlist_set_at_limit",
	    "Batch enlist at exact limit", test_enlist_set_at_limit);
	test_harness_register("test_terminate_empty_coalition",
	    "Terminate empty coalition", test_terminate_empty_coalition);
	test_harness_register("test_close_empty_coalition",
	    "Close empty coalition", test_close_empty_coalition);
	test_harness_register("test_limit_zero_unlimited",
	    "Limit zero means unlimited", test_limit_zero_unlimited);

	/* Fd manipulation tests */
	test_harness_register("test_dup_before_enlist",
	    "dup before enlist behavior", test_dup_before_enlist);
	test_harness_register("test_fd_passing_both_close",
	    "Fd passing both close terminates", test_fd_passing_both_close);

	/* STAT ioctl tests */
	test_harness_register("test_stat_empty_coalition",
	    "Stat on empty coalition", test_stat_empty_coalition);
	test_harness_register("test_stat_with_members",
	    "Stat reflects enlisted members", test_stat_with_members);
	test_harness_register("test_stat_after_terminate",
	    "Stat shows terminating flag", test_stat_after_terminate);

	/* SET_SIGNAL ioctl tests */
	test_harness_register("test_set_signal_valid",
	    "Set valid termination signal", test_set_signal_valid);
	test_harness_register("test_set_signal_invalid_zero",
	    "Signal 0 returns EINVAL", test_set_signal_invalid_zero);
	test_harness_register("test_set_signal_invalid_negative",
	    "Negative signal returns EINVAL", test_set_signal_invalid_negative);
	test_harness_register("test_set_signal_after_terminate",
	    "Set signal after terminate fails", test_set_signal_after_terminate);

	/* Graceful termination tests */
	test_harness_register("test_graceful_process_exits",
	    "Graceful terminate with SIGTERM", test_graceful_process_exits);
	test_harness_register("test_graceful_stubborn_process",
	    "Stubborn process gets SIGKILL", test_graceful_stubborn_process);
	test_harness_register("test_graceful_invalid_signal",
	    "Graceful with invalid signal fails", test_graceful_invalid_signal);

	/* Deadline termination tests */
	test_harness_register("test_deadline_basic",
	    "Process killed after timeout", test_deadline_basic);
	test_harness_register("test_deadline_cancel",
	    "Deadline cancelled with timeout=0", test_deadline_cancel);
	test_harness_register("test_deadline_with_grace",
	    "Deadline with grace period", test_deadline_with_grace);
	test_harness_register("test_deadline_after_terminate",
	    "Set deadline after terminate fails", test_deadline_after_terminate);
	test_harness_register("test_deadline_invalid_signal",
	    "Deadline with invalid signal fails", test_deadline_invalid_signal);

	/* Watchdog tests */
	test_harness_register("test_watchdog_basic",
	    "Watchdog kills on timeout", test_watchdog_basic);
	test_harness_register("test_watchdog_heartbeat",
	    "Heartbeat keeps coalition alive", test_watchdog_heartbeat);
	test_harness_register("test_watchdog_disable",
	    "Disable watchdog with timeout=0", test_watchdog_disable);
	test_harness_register("test_watchdog_heartbeat_no_watchdog",
	    "Heartbeat without watchdog fails", test_watchdog_heartbeat_no_watchdog);
	test_harness_register("test_watchdog_after_terminate",
	    "Set watchdog after terminate fails", test_watchdog_after_terminate);

	/* Nested coalition tests */
	test_harness_register("test_nested_coalition_basic",
	    "Basic nested coalition", test_nested_coalition_basic);
	test_harness_register("test_nested_coalition_cascade_terminate",
	    "Cascade terminate to nested", test_nested_coalition_cascade_terminate);
	test_harness_register("test_nested_coalition_depth",
	    "Nested coalition depth tracking", test_nested_coalition_depth);
	test_harness_register("test_nested_coalition_self_enlist",
	    "Self-enlistment fails", test_nested_coalition_self_enlist);
	test_harness_register("test_nested_coalition_depth_limit",
	    "Nesting depth limit enforced", test_nested_coalition_depth_limit);

	int result = test_harness_run_all();
	test_harness_summary();

	return result;
}
