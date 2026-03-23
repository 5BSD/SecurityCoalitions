/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * Stress tests for vbsd_coalition module.
 * These tests simulate real-world usage patterns:
 * - Long-running service daemons managing worker coalitions
 * - Serverless/ephemeral rapid coalition lifecycle
 * - Concurrent operations under load
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "vbsd_coalition.h"

/* Test configuration */
#define DEFAULT_ITERATIONS	100
#define DEFAULT_WORKERS		5
#define DEFAULT_DURATION_SEC	30
#define WORKER_LIFETIME_MS	500
#define SERVERLESS_ITERATIONS	500

static int verbose = 0;
static volatile sig_atomic_t stop_flag = 0;

static void
sigint_handler(int sig __unused)
{
	stop_flag = 1;
}

static void
log_msg(const char *fmt, ...)
{
	va_list ap;
	struct timeval tv;

	if (!verbose)
		return;

	gettimeofday(&tv, NULL);
	printf("[%ld.%03ld] ", (long)tv.tv_sec % 1000, tv.tv_usec / 1000);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	fflush(stdout);
}

static int
create_coalition(void)
{
	int fd, flags;

	fd = open("/dev/vbsd_coalition", O_RDWR | O_CLOFORK);
	if (fd < 0)
		return (-1);

	/* Ensure FD_CLOFORK is set */
	flags = fcntl(fd, F_GETFD);
	if (flags >= 0)
		(void)fcntl(fd, F_SETFD, flags | FD_CLOFORK);

	return (fd);
}

static int
waitpid_timeout(pid_t pid, int *status, int timeout_ms)
{
	const int step_ms = 10;
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

/* Reap any zombie children */
static int
reap_zombies(void)
{
	int count = 0;
	while (waitpid(-1, NULL, WNOHANG) > 0)
		count++;
	return (count);
}

/* =========================================================================
 * WORKER PROCESS SIMULATION
 * ========================================================================= */

/*
 * Simulate a worker process that does some "work" then exits or waits.
 * work_type:
 *   0 = busy work (CPU)
 *   1 = I/O simulation (sleep with occasional wake)
 *   2 = memory allocation
 *   3 = just pause (wait for signal)
 */
static void
worker_process(int work_type, int duration_ms)
{
	volatile int x = 0;
	int elapsed = 0;

	switch (work_type) {
	case 0: /* CPU work */
		while (elapsed < duration_ms && !stop_flag) {
			for (int i = 0; i < 100000; i++)
				x += i;
			usleep(1000);
			elapsed++;
		}
		break;

	case 1: /* I/O simulation */
		while (elapsed < duration_ms && !stop_flag) {
			usleep(50000);  /* 50ms sleep */
			elapsed += 50;
		}
		break;

	case 2: /* Memory work */
		while (elapsed < duration_ms && !stop_flag) {
			void *p = malloc(4096);
			if (p) {
				memset(p, 0xAA, 4096);
				free(p);
			}
			usleep(10000);
			elapsed += 10;
		}
		break;

	case 3: /* Wait for signal */
	default:
		pause();
		break;
	}

	_exit(0);
}

/* =========================================================================
 * TEST 1: SERVICE DAEMON PATTERN
 *
 * Simulates a long-running service manager that:
 * - Creates coalitions for "jobs"
 * - Spawns worker processes for each job
 * - Terminates jobs after some time
 * - Repeats continuously
 * ========================================================================= */

struct job {
	int		coal_fd;
	int		*proc_fds;
	pid_t		*pids;
	int		worker_count;
	struct timeval	start_time;
};

static int
job_create(struct job *j, int worker_count)
{
	int sync_pipe[2];
	char buf;
	int i;

	memset(j, 0, sizeof(*j));
	j->worker_count = worker_count;
	j->proc_fds = calloc(worker_count, sizeof(int));
	j->pids = calloc(worker_count, sizeof(pid_t));

	if (!j->proc_fds || !j->pids) {
		free(j->proc_fds);
		free(j->pids);
		return (-1);
	}

	/* Initialize to -1 for cleanup tracking */
	for (i = 0; i < worker_count; i++) {
		j->proc_fds[i] = -1;
		j->pids[i] = -1;
	}

	j->coal_fd = create_coalition();
	if (j->coal_fd < 0) {
		free(j->proc_fds);
		free(j->pids);
		return (-1);
	}

	if (pipe(sync_pipe) < 0) {
		close(j->coal_fd);
		free(j->proc_fds);
		free(j->pids);
		return (-1);
	}

	gettimeofday(&j->start_time, NULL);

	/* Spawn workers */
	for (i = 0; i < worker_count; i++) {
		j->pids[i] = pdfork(&j->proc_fds[i], 0);
		if (j->pids[i] < 0) {
			/* Cleanup on failure */
			close(sync_pipe[0]);
			close(sync_pipe[1]);
			goto fail;
		}

		if (j->pids[i] == 0) {
			/* Child: close inherited fds, signal ready, do work */
			close(j->coal_fd);
			close(sync_pipe[0]);
			/* Close any inherited sibling proc_fds */
			for (int k = 0; k < i; k++) {
				if (j->proc_fds[k] >= 0)
					close(j->proc_fds[k]);
			}
			(void)write(sync_pipe[1], "R", 1);
			close(sync_pipe[1]);

			/* Do work based on worker index */
			worker_process(i % 4, WORKER_LIFETIME_MS);
			_exit(0);
		}
	}

	/* Wait for all workers to signal ready */
	close(sync_pipe[1]);
	for (i = 0; i < worker_count; i++) {
		if (read(sync_pipe[0], &buf, 1) != 1) {
			close(sync_pipe[0]);
			goto fail;
		}
	}
	close(sync_pipe[0]);

	/* Enlist all workers */
	struct vbsd_enlist_set es = {
		.fds = j->proc_fds,
		.count = worker_count,
		.enlisted = 0,
	};

	if (ioctl(j->coal_fd, VBSD_COALITION_ENLIST_SET, &es) != 0) {
		log_msg("ENLIST_SET failed: %s\n", strerror(errno));
		goto fail;
	}

	if ((int)es.enlisted != worker_count) {
		log_msg("ENLIST_SET: only %u of %d enlisted\n",
		    es.enlisted, worker_count);
		goto fail;
	}

	log_msg("Job created: coal_fd=%d, %d workers\n", j->coal_fd, worker_count);
	return (0);

fail:
	for (i = 0; i < worker_count; i++) {
		if (j->proc_fds[i] >= 0) {
			pdkill(j->proc_fds[i], SIGKILL);
			close(j->proc_fds[i]);
		}
		if (j->pids[i] > 0)
			waitpid(j->pids[i], NULL, 0);
	}
	if (j->coal_fd >= 0)
		close(j->coal_fd);
	free(j->proc_fds);
	free(j->pids);
	return (-1);
}

static int
job_terminate(struct job *j, int use_graceful)
{
	int status;
	int failed = 0;
	int i;
	struct timeval end_time;
	long elapsed_ms;

	gettimeofday(&end_time, NULL);
	elapsed_ms = (end_time.tv_sec - j->start_time.tv_sec) * 1000 +
	    (end_time.tv_usec - j->start_time.tv_usec) / 1000;

	log_msg("Terminating job (coal_fd=%d) after %ldms\n",
	    j->coal_fd, elapsed_ms);

	if (use_graceful) {
		struct vbsd_graceful g = {
			.vg_signal = SIGTERM,
			.vg_timeout_ms = 1000,
		};
		if (ioctl(j->coal_fd, VBSD_COALITION_TERMINATE_GRACEFUL, &g) != 0) {
			log_msg("TERMINATE_GRACEFUL failed: %s\n", strerror(errno));
		}
	}

	/* Close coalition - triggers termination */
	close(j->coal_fd);
	j->coal_fd = -1;

	/* Wait for all workers to exit */
	for (i = 0; i < j->worker_count; i++) {
		if (j->pids[i] <= 0)
			continue;

		if (waitpid_timeout(j->pids[i], &status, 5000) != 0) {
			int alive = (kill(j->pids[i], 0) == 0);
			fprintf(stderr, "ERROR: Worker %d (pid %d) did not exit "
			    "(alive=%s)\n", i, (int)j->pids[i],
			    alive ? "yes" : "no");

			/* Force kill */
			if (alive) {
				pdkill(j->proc_fds[i], SIGKILL);
				waitpid(j->pids[i], NULL, 0);
			}
			failed++;
		}

		if (j->proc_fds[i] >= 0) {
			close(j->proc_fds[i]);
			j->proc_fds[i] = -1;
		}
	}

	free(j->proc_fds);
	free(j->pids);
	j->proc_fds = NULL;
	j->pids = NULL;

	return (failed > 0 ? -1 : 0);
}

static int
test_service_daemon(int duration_sec, int max_concurrent_jobs, int workers_per_job)
{
	struct job *jobs;
	int *job_active;
	struct timeval start, now;
	int total_jobs = 0;
	int total_failures = 0;
	int active_count = 0;
	int i;

	printf("\n=== SERVICE DAEMON TEST ===\n");
	printf("Duration: %d seconds\n", duration_sec);
	printf("Max concurrent jobs: %d\n", max_concurrent_jobs);
	printf("Workers per job: %d\n", workers_per_job);
	printf("\n");

	jobs = calloc(max_concurrent_jobs, sizeof(struct job));
	job_active = calloc(max_concurrent_jobs, sizeof(int));
	if (!jobs || !job_active) {
		free(jobs);
		free(job_active);
		return (-1);
	}

	gettimeofday(&start, NULL);

	while (!stop_flag) {
		gettimeofday(&now, NULL);
		long elapsed = now.tv_sec - start.tv_sec;
		if (elapsed >= duration_sec)
			break;

		/* Try to start a new job if we have capacity */
		if (active_count < max_concurrent_jobs) {
			for (i = 0; i < max_concurrent_jobs; i++) {
				if (!job_active[i]) {
					if (job_create(&jobs[i], workers_per_job) == 0) {
						job_active[i] = 1;
						active_count++;
						total_jobs++;
					}
					break;
				}
			}
		}

		/* Check if any jobs should be terminated */
		for (i = 0; i < max_concurrent_jobs; i++) {
			if (!job_active[i])
				continue;

			gettimeofday(&now, NULL);
			long job_elapsed = (now.tv_sec - jobs[i].start_time.tv_sec) * 1000 +
			    (now.tv_usec - jobs[i].start_time.tv_usec) / 1000;

			/* Terminate jobs older than WORKER_LIFETIME_MS */
			if (job_elapsed >= WORKER_LIFETIME_MS) {
				if (job_terminate(&jobs[i], (total_jobs % 2) == 0) != 0)
					total_failures++;
				job_active[i] = 0;
				active_count--;
			}
		}

		/* Brief sleep to avoid spinning */
		usleep(10000);  /* 10ms */

		/* Progress indicator */
		if (total_jobs % 20 == 0 && total_jobs > 0) {
			printf("  Jobs completed: %d (failures: %d)\r",
			    total_jobs, total_failures);
			fflush(stdout);
		}
	}

	/* Cleanup any remaining active jobs */
	for (i = 0; i < max_concurrent_jobs; i++) {
		if (job_active[i]) {
			if (job_terminate(&jobs[i], 0) != 0)
				total_failures++;
		}
	}

	/* Reap any remaining zombies */
	reap_zombies();

	printf("\n\nService daemon test complete:\n");
	printf("  Total jobs: %d\n", total_jobs);
	printf("  Failures: %d\n", total_failures);

	free(jobs);
	free(job_active);

	return (total_failures > 0 ? 1 : 0);
}

/* =========================================================================
 * TEST 2: SERVERLESS PATTERN
 *
 * Simulates rapid-fire ephemeral workloads:
 * - Create coalition
 * - Spawn 1-3 workers
 * - Execute brief "function"
 * - Terminate and destroy immediately
 * - Repeat as fast as possible
 * ========================================================================= */

static int
test_serverless_single(int worker_count)
{
	int coal_fd;
	int *proc_fds;
	pid_t *pids;
	int sync_pipe[2];
	char buf;
	int i, status;
	int failed = 0;

	proc_fds = calloc(worker_count, sizeof(int));
	pids = calloc(worker_count, sizeof(pid_t));
	if (!proc_fds || !pids) {
		free(proc_fds);
		free(pids);
		return (-1);
	}

	for (i = 0; i < worker_count; i++) {
		proc_fds[i] = -1;
		pids[i] = -1;
	}

	coal_fd = create_coalition();
	if (coal_fd < 0) {
		free(proc_fds);
		free(pids);
		return (-1);
	}

	if (pipe(sync_pipe) < 0) {
		close(coal_fd);
		free(proc_fds);
		free(pids);
		return (-1);
	}

	/* Create workers */
	for (i = 0; i < worker_count; i++) {
		pids[i] = pdfork(&proc_fds[i], 0);
		if (pids[i] < 0) {
			failed = 1;
			break;
		}

		if (pids[i] == 0) {
			/* Child */
			close(coal_fd);
			close(sync_pipe[0]);
			for (int k = 0; k < i; k++)
				if (proc_fds[k] >= 0)
					close(proc_fds[k]);
			write(sync_pipe[1], "R", 1);
			close(sync_pipe[1]);

			/* Brief "serverless function" work */
			usleep(1000 + (rand() % 5000));  /* 1-6ms */
			_exit(0);
		}
	}

	close(sync_pipe[1]);

	if (!failed) {
		/* Wait for all workers ready */
		for (i = 0; i < worker_count; i++) {
			if (read(sync_pipe[0], &buf, 1) != 1) {
				failed = 1;
				break;
			}
		}
	}
	close(sync_pipe[0]);

	if (!failed) {
		/* Enlist all workers */
		struct vbsd_enlist_set es = {
			.fds = proc_fds,
			.count = worker_count,
			.enlisted = 0,
		};

		if (ioctl(coal_fd, VBSD_COALITION_ENLIST_SET, &es) != 0 ||
		    (int)es.enlisted != worker_count) {
			failed = 1;
		}
	}

	/* Terminate (close coalition) */
	close(coal_fd);

	/* Wait for workers with short timeout */
	for (i = 0; i < worker_count; i++) {
		if (pids[i] <= 0)
			continue;

		if (waitpid_timeout(pids[i], &status, 2000) != 0) {
			int alive = (kill(pids[i], 0) == 0);
			if (alive) {
				fprintf(stderr, "ERROR: Serverless worker %d "
				    "(pid %d) still alive!\n", i, (int)pids[i]);
				pdkill(proc_fds[i], SIGKILL);
				waitpid(pids[i], NULL, 0);
			}
			failed = 1;
		}

		if (proc_fds[i] >= 0)
			close(proc_fds[i]);
	}

	free(proc_fds);
	free(pids);

	return (failed ? -1 : 0);
}

static int
test_serverless(int iterations)
{
	int failures = 0;
	int i;
	struct timeval start, end;

	printf("\n=== SERVERLESS PATTERN TEST ===\n");
	printf("Iterations: %d\n\n", iterations);

	gettimeofday(&start, NULL);

	for (i = 0; i < iterations && !stop_flag; i++) {
		int worker_count = 1 + (rand() % 3);  /* 1-3 workers */

		if (test_serverless_single(worker_count) != 0)
			failures++;

		/* Reap zombies periodically */
		if (i % 10 == 0)
			reap_zombies();

		if (i % 50 == 0) {
			printf("  Iteration %d/%d (failures: %d)\r",
			    i, iterations, failures);
			fflush(stdout);
		}
	}

	gettimeofday(&end, NULL);
	reap_zombies();

	long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
	    (end.tv_usec - start.tv_usec) / 1000;

	printf("\n\nServerless test complete:\n");
	printf("  Iterations: %d\n", i);
	printf("  Failures: %d\n", failures);
	printf("  Time: %ldms (%.1f invocations/sec)\n",
	    elapsed_ms, (float)i * 1000 / elapsed_ms);

	return (failures > 0 ? 1 : 0);
}

/* =========================================================================
 * TEST 3: CONCURRENT STRESS TEST
 *
 * Multiple threads/processes operating on coalitions simultaneously
 * ========================================================================= */

static int
test_concurrent_stress(int num_managers, int duration_sec)
{
	pid_t *managers;
	int *status_codes;
	int i, status;
	int total_failures = 0;

	printf("\n=== CONCURRENT STRESS TEST ===\n");
	printf("Managers: %d\n", num_managers);
	printf("Duration: %d seconds each\n\n", duration_sec);

	managers = calloc(num_managers, sizeof(pid_t));
	status_codes = calloc(num_managers, sizeof(int));
	if (!managers || !status_codes) {
		free(managers);
		free(status_codes);
		return (-1);
	}

	/* Fork manager processes */
	for (i = 0; i < num_managers; i++) {
		managers[i] = fork();
		if (managers[i] < 0) {
			perror("fork");
			continue;
		}

		if (managers[i] == 0) {
			/* Child: run serverless tests */
			srand(getpid());
			int result = test_serverless(100);
			_exit(result);
		}
	}

	/* Wait for all managers */
	for (i = 0; i < num_managers; i++) {
		if (managers[i] <= 0)
			continue;

		if (waitpid(managers[i], &status, 0) == managers[i]) {
			if (WIFEXITED(status)) {
				status_codes[i] = WEXITSTATUS(status);
				if (status_codes[i] != 0)
					total_failures++;
			} else {
				total_failures++;
			}
		}
	}

	printf("\nConcurrent stress test complete:\n");
	printf("  Managers: %d\n", num_managers);
	printf("  Failures: %d\n", total_failures);

	free(managers);
	free(status_codes);

	return (total_failures > 0 ? 1 : 0);
}

/* =========================================================================
 * TEST 4: RAPID CREATE/DESTROY CYCLE
 *
 * Tests for resource leaks by rapidly creating and destroying coalitions
 * ========================================================================= */

static int
test_rapid_lifecycle(int iterations)
{
	int i;
	int failures = 0;
	int coal_fd;
	struct timeval start, end;

	printf("\n=== RAPID LIFECYCLE TEST ===\n");
	printf("Iterations: %d\n\n", iterations);

	gettimeofday(&start, NULL);

	for (i = 0; i < iterations && !stop_flag; i++) {
		coal_fd = create_coalition();
		if (coal_fd < 0) {
			failures++;
			continue;
		}

		/* Optionally do a stat */
		if (i % 3 == 0) {
			struct vbsd_coalition_stat st;
			ioctl(coal_fd, VBSD_COALITION_STAT, &st);
		}

		close(coal_fd);

		if (i % 1000 == 0) {
			printf("  Iteration %d/%d\r", i, iterations);
			fflush(stdout);
		}
	}

	gettimeofday(&end, NULL);

	long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
	    (end.tv_usec - start.tv_usec) / 1000;

	printf("\n\nRapid lifecycle test complete:\n");
	printf("  Iterations: %d\n", i);
	printf("  Failures: %d\n", failures);
	printf("  Time: %ldms (%.0f ops/sec)\n",
	    elapsed_ms, (float)i * 1000 / elapsed_ms);

	return (failures > 0 ? 1 : 0);
}

/* =========================================================================
 * MAIN
 * ========================================================================= */

static void
usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options] [test...]\n", progname);
	fprintf(stderr, "\nTests:\n");
	fprintf(stderr, "  daemon     - Long-running service daemon pattern\n");
	fprintf(stderr, "  serverless - Rapid ephemeral workload pattern\n");
	fprintf(stderr, "  concurrent - Multiple concurrent managers\n");
	fprintf(stderr, "  lifecycle  - Rapid create/destroy cycles\n");
	fprintf(stderr, "  all        - Run all tests (default)\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -v         - Verbose output\n");
	fprintf(stderr, "  -d SEC     - Duration for timed tests (default: %d)\n",
	    DEFAULT_DURATION_SEC);
	fprintf(stderr, "  -i NUM     - Iterations for counted tests (default: %d)\n",
	    DEFAULT_ITERATIONS);
	fprintf(stderr, "  -w NUM     - Workers per job (default: %d)\n",
	    DEFAULT_WORKERS);
}

int
main(int argc, char *argv[])
{
	int ch;
	int duration = DEFAULT_DURATION_SEC;
	int iterations = DEFAULT_ITERATIONS;
	int workers = DEFAULT_WORKERS;
	int run_daemon = 0, run_serverless = 0, run_concurrent = 0, run_lifecycle = 0;
	int result = 0;

	/* Check if device exists */
	if (access("/dev/vbsd_coalition", F_OK) != 0) {
		fprintf(stderr, "ERROR: /dev/vbsd_coalition not found.\n");
		fprintf(stderr, "Is the vbsd_coalition module loaded?\n");
		return (1);
	}

	while ((ch = getopt(argc, argv, "vd:i:w:h")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		case 'd':
			duration = atoi(optarg);
			break;
		case 'i':
			iterations = atoi(optarg);
			break;
		case 'w':
			workers = atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			return (ch == 'h' ? 0 : 1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Parse test names */
	if (argc == 0) {
		/* Run all tests by default */
		run_daemon = run_serverless = run_concurrent = run_lifecycle = 1;
	} else {
		for (int i = 0; i < argc; i++) {
			if (strcmp(argv[i], "daemon") == 0)
				run_daemon = 1;
			else if (strcmp(argv[i], "serverless") == 0)
				run_serverless = 1;
			else if (strcmp(argv[i], "concurrent") == 0)
				run_concurrent = 1;
			else if (strcmp(argv[i], "lifecycle") == 0)
				run_lifecycle = 1;
			else if (strcmp(argv[i], "all") == 0)
				run_daemon = run_serverless = run_concurrent = run_lifecycle = 1;
			else {
				fprintf(stderr, "Unknown test: %s\n", argv[i]);
				usage(argv[0]);
				return (1);
			}
		}
	}

	/* Setup signal handler for clean shutdown */
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	srand(time(NULL) ^ getpid());

	printf("vBSD Coalition Stress Tests\n");
	printf("============================\n");

	if (run_lifecycle) {
		if (test_rapid_lifecycle(iterations * 100) != 0)
			result = 1;
	}

	if (run_serverless && !stop_flag) {
		if (test_serverless(SERVERLESS_ITERATIONS) != 0)
			result = 1;
	}

	if (run_daemon && !stop_flag) {
		if (test_service_daemon(duration, 3, workers) != 0)
			result = 1;
	}

	if (run_concurrent && !stop_flag) {
		if (test_concurrent_stress(4, duration / 2) != 0)
			result = 1;
	}

	printf("\n============================\n");
	if (result == 0)
		printf("\033[32mAll stress tests PASSED\033[0m\n");
	else
		printf("\033[31mSome stress tests FAILED\033[0m\n");

	return (result);
}
