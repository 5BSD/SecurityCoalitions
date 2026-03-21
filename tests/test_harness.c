/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * Minimal test harness implementation.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "test_harness.h"
#include "vbsd_coalition.h"

#define MAX_TESTS 128

static struct test_entry tests[MAX_TESTS];
static int num_tests = 0;
static int passed = 0;
static int failed = 0;

void
test_harness_init(void)
{
	num_tests = 0;
	passed = 0;
	failed = 0;
}

void
test_harness_register(const char *name, const char *desc, test_fn fn)
{
	if (num_tests >= MAX_TESTS) {
		fprintf(stderr, "Too many tests registered\n");
		exit(1);
	}
	tests[num_tests].name = name;
	tests[num_tests].description = desc;
	tests[num_tests].fn = fn;
	num_tests++;
}

int
test_harness_run_all(void)
{
	struct test_result result;
	int i;

	printf("\nRunning %d tests...\n\n", num_tests);

	for (i = 0; i < num_tests; i++) {
		printf("[%3d/%3d] %-40s ", i + 1, num_tests, tests[i].name);
		fflush(stdout);

		result = tests[i].fn();

		if (result.passed) {
			printf("\033[32mPASS\033[0m\n");
			passed++;
		} else {
			printf("\033[31mFAIL\033[0m\n");
			if (result.message)
				printf("         %s\n", result.message);
			failed++;
		}

		/*
		 * Cleanup between tests:
		 * 1. Reap any zombie children from previous tests
		 * 2. Small delay for kernel cleanup
		 */
		while (waitpid(-1, NULL, WNOHANG) > 0)
			;
		usleep(50000);  /* 50ms delay */
	}

	return (failed > 0 ? 1 : 0);
}

void
test_harness_summary(void)
{
	printf("\n");
	printf("===========================================\n");
	printf("Results: %d passed, %d failed, %d total\n",
	    passed, failed, num_tests);
	printf("===========================================\n");

	if (failed == 0)
		printf("\033[32mAll tests passed!\033[0m\n");
	else
		printf("\033[31m%d test(s) failed!\033[0m\n", failed);
}

/*
 * Utility: Create a new coalition and return fd.
 * Each open of /dev/coalition creates a new coalition.
 */
int
create_coalition(void)
{
	int fd;

	fd = open("/dev/coalition", O_RDWR);
	if (fd < 0 && errno == ENOENT) {
		fprintf(stderr, "ERROR: /dev/coalition not found.\n");
		fprintf(stderr, "Is the vbsd_coalition module loaded?\n");
		fprintf(stderr, "Run: kldload ./sys/modules/vbsd_coalition/vbsd_coalition.ko\n");
	}
	return fd;
}

/*
 * Utility: Wait for child and return exit status
 */
int
wait_for_child(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) < 0)
		return -1;

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return -1;
}
