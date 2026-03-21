/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * Test helper program for coalition tests.
 *
 * Usage:
 *   test_helper sleep <seconds>     - Sleep for N seconds
 *   test_helper join <fd>           - Join coalition on fd, then sleep
 *   test_helper exit <code>         - Exit with code
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vbsd_coalition.h"

static void
usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  test_helper sleep <seconds>\n");
	fprintf(stderr, "  test_helper join <fd>\n");
	fprintf(stderr, "  test_helper exit <code>\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	if (argc < 2)
		usage();

	if (strcmp(argv[1], "sleep") == 0) {
		if (argc < 3)
			usage();
		int secs = atoi(argv[2]);
		sleep(secs);
		return 0;
	}

	if (strcmp(argv[1], "join") == 0) {
		if (argc < 3)
			usage();
		int fd = atoi(argv[2]);
		if (ioctl(fd, VBSD_COALITION_JOIN) < 0) {
			perror("VBSD_COALITION_JOIN");
			return 1;
		}
		/* Sleep indefinitely after joining */
		while (1)
			sleep(3600);
		return 0;
	}

	if (strcmp(argv[1], "exit") == 0) {
		if (argc < 3)
			usage();
		int code = atoi(argv[2]);
		return code;
	}

	usage();
	return 2;
}
