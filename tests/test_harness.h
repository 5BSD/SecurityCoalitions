/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * Minimal test harness for vBSD Coalition tests.
 */

#ifndef _TEST_HARNESS_H_
#define _TEST_HARNESS_H_

#include <stdbool.h>

/*
 * Test result structure
 */
struct test_result {
	const char	*name;
	bool		passed;
	const char	*message;
};

/*
 * Test function signature
 */
typedef struct test_result (*test_fn)(void);

/*
 * Test registration
 */
struct test_entry {
	const char	*name;
	const char	*description;
	test_fn		fn;
};

/*
 * Macros for defining tests
 */
#define TEST_PASS(msg) \
	((struct test_result){ .name = __func__, .passed = true, .message = (msg) })

#define TEST_FAIL(msg) \
	((struct test_result){ .name = __func__, .passed = false, .message = (msg) })

#define TEST_ASSERT(cond, msg) \
	do { \
		if (!(cond)) \
			return TEST_FAIL(msg); \
	} while (0)

#define TEST_ASSERT_EQ(a, b, msg) \
	TEST_ASSERT((a) == (b), msg)

#define TEST_ASSERT_NE(a, b, msg) \
	TEST_ASSERT((a) != (b), msg)

#define TEST_ASSERT_ERRNO(expected, msg) \
	TEST_ASSERT(errno == (expected), msg)

/*
 * Test runner functions
 */
void	test_harness_init(void);
void	test_harness_register(const char *name, const char *desc, test_fn fn);
int	test_harness_run_all(void);
void	test_harness_summary(void);

/*
 * Utility functions
 */
int	create_coalition(void);
int	wait_for_child(pid_t pid);

#endif /* _TEST_HARNESS_H_ */
