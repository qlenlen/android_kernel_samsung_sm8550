// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit test for strerror and strerror_r
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Mike Krinkin <krinkin@google.com>
 */

#include <linux/err.h>
#include <kunit/strerror.h>
#include <kunit/test.h>

static void test_strerror_returns_null_for_unknown_errors(struct kunit *test)
{
	KUNIT_EXPECT_PTR_EQ(test, strerror_str(-1), NULL);
	KUNIT_EXPECT_PTR_EQ(test, strerror_str(MAX_ERRNO + 1), NULL);
}

static void test_strerror_r_returns_null_if_buflen_is_zero(struct kunit *test)
{
	KUNIT_EXPECT_PTR_EQ(test, strerror_r(-1, NULL, 0), NULL);
}

static void test_strerror_returns_string(struct kunit *test)
{
	const char *err;
	char buf[64];

	err = strerror_str(EAGAIN);
	KUNIT_ASSERT_PTR_NE(test, err, NULL);
	KUNIT_EXPECT_STREQ(test, err, "EAGAIN");

	err = strerror_r(EAGAIN, buf, sizeof(buf));
	KUNIT_ASSERT_PTR_NE(test, err, NULL);
	KUNIT_EXPECT_STREQ(test, err, "EAGAIN");
}

static void test_strerror_r_correctly_truncates_message_to_buffer_size(
		struct kunit *test)
{
	const char *err;
	char buf[64];

	err = strerror_r(EAGAIN, buf, 1);
	KUNIT_ASSERT_PTR_NE(test, err, NULL);
	KUNIT_EXPECT_EQ(test, strlen(err), 0);

	err = strerror_r(EAGAIN, buf, 2);
	KUNIT_ASSERT_PTR_NE(test, err, NULL);
	KUNIT_EXPECT_EQ(test, strlen(err), 1);

	err = strerror_r(EAGAIN, buf, sizeof(buf));
	KUNIT_ASSERT_PTR_NE(test, err, NULL);
	KUNIT_EXPECT_STREQ(test, err, "EAGAIN");
}

static void test_strerror_r_returns_string_for_unknown_errors(struct kunit *test)
{
	char buf[64];

	KUNIT_EXPECT_PTR_NE(test, strerror_r(-1, buf, sizeof(buf)), NULL);
	KUNIT_EXPECT_PTR_NE(test, strerror_r(MAX_ERRNO + 1, buf, sizeof(buf)), NULL);
}

static struct kunit_case strerror_test_cases[] = {
	KUNIT_CASE(test_strerror_returns_null_for_unknown_errors),
	KUNIT_CASE(test_strerror_r_returns_null_if_buflen_is_zero),
	KUNIT_CASE(test_strerror_returns_string),
	KUNIT_CASE(test_strerror_r_correctly_truncates_message_to_buffer_size),
	KUNIT_CASE(test_strerror_r_returns_string_for_unknown_errors),
	{},
};

static struct kunit_suite strerror_test_module = {
	.name = "strerror-test",
	.test_cases = strerror_test_cases,
};
kunit_test_suites(&strerror_test_module);
