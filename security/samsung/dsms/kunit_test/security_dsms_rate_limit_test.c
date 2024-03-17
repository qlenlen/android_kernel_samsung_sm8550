/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/mock.h>
#include <kunit/test.h>
#include <linux/dsms.h>
#include <linux/errno.h>
#include "dsms_rate_limit.h"
#include "dsms_test.h"

/* Must have the same values as defined in dsms_rate_limit.c */
#define ROUND_DURATION_MS ((u64)(1000L))
#define MAX_MESSAGES_PER_ROUND (50)

static u64 start_ms;

/* ------------------------------------------------------------------------- */
/* Module test functions                                                     */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* File: dsms_rate_limit.c                                                   */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_get_max_messages_per_round                    */
/* ------------------------------------------------------------------------- */

/*
 * get_max_messages_per_round_test()
 * Check the correct return value for max messages per round.
 * Expected: Function should return value of MAX_MESSAGES_PER_ROUND.
 */
static void security_dsms_get_max_messages_per_round_test(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, dsms_get_max_messages_per_round() > 0);
	KUNIT_EXPECT_EQ(test, MAX_MESSAGES_PER_ROUND, dsms_get_max_messages_per_round());
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: round_end_ms                                       */
/* ------------------------------------------------------------------------- */

/*
 * round_end_ms_test()
 * Verify if round end time is correctly calculated.
 * Expected: Function should return the round end time, which is equal
 * to the start time plus the round duration.
 */
static void security_dsms_round_end_ms_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, start_ms + ROUND_DURATION_MS, round_end_ms(start_ms));
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: is_new_round                                       */
/* ------------------------------------------------------------------------- */

/*
 * is_new_round_test()
 * Check the correct return of the function for the test cases when a new
 * round has started or not.
 * Expected: Function should return 0 if a new round has not started, else should
 * return 1.
 */
static void security_dsms_is_new_round_test(struct kunit *test)
{
	u64 now_ms = dsms_get_time_ms();

	KUNIT_EXPECT_EQ(test, 0, is_new_round(now_ms, start_ms));
	KUNIT_EXPECT_EQ(test, 1, is_new_round(start_ms + ROUND_DURATION_MS + 1, start_ms));
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_check_message_rate_limit                      */
/* ------------------------------------------------------------------------- */

/*
 * check_message_rate_limit_deny_test()
 * Test case when the message rate is higher than the max rate per round.
 * Expected: Function should return DSMS_DENY if the rate limit is reached.
 */
static void security_dsms_check_message_rate_limit_deny_test(struct kunit *test)
{
	int failed = 0, i;

	for (i = dsms_get_max_messages_per_round(); i >= 0; --i)
		if (dsms_check_message_rate_limit() == DSMS_DENY)
			failed = 1;
	KUNIT_EXPECT_TRUE(test, failed);
}

/*
 * check_message_rate_limit_success_test()
 * Test case when the message rate is lower than the max rate per round.
 * Expected: Function should return DSMS_SUCCESS if the rate limit is not
 * reached.
 */
static void security_dsms_check_message_rate_limit_success_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, DSMS_SUCCESS, dsms_check_message_rate_limit());
}

/*
 * check_message_rate_limit_boundary_test()
 * Test boundary cases (simulate clock wrapped, too many messages).
 * Expected: Function should return DSMS_SUCCESS and reset the message count
 * to zero.
 */
static void security_dsms_check_message_rate_limit_boundary_test(struct kunit *test)
{
	int old_count;

	dsms_round_start_ms -= 10;
	KUNIT_EXPECT_EQ(test, DSMS_SUCCESS, dsms_check_message_rate_limit());
	old_count = dsms_message_count;
	dsms_round_start_ms = 0;
	dsms_message_count = dsms_get_max_messages_per_round() + 1;
	KUNIT_EXPECT_EQ(test, DSMS_SUCCESS, dsms_check_message_rate_limit());
	KUNIT_EXPECT_EQ(test, dsms_message_count, 0);
	dsms_message_count = old_count;
}

/*
 * dsms_check_message_rate_limit_reset_test
 * This test sets the "dsms_round_start_ms" variable to the maximum value
 * of an unsigned 64 bit type (2^64 - 1). Such modification triggers the
 * "[rate limit] RESET" case on "dsms_check_message_rate_limit" function.
 * Expected: Function should return DSMS_SUCCESS and reset the message count
 * to zero.
 */
static void security_dsms_check_message_rate_limit_reset_test(struct kunit *test)
{
	dsms_round_start_ms = -1;
	KUNIT_EXPECT_EQ(test, DSMS_SUCCESS, dsms_check_message_rate_limit());
	KUNIT_EXPECT_EQ(test, dsms_message_count, 1);
}

/* ------------------------------------------------------------------------- */
/* Module initialization and exit functions                                  */
/* ------------------------------------------------------------------------- */

static int security_dsms_rate_test_init(struct kunit *test)
{
	dsms_rate_limit_init();
	start_ms = dsms_get_time_ms();
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Module definition                                                         */
/* ------------------------------------------------------------------------- */

static struct kunit_case security_dsms_rate_test_cases[] = {
	KUNIT_CASE(security_dsms_get_max_messages_per_round_test),
	KUNIT_CASE(security_dsms_round_end_ms_test),
	KUNIT_CASE(security_dsms_is_new_round_test),
	KUNIT_CASE(security_dsms_check_message_rate_limit_deny_test),
	KUNIT_CASE(security_dsms_check_message_rate_limit_success_test),
	KUNIT_CASE(security_dsms_check_message_rate_limit_boundary_test),
	KUNIT_CASE(security_dsms_check_message_rate_limit_reset_test),
	{},
};

static struct kunit_suite security_dsms_rate_test_module = {
	.name = "security-dsms-rate-limit-test",
	.init = security_dsms_rate_test_init,
	.test_cases = security_dsms_rate_test_cases,
};
kunit_test_suites(&security_dsms_rate_test_module);
