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
#include <linux/slab.h>
#include <linux/types.h>
#include "dsms_kernel_api.h"
#include "dsms_test.h"
#include "dsms_test_utils.h"

/* ------------------------------------------------------------------------- */
/* Module test functions                                                     */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* File: dsms_kernel_api.c                                                   */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_send_message                                  */
/* ------------------------------------------------------------------------- */

/*
 * security_dsms_send_message()
 * Helper function to send messages during tests, whitelisted on eng builds.
 */
static noinline int security_dsms_test_send_message(const char *feature_code,
						    const char *detail,
						    int64_t value)
{
	return dsms_send_message(feature_code, detail, value);
}

/*
 * security_dsms_send_message_success_test()
 * Error-free test case when sending a dsms message, which means that the
 * message was created and processed successfully.
 * Expected: Function should return 0.
 */
static void security_dsms_send_message_success_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0, security_dsms_test_send_message("KATS", "kunit test", 0));
}

/*
 * security_dsms_send_message_allowlist_block_test()
 * Error-free test case when sending a dsms message, but failing to pass
 * allowlist verification.
 * Expected: Function should return 0.
 */
static void security_dsms_send_message_allowlist_block_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, DSMS_DENY, dsms_send_message("KATB", "kunit test", 0));
}

/*
 * send_message_null_feature_code_test()
 * Trigger error case for NULL feature code.
 * Expected: Function should return -EINVAL for invalid value error.
 */
static void security_dsms_send_message_null_feature_code_test(
				struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, security_dsms_test_send_message(NULL, "kunit test", 0));
}

/*
 * _send_message_rate_limit_deny_test()
 * Trigger error case when checking the message rate limit by setting the
 * message counter to max value per round.
 * Expected: Function should return DSMS_DENY.
 */
static void security_dsms_send_message_rate_limit_deny_test(struct kunit *test)
{
	int old_count;

	old_count = dsms_message_count;
	dsms_message_count = dsms_get_max_messages_per_round();
	KUNIT_EXPECT_EQ(test, DSMS_DENY, security_dsms_test_send_message("KATR", "kunit test", 0));
	dsms_message_count = old_count;
}

/* Function dsms_send_message has other error cases that are difficult to
 * trigger, possibly needing to mock certain functions.
 * TODO: Test Case when dsms_is_initialized returns False
 * TODO: Test Case when dsms_verify_access returns DSMS_DENY
 * TODO: Test Case when dsms_check_message_rate_limit returns DSMS_DENY
 */

/* ------------------------------------------------------------------------- */
/* Module definition                                                         */
/* ------------------------------------------------------------------------- */

static struct kunit_case security_dsms_kernel_api_test_cases[] = {
	KUNIT_CASE(security_dsms_send_message_success_test),
	KUNIT_CASE(security_dsms_send_message_allowlist_block_test),
	KUNIT_CASE(security_dsms_send_message_null_feature_code_test),
	KUNIT_CASE(security_dsms_send_message_rate_limit_deny_test),
	{},
};

static struct kunit_suite security_dsms_kernel_api_module = {
	.name = "security-dsms-kernel-api",
	.test_cases = security_dsms_kernel_api_test_cases,
};
kunit_test_suites(&security_dsms_kernel_api_module);
