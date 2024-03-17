/*
 * Copyright (c) 2020-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */
#include <linux/llist.h>
#include <kunit/mock.h>
#include <kunit/test.h>
#include "dsms_kernel_api.h"
#include "dsms_netlink.h"
#include "dsms_test.h"
#include "dsms_test_utils.h"

/* ------------------------------------------------------------------------- */
/* Module test functions                                                     */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* File: dsms_netlink.c                                                      */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_daemon_ready                                  */
/* ------------------------------------------------------------------------- */

/*
 * security_dsms_daemon_ready_success_test()
 * Daemon ready test.
 * Expected: Function should return whether daemon is ready.
 */
static void security_dsms_daemon_ready_success_test(struct kunit *test)
{
	int ready;

	ready = atomic_read(&daemon_ready);
	KUNIT_EXPECT_EQ(test, dsms_daemon_ready(), ready);
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_send_netlink_message                          */
/* ------------------------------------------------------------------------- */

/*
 * send_netlink_message_test()
 * Check if a message can be sent.
 * Expected: Function should return 0.
 */
static void security_dsms_send_netlink_message_success_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, dsms_send_netlink_message("KNIT", "kunit test", 0), 0);
}

/* Function dsms_send_netlink_message has error cases that are
 * difficult to trigger, possibly needing to mock certain functions.
 * TODO: Case when genlmsg_new returns NULL
 * TODO: Case when genlmsg_put returns NULL
 * TODO: Cases when nla_put returns error (for value, feature code and detail)
 * TODO: Case when genlmsg_multicast returns error
 */

/* ------------------------------------------------------------------------- */
/* Module definition                                                         */
/* ------------------------------------------------------------------------- */

static struct kunit_case security_dsms_netlink_test_cases[] = {
	KUNIT_CASE(security_dsms_daemon_ready_success_test),
	KUNIT_CASE(security_dsms_send_netlink_message_success_test),
	{},
};

static struct kunit_suite security_dsms_netlink_module = {
	.name = "security-dsms-netlink",
	.test_cases = security_dsms_netlink_test_cases,
};
kunit_test_suites(&security_dsms_netlink_module);
