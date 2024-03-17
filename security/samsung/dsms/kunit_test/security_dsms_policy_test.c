/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <linux/dsms.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include "dsms_access_control.h"
#include "dsms_test.h"

/* ------------------------------------------------------------------------- */
/* Module test functions                                                     */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* File: dsms_policy.c                                                       */
/* ------------------------------------------------------------------------- */

static void security_dsms_policy_test(struct kunit *test)
{
	size_t i;

	// Check whether policy entries are sorted by function_name
	for (i = dsms_policy_size(); i > 1; --i)
		KUNIT_EXPECT_TRUE(test,
			    strncmp(dsms_policy[i - 2].function_name,
				    dsms_policy[i - 1].function_name,
				    KSYM_NAME_LEN) <= 0);
}

/* ------------------------------------------------------------------------- */
/* Module definition                                                         */
/* ------------------------------------------------------------------------- */

static struct kunit_case security_dsms_policy_test_cases[] = {
	KUNIT_CASE(security_dsms_policy_test),
	{},
};

static struct kunit_suite security_dsms_policy_test_module = {
	.name = "security-dsms-policy-test",
	.test_cases = security_dsms_policy_test_cases,
};
kunit_test_suites(&security_dsms_policy_test_module);
