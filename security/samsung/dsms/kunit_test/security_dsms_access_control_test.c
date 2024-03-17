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
#include "dsms_access_control.h"
#include "dsms_test.h"

/* ------------------------------------------------------------------------- */
/* Test Module - dsms_access_control.c                                       */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Function to be tested: compare_policy_entries                             */
/* ------------------------------------------------------------------------- */

/*
 * compare_policy_entries_test()
 * Test the lexicographic comparison:
 *     + Positive number if str1 > str2
 *     + Negative number if str1 < str2
 *     + Zero if str1 == str2
 * Expected: Right Lexicographic comparison.
 */
static void security_dsms_compare_policy_entries_test(struct kunit *test)
{
	struct dsms_policy_entry entry;

	entry.file_path = "/path/test";
	entry.function_name = "myfunction";
	KUNIT_EXPECT_GT(test, compare_policy_entries("myfunction1", &entry), 0);
	KUNIT_EXPECT_EQ(test, compare_policy_entries("myfunction", &entry), 0);
	KUNIT_EXPECT_LT(test, compare_policy_entries("myfunct", &entry), 0);
	entry.function_name = "myfunction1";
	KUNIT_EXPECT_EQ(test, compare_policy_entries("myfunction1", &entry), 0);
	KUNIT_EXPECT_LT(test, compare_policy_entries("Myfunction", &entry), 0);
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: find_policy_entry                                  */
/* ------------------------------------------------------------------------- */

/*
 * find_policy_entry_test()
 * Use a function name that is not in dsms policy.
 * Expected: No policy should be returned.
 */
static void security_dsms_find_policy_entry_failure_test(struct kunit *test)
{
	KUNIT_EXPECT_PTR_EQ(test, (struct dsms_policy_entry *)NULL, find_policy_entry("test"));
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_policy_size                                   */
/* ------------------------------------------------------------------------- */

/*
 * security_dsms_policy_size_test()
 * Test DSMS policy size. It may vary in size, depending on build type and model.
 * Expect: At least one rule, but no more than a few entries.
 */
static void security_dsms_policy_size_valid_value_test(struct kunit *test)
{
	KUNIT_EXPECT_LT(test, (unsigned long)0, dsms_policy_size());
	KUNIT_EXPECT_GT(test, (unsigned long)10, dsms_policy_size());
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_verify_access                                 */
/* ------------------------------------------------------------------------- */

/*
 * dsms_verify_access_test()
 * Testcase with null address as input.
 * Expected: Function should check input and return DSMS_DENY when wrong input
 * is inserted.
 */
static void security_dsms_verify_access_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, DSMS_DENY, dsms_verify_access(NULL));
}

/*
 * verify_access_address_not_in_kallsyms_test()
 * Caller address not in kallsyms. Test the case where the address passed to
 * dsms_verify_access is not null and is not in the kallsyms.
 * Expected: Function returns DSMS_DENY.
 */
static void security_dsms_verify_access_address_not_in_kallsyms_test(
				struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, DSMS_DENY, dsms_verify_access((const void *)0x1));
}

/* ------------------------------------------------------------------------- */
/* Tests - dsms_access_control.h                                             */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Function to be tested: should_ignore_allowlist_suffix                     */
/* ------------------------------------------------------------------------- */

/*
 * should_ignore_allowlist_suffix_test()
 * Call should_ignore_allowlist_suffix() function.
 * Expected: Should return 0 or 1.
 */
static void security_dsms_should_ignore_allowlist_suffix_test(struct kunit *test)
{
	unsigned int result;

	result = should_ignore_allowlist_suffix();
	result &= ~1UL;
	KUNIT_EXPECT_EQ(test, (unsigned int)0UL, result);
}

/* ------------------------------------------------------------------------- */
/* Module Definition                                                         */
/* ------------------------------------------------------------------------- */

static struct kunit_case security_dsms_access_control_test_cases[] = {
	KUNIT_CASE(security_dsms_compare_policy_entries_test),
	KUNIT_CASE(security_dsms_find_policy_entry_failure_test),
	KUNIT_CASE(security_dsms_policy_size_valid_value_test),
	KUNIT_CASE(security_dsms_verify_access_test),
	KUNIT_CASE(security_dsms_verify_access_address_not_in_kallsyms_test),
	KUNIT_CASE(security_dsms_should_ignore_allowlist_suffix_test),
	{},
};

static struct kunit_suite security_dsms_access_control_test_module = {
	.name = "security-dsms-access-control-test",
	.test_cases = security_dsms_access_control_test_cases,
};
kunit_test_suites(&security_dsms_access_control_test_module);
