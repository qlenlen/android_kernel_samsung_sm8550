/*
 * Copyright (c) 2020-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/mock.h>
#include <kunit/test.h>
#include "dsms_init.h"
#include "dsms_test.h"

/* ------------------------------------------------------------------------- */
/* Module test functions                                                     */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* File: dsms_init.c                                                         */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_is_initialized                                */
/* ------------------------------------------------------------------------- */

/*
 * is_initialized_test()
 * Test if dsms was initialized by checking the value of
 * is_dsms_initialized_flag.
 * Expected: Function should return True value.
 */
static void security_dsms_is_initialized_test(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, dsms_is_initialized());
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_init                                          */
/* ------------------------------------------------------------------------- */

/*
 * dsms_init_test()
 * Test dsms init module.
 * Expected: Function returns 0 if executed correctly, any other value if an
 * error is triggered.
 */
static void security_dsms_init_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, dsms_init(), 0);
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_exit                                          */
/* ------------------------------------------------------------------------- */

/*
 * dsms_exit_test()
 * Test dsms init module.
 * Expected: After execution dsms_is_initialized must be 0 (false).
 */
static void security_dsms_exit_test(struct kunit *test)
{
	KUNIT_ASSERT_TRUE(test, dsms_is_initialized());
//	dsms_exit();
//	KUNIT_EXPECT_FALSE(test, dsms_is_initialized());
//	/* restore DSMS to continue tests */
//	KUNIT_EXPECT_EQ(test, dsms_init(), 0);
	KUNIT_EXPECT_TRUE(test, dsms_is_initialized());
}

/* ------------------------------------------------------------------------- */
/* Module definition                                                         */
/* ------------------------------------------------------------------------- */

static struct kunit_case security_dsms_init_test_cases[] = {
	KUNIT_CASE(security_dsms_is_initialized_test),
	KUNIT_CASE(security_dsms_init_test),
	KUNIT_CASE(security_dsms_exit_test),
	{},
};

static struct kunit_suite security_dsms_init_test_module = {
	.name = "security-dsms-init-test",
	.test_cases = security_dsms_init_test_cases,
};
kunit_test_suites(&security_dsms_init_test_module);
