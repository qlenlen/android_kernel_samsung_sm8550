/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "dsms_test.h"
#include "dsms_test_utils.h"

/* ------------------------------------------------------------------------- */
/* Module test functions                                                     */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* File: test_utils.c                                                        */
/* ------------------------------------------------------------------------- */

/* By default kmalloc is defined as kmalloc_mock in dsms_test.h*/
static void security_dsms_test_kmalloc_mock_test(struct kunit *test)
{
	void *p;

	security_dsms_test_request_kmalloc_fail_at(1);
	security_dsms_test_request_kmalloc_fail_at(3);
	/* kmalloc must call security_dsms_test_kmalloc_mock */
	p = kmalloc(1, GFP_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, p, NULL);
	kfree(p);
	p = kmalloc(1, GFP_KERNEL);
	KUNIT_EXPECT_PTR_NE(test, p, NULL);
	kfree(p);
	p = kmalloc(1, GFP_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, p, NULL);
	kfree(p);
	p = kmalloc(1, GFP_KERNEL);
	KUNIT_EXPECT_PTR_NE(test, p, NULL);
	kfree(p);
}

/* ------------------------------------------------------------------------- */
/* Module initialization and exit functions                                  */
/* ------------------------------------------------------------------------- */

static int security_dsms_test_utils_init(struct kunit *test)
{
	security_dsms_test_cancel_kmalloc_fail_requests();
	return 0;
}

static void security_dsms_test_utils_exit(struct kunit *test)
{
	security_dsms_test_cancel_kmalloc_fail_requests();
}

/* ------------------------------------------------------------------------- */
/* Module definition                                                         */
/* ------------------------------------------------------------------------- */

static struct kunit_case security_dsms_test_utils_test_cases[] = {
	KUNIT_CASE(security_dsms_test_kmalloc_mock_test),
	{},
};

static struct kunit_suite security_dsms_test_utils_module = {
	.name = "security-dsms-test-utils-test",
	.init = security_dsms_test_utils_init,
	.exit = security_dsms_test_utils_exit,
	.test_cases = security_dsms_test_utils_test_cases,
};
kunit_test_suites(&security_dsms_test_utils_module);
