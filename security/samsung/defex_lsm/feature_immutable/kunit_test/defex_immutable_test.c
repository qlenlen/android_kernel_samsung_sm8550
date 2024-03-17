/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <kunit/mock.h>
#include "include/defex_internal.h"
#include "include/defex_test.h"

static void immutable_status_store_test(struct kunit *test)
{
	char *invalid_prefix = "test";
	char *over_range_prefix = "5";
	char *valid_prefix = "2";

	/* buffer null */
	KUNIT_EXPECT_EQ(test, immutable_status_store(NULL), -EINVAL);
	/* invalid prefix */
	KUNIT_EXPECT_EQ(test, immutable_status_store(invalid_prefix), -EINVAL);
	/* over range prefix */
	KUNIT_EXPECT_EQ(test, immutable_status_store(over_range_prefix), -EINVAL);
	/* valid prefix */
	KUNIT_EXPECT_EQ(test, immutable_status_store(valid_prefix), 0);
}

static int defex_immutable_test_init(struct kunit *test)
{
	return 0;
}

static void defex_immutable_test_exit(struct kunit *test)
{
}

static struct kunit_case defex_immutable_test_cases[] = {
	/* TEST FUNC DEFINES */
	KUNIT_CASE(immutable_status_store_test),
	{},
};

static struct kunit_suite defex_immutable_test_module = {
	.name = "defex_immutable_test",
	.init = defex_immutable_test_init,
	.exit = defex_immutable_test_exit,
	.test_cases = defex_immutable_test_cases,
};
kunit_test_suites(&defex_immutable_test_module);
