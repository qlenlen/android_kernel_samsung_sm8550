/*
 * Copyright (c) 2020-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/version.h>

static void defex_rules_signature_check_test(struct kunit *test)
{
	/* __init function */
	KUNIT_SUCCEED(test);
}


static void defex_public_key_verify_signature_test(struct kunit *test)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
	/* __init function */
#else
	/* Skip signature check at kernel version < 3.7.0 */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) */
	KUNIT_SUCCEED(test);
}


static void defex_keyring_init_test(struct kunit *test)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
	/* __init function */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) */
	KUNIT_SUCCEED(test);
}


static void defex_keyring_alloc_test(struct kunit *test)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
	/* __init function */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) */
	KUNIT_SUCCEED(test);
}


static void defex_calc_hash_test(struct kunit *test)
{
	/* __init function */
	KUNIT_SUCCEED(test);
}


static void blob_test(struct kunit *test)
{
#ifdef DEFEX_DEBUG_ENABLE
	/* __init function */
#endif /* DEFEX_DEBUG_ENABLE */
	KUNIT_SUCCEED(test);
}


static int defex_sign_test_init(struct kunit *test)
{
	return 0;
}

static void defex_sign_test_exit(struct kunit *test)
{
}

static struct kunit_case defex_sign_test_cases[] = {
	/* TEST FUNC DEFINES */
	KUNIT_CASE(defex_rules_signature_check_test),
	KUNIT_CASE(defex_public_key_verify_signature_test),
	KUNIT_CASE(defex_keyring_init_test),
	KUNIT_CASE(defex_keyring_alloc_test),
	KUNIT_CASE(defex_calc_hash_test),
	KUNIT_CASE(blob_test),
	{},
};

static struct kunit_suite defex_sign_test_module = {
	.name = "defex_sign_test",
	.init = defex_sign_test_init,
	.exit = defex_sign_test_exit,
	.test_cases = defex_sign_test_cases,
};
kunit_test_suites(&defex_sign_test_module);

