/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/cred.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include "include/defex_debug.h"
#include "include/defex_internal.h"
#include "include/defex_test.h"

/* General test functions created by Generate_KUnit.sh */

static void set_user_test(struct kunit *test)
{
	struct cred *cred_test = (struct cred *) current_cred();
	struct user_namespace *ns = current_user_ns();
	kuid_t kuid;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cred_test);

	/* invalid uid first */
	kuid = make_kuid(ns, -1);
	cred_test->uid = kuid;
	KUNIT_EXPECT_EQ(test, set_user(cred_test), 0);

	/* Valid ID */
	kuid = make_kuid(ns, 1000);
	cred_test->uid = kuid;
	KUNIT_EXPECT_EQ(test, set_user(cred_test), 0);
	KUNIT_ASSERT_EQ(test, cred_test->user->uid.val, (unsigned int)1000);
}


static void set_cred_test(struct kunit *test)
{
	/* uid, valid */
	KUNIT_EXPECT_EQ(test, set_cred(0, 1000), 0);

	/* uid, invalid */
	KUNIT_EXPECT_EQ(test, set_cred(0, -1), -EPERM);

	/* fsuid, valid */
	KUNIT_EXPECT_EQ(test, set_cred(1, 1000), 0);

	/* fsuid, invalid */
	KUNIT_EXPECT_EQ(test, set_cred(1, -1), -EPERM);

	/* guid, valid */
	KUNIT_EXPECT_EQ(test, set_cred(2, 1000), 0);

	/* guid, invalid */
	KUNIT_EXPECT_EQ(test, set_cred(2, -1), -EPERM);
}


static void defex_create_debug_test(struct kunit *test)
{
	struct kset *defex_kset = kset_create_and_add("defex_create_debug_test", NULL, NULL);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, defex_kset);
	KUNIT_EXPECT_EQ(test, defex_create_debug(defex_kset), DEFEX_OK);

	/* free resources */
	kset_unregister(defex_kset);
}


static void debug_store_test(struct kunit *test)
{
	char *invalid_prefix = "test";
	char *incomplete_prefix = "uid=";
	char *valid_prefix = "uid=2000";

	/* buffer null */
	KUNIT_EXPECT_EQ(test, debug_store(NULL, NULL, NULL, 0), (long)-EINVAL);
	/* invalid prefix */
	KUNIT_EXPECT_EQ(test, debug_store(NULL, NULL, invalid_prefix, 1), (long)-EINVAL);
	/* incomplete prefix */
	KUNIT_EXPECT_EQ(test, debug_store(NULL, NULL, incomplete_prefix, 1), (long)-EINVAL);
	/* valid prefix */
	KUNIT_EXPECT_EQ(test, debug_store(NULL, NULL, valid_prefix, 10), (long)10);
}


static void debug_show_test(struct kunit *test)
{
	struct task_struct *p = current;
	struct kset *defex_kset = kset_create_and_add("debug_show_test", NULL, NULL);
	char expected_output[MAX_LEN + 1];
	char buff[MAX_LEN + 1];
	int res = 0;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, defex_kset);
	KUNIT_ASSERT_EQ(test, defex_create_debug(defex_kset), DEFEX_OK);

	/* Make a command so last_cmd has a valid value */
	res = debug_store(NULL, NULL, "uid=1000", 10);
	KUNIT_ASSERT_EQ(test, res, 10);

	res = snprintf(expected_output, MAX_LEN + 1, "pid=%d\nuid=%d\ngid=%d\neuid=%d\negid=%d\n",
			p->pid,
			uid_get_value(p->cred->uid),
			uid_get_value(p->cred->gid),
			uid_get_value(p->cred->euid),
			uid_get_value(p->cred->egid));

	KUNIT_EXPECT_EQ(test, (long)res, debug_show(NULL, NULL, buff));
	KUNIT_EXPECT_TRUE(test, !strcmp(buff, expected_output));

	/* free resources */
	kset_unregister(defex_kset);
}


static void debug_attribute_test(struct kunit *test)
{
	/* KUNIT_EXPECT_EQ(test, 1, debug_attribute()); */
}


static int defex_debug_test_init(struct kunit *test)
{
	/*
	 * test->priv = a_struct_pointer;
	 * if (!test->priv)
	 *    return -ENOMEM;
	 */

	return 0;
}

static void defex_debug_test_exit(struct kunit *test)
{
}

static struct kunit_case defex_debug_test_cases[] = {
	/* TEST FUNC DEFINES */
	KUNIT_CASE(set_user_test),
	KUNIT_CASE(set_cred_test),
	KUNIT_CASE(defex_create_debug_test),
	KUNIT_CASE(debug_store_test),
	KUNIT_CASE(debug_show_test),
	KUNIT_CASE(debug_attribute_test),
	{},
};

static struct kunit_suite defex_debug_test_module = {
	.name = "defex_debug_test",
	.init = defex_debug_test_init,
	.exit = defex_debug_test_exit,
	.test_cases = defex_debug_test_cases,
};
kunit_test_suites(&defex_debug_test_module);

