/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */
#include <linux/key-type.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/task_integrity.h>
#include <linux/proca.h>
#include <linux/xattr.h>
#include <linux/fs.h>
#include "test_helpers.h"

void init_once(void *foo);
int copy_label(struct task_integrity *from, struct task_integrity *to);

#define USAGE_COUNT_VAL 4
#define USAGE_VALUE_VAL (INTEGRITY_NONE + 3)
#define LABEL_LEN	17

static void task_integrity_check_init_once_test(struct kunit *test)
{
	int i;
	char *p_intg;
	DECLARE_NEW(test, struct task_integrity, intg);

	memset(intg, 1, sizeof(*intg));
	init_once(intg);
	p_intg = (char *)intg;
	for (i = 0; i < sizeof(*intg); ++i) {
		int foo = 0;

		KUNIT_EXPECT_EQ(test, (int)p_intg[i], foo);
	}
}

static void task_integrity_free_test(struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);

	// This memory should be released in tested function.
	intg->label = kzalloc(sizeof(struct integrity_label), GFP_KERNEL);
	intg->reset_file = NEW(test, struct file);

	task_integrity_free(intg);

	KUNIT_EXPECT_PTR_EQ(test, intg->label, (struct integrity_label *)NULL);
	KUNIT_EXPECT_EQ(test, intg->value,
		(enum task_integrity_value)INTEGRITY_NONE);
	KUNIT_EXPECT_EQ(test, intg->user_value,
		(enum task_integrity_value)INTEGRITY_NONE);
	KUNIT_EXPECT_EQ(test, intg->usage_count.counter, 0);
	KUNIT_EXPECT_EQ(test, intg->reset_cause,
		(enum task_integrity_reset_cause)CAUSE_UNSET);
	KUNIT_EXPECT_PTR_EQ(test, intg->reset_file, (struct file *)NULL);
}

static void task_integrity_clear_test(struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);

	// This memory should be released in tested function.
	intg->label = kzalloc(sizeof(struct integrity_label), GFP_KERNEL);
	intg->reset_file = NEW(test, struct file);
	intg->user_value = USAGE_VALUE_VAL;
	atomic_set(&intg->usage_count, USAGE_COUNT_VAL);

	task_integrity_clear(intg);

	KUNIT_EXPECT_PTR_EQ(test, intg->label, (struct integrity_label *)NULL);
	KUNIT_EXPECT_EQ(test, intg->value,
		(enum task_integrity_value)INTEGRITY_NONE);
	KUNIT_EXPECT_EQ(test, intg->user_value,
		(enum task_integrity_value)USAGE_VALUE_VAL);
	KUNIT_EXPECT_EQ(test, intg->usage_count.counter, USAGE_COUNT_VAL);
	KUNIT_EXPECT_EQ(test, intg->reset_cause,
		(enum task_integrity_reset_cause)CAUSE_UNSET);
	KUNIT_EXPECT_PTR_EQ(test, intg->reset_file, (struct file *)NULL);
}

static void task_integrity_copy_label_no_value_test(struct kunit *test)
{
	struct task_integrity *to = NULL;
	DECLARE_NEW(test, struct task_integrity, from);

	task_integrity_set(from, INTEGRITY_NONE);
	from->label = NEW(test, struct integrity_label);

	KUNIT_EXPECT_EQ(test, copy_label(from, to), 0);
}

static void task_integrity_copy_label_no_label_test(struct kunit *test)
{
	struct task_integrity *to = NULL;
	DECLARE_NEW(test, struct task_integrity, from);

	task_integrity_set(from, INTEGRITY_MIXED);
	from->label = NULL;

	KUNIT_EXPECT_EQ(test, copy_label(from, to), 0);
}

static void task_integrity_copy_label_test(struct kunit *test)
{
	int i;
	struct  {
		uint16_t len;
		uint8_t data[LABEL_LEN];
	} __packed integrity_label_inst;

	DECLARE_NEW(test, struct task_integrity, from);
	DECLARE_NEW(test, struct task_integrity, to);

	task_integrity_set(from, INTEGRITY_MIXED);
	from->label = (struct integrity_label *)&integrity_label_inst;
	from->label->len = LABEL_LEN;
	for (i = 0; i < LABEL_LEN; ++i)
		from->label->data[i] = i + 1;

	KUNIT_EXPECT_EQ(test, copy_label(from, to), 0);

	for (i = 0; i < LABEL_LEN; ++i) {
		int foo = i+1;

		KUNIT_EXPECT_EQ(test, (int)to->label->data[i], foo);
	}
	KUNIT_EXPECT_EQ(test, to->label->len, (uint16_t)LABEL_LEN);
	kfree(to->label);
}

static void task_integrity_copy_list_is_empty_test(struct kunit *test)
{
	int i;
	struct  {
		uint16_t len;
		uint8_t data[LABEL_LEN];
	} __packed integrity_label_inst;

	DECLARE_NEW(test, struct task_integrity, from);
	DECLARE_NEW(test, struct task_integrity, to);
	DECLARE_NEW(test, struct file, reset_file);

	from->reset_file = NULL;
	from->reset_cause = CAUSE_MISMATCH_LABEL;
	task_integrity_set(from, INTEGRITY_MIXED);
	from->label = (struct integrity_label *)&integrity_label_inst;
	from->label->len = LABEL_LEN;
	for (i = 0; i < LABEL_LEN; ++i)
		from->label->data[i] = i + 1;
	to->user_value = INTEGRITY_DMVERITY_ALLOW_SIGN;
	to->reset_file = reset_file;

	KUNIT_EXPECT_EQ(test, task_integrity_copy(from, to), 0);

	for (i = 0; i < LABEL_LEN; ++i) {
		int foo = i+1;

		KUNIT_EXPECT_EQ(test, (int)to->label->data[i], foo);
	}
	KUNIT_EXPECT_EQ(test, to->label->len, (uint16_t)LABEL_LEN);
	KUNIT_EXPECT_EQ(test,
		task_integrity_read(from), task_integrity_read(to));
	KUNIT_EXPECT_EQ(test, to->user_value,
		(enum task_integrity_value)INTEGRITY_DMVERITY_ALLOW_SIGN);
	KUNIT_EXPECT_EQ(test, to->reset_cause,
		(enum task_integrity_reset_cause)CAUSE_MISMATCH_LABEL);
	KUNIT_EXPECT_PTR_EQ(test, to->reset_file, (struct file *)reset_file);

	kfree(to->label);
}

static void task_integrity_copy_list_not_empty_test(struct kunit *test)
{
	int i;
	struct  {
		uint16_t len;
		uint8_t data[LABEL_LEN];
	} __packed integrity_label_inst;

	DECLARE_NEW(test, struct task_integrity, from);
	DECLARE_NEW(test, struct task_integrity, to);
	DECLARE_NEW(test, struct file, reset_file);

	from->reset_file = reset_file;
	from->reset_cause = CAUSE_MISMATCH_LABEL;
	task_integrity_set(from, INTEGRITY_MIXED);
	from->label = (struct integrity_label *)&integrity_label_inst;
	from->label->len = LABEL_LEN;
	for (i = 0; i < LABEL_LEN; ++i)
		from->label->data[i] = i + 1;
	from->events.list.next = &from->events.list;

	to->user_value = INTEGRITY_DMVERITY_ALLOW_SIGN;
	to->reset_file = NULL;

	KUNIT_EXPECT_EQ(test, task_integrity_copy(from, to), 0);

	for (i = 0; i < LABEL_LEN; ++i) {
		int foo = i+1;

		KUNIT_EXPECT_EQ(test, (int)to->label->data[i], foo);
	}
	KUNIT_EXPECT_EQ(test, to->label->len, (uint16_t)LABEL_LEN);
	KUNIT_EXPECT_EQ(test,
		task_integrity_read(from), task_integrity_read(to));
	KUNIT_EXPECT_EQ(test, to->user_value,
		(enum task_integrity_value)INTEGRITY_MIXED);
	KUNIT_EXPECT_EQ(test, to->reset_cause,
		(enum task_integrity_reset_cause)CAUSE_MISMATCH_LABEL);
	KUNIT_EXPECT_PTR_EQ(test, to->reset_file, (struct file *)reset_file);

	kfree(to->label);
}

static void task_integrity_copy_reset_cause_to_string_test(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
		tint_reset_cause_to_string(CAUSE_MAX+1), "incorrect-cause");
}

static void task_integrity_set_reset_reason_non_cause_unset_test(
		struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct file, reset_file);

	intg->reset_file = NULL;
	intg->reset_cause = CAUSE_UNKNOWN;
	task_integrity_set_reset_reason(
		intg, CAUSE_MISMATCH_LABEL, reset_file);
	KUNIT_EXPECT_EQ(test, intg->reset_cause,
		(enum task_integrity_reset_cause)CAUSE_UNKNOWN);
	KUNIT_EXPECT_PTR_EQ(test, intg->reset_file, (struct file *)NULL);
}

static void task_integrity_set_reset_reason_no_file_test(
		struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct file, reset_file);

	intg->reset_file = reset_file;
	intg->reset_cause = CAUSE_UNSET;
	task_integrity_set_reset_reason(intg, CAUSE_MISMATCH_LABEL, NULL);
	KUNIT_EXPECT_EQ(test, intg->reset_cause,
		(enum task_integrity_reset_cause)CAUSE_MISMATCH_LABEL);
	KUNIT_EXPECT_PTR_EQ(test, intg->reset_file, reset_file);
}

static void task_integrity_set_reset_reason_test(
		struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct file, reset_file);

	intg->reset_file = NULL;
	intg->reset_cause = CAUSE_UNSET;
	task_integrity_set_reset_reason(intg, CAUSE_MISMATCH_LABEL, reset_file);
	KUNIT_EXPECT_EQ(test, intg->reset_cause,
		(enum task_integrity_reset_cause)CAUSE_MISMATCH_LABEL);
	KUNIT_EXPECT_PTR_EQ(test, intg->reset_file, reset_file);
}

static struct kunit_case task_integrity_test_cases[] = {
	KUNIT_CASE(task_integrity_check_init_once_test),
	KUNIT_CASE(task_integrity_free_test),
	KUNIT_CASE(task_integrity_clear_test),
	KUNIT_CASE(task_integrity_copy_label_no_value_test),
	KUNIT_CASE(task_integrity_copy_label_no_label_test),
	KUNIT_CASE(task_integrity_copy_label_test),
	KUNIT_CASE(task_integrity_copy_list_is_empty_test),
	KUNIT_CASE(task_integrity_copy_list_not_empty_test),
	KUNIT_CASE(task_integrity_copy_reset_cause_to_string_test),
	KUNIT_CASE(task_integrity_set_reset_reason_non_cause_unset_test),
	KUNIT_CASE(task_integrity_set_reset_reason_no_file_test),
	KUNIT_CASE(task_integrity_set_reset_reason_test),
	{},
};

static int task_integrity_test_init(struct kunit *test)
{
	return 0;
}

static void task_integrity_test_exit(struct kunit *test)
{
	return;
}

static struct kunit_suite task_integrity_test_module = {
	.name = "task_integrity_test",
	.init = task_integrity_test_init,
	.exit = task_integrity_test_exit,
	.test_cases = task_integrity_test_cases,
};

kunit_test_suites(&task_integrity_test_module);

MODULE_LICENSE("GPL v2");
