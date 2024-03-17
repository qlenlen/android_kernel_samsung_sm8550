/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */
#include <linux/task_integrity.h>
#include "five_cache.h"
#include "five_state.h"
#include "five_hooks.h"
#include "test_helpers.h"

enum task_integrity_state_cause {
	STATE_CAUSE_UNKNOWN,
	STATE_CAUSE_DIGSIG,
	STATE_CAUSE_DMV_PROTECTED,
	STATE_CAUSE_TRUSTED,
	STATE_CAUSE_HMAC,
	STATE_CAUSE_SYSTEM_LABEL,
	STATE_CAUSE_NOCERT,
	STATE_CAUSE_TAMPERED,
	STATE_CAUSE_MISMATCH_LABEL,
	STATE_CAUSE_FSV_PROTECTED
};

struct task_verification_result {
	enum task_integrity_value new_tint;
	enum task_integrity_value prev_tint;
	enum task_integrity_state_cause cause;
};

#define LABEL_SIZE 10
#define FAKE_ITEGRITY_VALUE (INTEGRITY_PRELOAD + 21)
#define MESSAGE_BUFFER_SIZE 600	// from five_dsms.c
#define CRC_VALUE_NO_MATTER 37 // any uint16
#define FIVE_RESULT 7

DECLARE_FUNCTION_MOCK(
	METHOD(call_crc16), RETURNS(u16), PARAMS(u16, u8 const *, size_t));

DEFINE_FUNCTION_MOCK_VOID_RETURN(five_audit_verbose,
	PARAMS(struct task_struct *,
	struct file *, const char *, enum task_integrity_value,
	enum task_integrity_value, const char *, int));

DEFINE_FUNCTION_MOCK(
	METHOD(five_d_path), RETURNS(const char *),
	PARAMS(const struct path *, char **, char *));

DEFINE_FUNCTION_MOCK_VOID_RETURN(five_hook_integrity_reset,
	PARAMS(struct task_struct *,
	struct file *,
	enum task_integrity_reset_cause))

const char *task_integrity_state_str(enum task_integrity_state_cause cause);
int is_system_label(struct integrity_label *label);

enum task_integrity_reset_cause state_to_reason_cause(
	enum task_integrity_state_cause cause);

int integrity_label_cmp(struct integrity_label *l1,
	struct integrity_label *l2);

int verify_or_update_label(struct task_integrity *intg,
		struct integrity_iint_cache *iint);

bool set_first_state(struct integrity_iint_cache *iint,
				struct task_integrity *integrity,
				struct task_verification_result *result);

bool set_next_state(struct integrity_iint_cache *iint,
			   struct task_integrity *integrity,
			   struct task_verification_result *result);

static void five_state_task_integrity_state_str_test(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, task_integrity_state_str(
		STATE_CAUSE_FSV_PROTECTED + 100), "unknown");
}

static void five_state_to_reason_cause_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)state_to_reason_cause(CAUSE_MAX + 100), CAUSE_UNSET);
}

static void five_state_is_system_label_test(struct kunit *test)
{
	DECLARE_NEW(test, struct integrity_label, label);

	KUNIT_EXPECT_EQ(test, is_system_label(NULL), 0);
	label->len = LABEL_SIZE;
	KUNIT_EXPECT_EQ(test, is_system_label(label), 0);
	label->len = 0;
	KUNIT_EXPECT_EQ(test, is_system_label(label), 1);
}

static void five_state_integrity_label_cmp_test(struct kunit *test)
{
	DECLARE_NEW(test, struct integrity_label, l1);
	DECLARE_NEW(test, struct integrity_label, l2);

	KUNIT_EXPECT_EQ(test, integrity_label_cmp(l1, l2), 0);
}

static void five_state_verify_or_update_label_test(struct kunit *test)
{
	int i;
	struct integrity_label {
		uint16_t len;
		uint8_t data[LABEL_SIZE];
	} __packed int_l;

	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct integrity_iint_cache, iint);
	DECLARE_NEW(test, struct integrity_label, intg_label);

	for (i = 0; i < LABEL_SIZE; ++i)
		int_l.data[i] = i+1;
	iint->five_label = NULL;
	KUNIT_EXPECT_EQ(test, verify_or_update_label(NULL, iint), 0);

	iint->five_label = (void *)&int_l;
	int_l.len = 0;
	KUNIT_EXPECT_EQ(test, verify_or_update_label(NULL, iint), 0);

	int_l.len = LABEL_SIZE;
	intg->label = (void *)intg_label;
	KUNIT_EXPECT_EQ(test, verify_or_update_label(intg, iint), 0);
	KUNIT_EXPECT_EQ(test, intg->label->len, (uint16_t)0);

	intg->label = NULL;
	KUNIT_EXPECT_EQ(test, verify_or_update_label(intg, iint), 0);
	KUNIT_EXPECT_EQ(test, intg->label->len, (uint16_t)LABEL_SIZE);
	for (i = 0; i < LABEL_SIZE; ++i)
		KUNIT_EXPECT_EQ(test,
			(uint8_t)intg->label->data[i], (uint8_t)(i+1));
}

#define KUNIT_EXPECT_EQ_RESULT(\
		intg_value, res_cause, res_prevtint, res_newtint) do {\
	KUNIT_EXPECT_EQ(test, task_integrity_read(intg),\
		(enum task_integrity_value)intg_value);\
	KUNIT_EXPECT_EQ(test, result->cause, \
		(enum task_integrity_state_cause)res_cause);\
	KUNIT_EXPECT_EQ(test, result->prev_tint,\
		(enum task_integrity_value)res_prevtint);\
	KUNIT_EXPECT_EQ(test, result->new_tint,\
		(enum task_integrity_value)res_newtint);\
	} while (0)

static void five_state_set_first_state_test(struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct integrity_iint_cache, iint);
	DECLARE_NEW(test, struct task_verification_result, result);

	iint->inode = NEW(test, struct inode);
	iint->version = 0;
	iint->inode->i_version.counter = 0;

	iint->five_status = FIVE_FILE_RSA;
	iint->five_flags = (unsigned long)-1;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(
		INTEGRITY_PRELOAD_ALLOW_SIGN, STATE_CAUSE_TRUSTED,
		FAKE_ITEGRITY_VALUE, INTEGRITY_PRELOAD_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_RSA;
	iint->five_flags = 0;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 1);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_PRELOAD, STATE_CAUSE_DIGSIG,
		FAKE_ITEGRITY_VALUE + 1, INTEGRITY_PRELOAD);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_FSVERITY;
	iint->five_flags = (unsigned long)-1;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 2);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(
		INTEGRITY_DMVERITY_ALLOW_SIGN, STATE_CAUSE_TRUSTED,
		FAKE_ITEGRITY_VALUE + 2, INTEGRITY_DMVERITY_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_FSVERITY;
	iint->five_flags = 0;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 3);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY, STATE_CAUSE_FSV_PROTECTED,
		FAKE_ITEGRITY_VALUE + 3, INTEGRITY_DMVERITY);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_DMVERITY;
	iint->five_flags = (unsigned long)-1;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 4);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(
		INTEGRITY_DMVERITY_ALLOW_SIGN, STATE_CAUSE_TRUSTED,
		FAKE_ITEGRITY_VALUE + 4, INTEGRITY_DMVERITY_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_DMVERITY;
	iint->five_flags = 0;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 5);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY, STATE_CAUSE_DMV_PROTECTED,
		FAKE_ITEGRITY_VALUE + 5, INTEGRITY_DMVERITY);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 6);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, STATE_CAUSE_HMAC,
		FAKE_ITEGRITY_VALUE + 6, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 7);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, STATE_CAUSE_HMAC,
		FAKE_ITEGRITY_VALUE + 7, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_FAIL;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 8);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_NONE, STATE_CAUSE_TAMPERED,
		FAKE_ITEGRITY_VALUE + 8, INTEGRITY_NONE);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_UNKNOWN + 100;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 9);
	KUNIT_EXPECT_TRUE(test, set_first_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_NONE, STATE_CAUSE_NOCERT,
		FAKE_ITEGRITY_VALUE + 9, INTEGRITY_NONE);
}

static void five_state_set_next_state_test(struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct integrity_iint_cache, iint);
	DECLARE_NEW(test, struct task_verification_result, result);

	iint->inode = NEW(test, struct inode);
	iint->version = 0;
	iint->inode->i_version.counter = 0;

	iint->five_status = FIVE_FILE_RSA;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(FAKE_ITEGRITY_VALUE, 0,
		FAKE_ITEGRITY_VALUE, FAKE_ITEGRITY_VALUE);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_UNKNOWN;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 1);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_NONE, STATE_CAUSE_NOCERT,
		FAKE_ITEGRITY_VALUE + 1, INTEGRITY_NONE);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_FAIL;
	task_integrity_set(intg, FAKE_ITEGRITY_VALUE + 2);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_NONE, STATE_CAUSE_TAMPERED,
		 FAKE_ITEGRITY_VALUE + 2, INTEGRITY_NONE);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_DMVERITY;
	task_integrity_set(intg, INTEGRITY_PRELOAD_ALLOW_SIGN);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY_ALLOW_SIGN,
		STATE_CAUSE_DMV_PROTECTED, INTEGRITY_PRELOAD_ALLOW_SIGN,
		INTEGRITY_DMVERITY_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_FSVERITY;
	task_integrity_set(intg, INTEGRITY_PRELOAD_ALLOW_SIGN);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY_ALLOW_SIGN,
		STATE_CAUSE_FSV_PROTECTED, INTEGRITY_PRELOAD_ALLOW_SIGN,
		INTEGRITY_DMVERITY_ALLOW_SIGN);

	iint->five_label = NEW(test, struct integrity_label);
	iint->five_label->len = 0;

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_PRELOAD_ALLOW_SIGN);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(
		INTEGRITY_MIXED_ALLOW_SIGN, STATE_CAUSE_SYSTEM_LABEL,
		INTEGRITY_PRELOAD_ALLOW_SIGN, INTEGRITY_MIXED_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_label->len = 1;
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_PRELOAD_ALLOW_SIGN);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, STATE_CAUSE_HMAC,
		INTEGRITY_PRELOAD_ALLOW_SIGN, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_DMVERITY;
	task_integrity_set(intg, INTEGRITY_PRELOAD);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY, STATE_CAUSE_DMV_PROTECTED,
		INTEGRITY_PRELOAD, INTEGRITY_DMVERITY);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_FSVERITY;
	task_integrity_set(intg, INTEGRITY_PRELOAD);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY, STATE_CAUSE_FSV_PROTECTED,
		INTEGRITY_PRELOAD, INTEGRITY_DMVERITY);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_PRELOAD);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, STATE_CAUSE_HMAC,
		INTEGRITY_PRELOAD, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_label->len = 0;
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_PRELOAD);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, STATE_CAUSE_HMAC,
		INTEGRITY_PRELOAD, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_label->len = 1;
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_MIXED_ALLOW_SIGN);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, STATE_CAUSE_HMAC,
		INTEGRITY_MIXED_ALLOW_SIGN, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_label->len = 0;
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_MIXED_ALLOW_SIGN);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED_ALLOW_SIGN, 0,
		INTEGRITY_MIXED_ALLOW_SIGN, INTEGRITY_MIXED_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_label->len = 1;
	iint->five_status = FIVE_FILE_DMVERITY;
	task_integrity_set(intg, INTEGRITY_MIXED_ALLOW_SIGN);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED_ALLOW_SIGN, 0,
		INTEGRITY_MIXED_ALLOW_SIGN, INTEGRITY_MIXED_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_label->len = 1;
	iint->five_status = FIVE_FILE_FSVERITY;
	task_integrity_set(intg, INTEGRITY_MIXED_ALLOW_SIGN);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED_ALLOW_SIGN, 0,
		INTEGRITY_MIXED_ALLOW_SIGN, INTEGRITY_MIXED_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_DMVERITY);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, STATE_CAUSE_HMAC,
		INTEGRITY_DMVERITY, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_DMVERITY;
	task_integrity_set(intg, INTEGRITY_DMVERITY);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY, 0,
		INTEGRITY_DMVERITY, INTEGRITY_DMVERITY);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_FSVERITY;
	task_integrity_set(intg, INTEGRITY_DMVERITY);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY, 0,
		INTEGRITY_DMVERITY, INTEGRITY_DMVERITY);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_label->len = 0;
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_DMVERITY_ALLOW_SIGN);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(
		INTEGRITY_MIXED_ALLOW_SIGN, STATE_CAUSE_SYSTEM_LABEL,
		INTEGRITY_DMVERITY_ALLOW_SIGN, INTEGRITY_MIXED_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_label->len = 1;
	iint->five_status = FIVE_FILE_HMAC;
	task_integrity_set(intg, INTEGRITY_DMVERITY_ALLOW_SIGN);
	KUNIT_EXPECT_TRUE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, STATE_CAUSE_HMAC,
		INTEGRITY_DMVERITY_ALLOW_SIGN, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_DMVERITY;
	task_integrity_set(intg, INTEGRITY_DMVERITY_ALLOW_SIGN);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY_ALLOW_SIGN, 0,
		INTEGRITY_DMVERITY_ALLOW_SIGN, INTEGRITY_DMVERITY_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	iint->five_status = FIVE_FILE_FSVERITY;
	task_integrity_set(intg, INTEGRITY_DMVERITY_ALLOW_SIGN);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_DMVERITY_ALLOW_SIGN, 0,
		INTEGRITY_DMVERITY_ALLOW_SIGN, INTEGRITY_DMVERITY_ALLOW_SIGN);

	memset(result, 0, sizeof(struct task_verification_result));
	task_integrity_set(intg, INTEGRITY_MIXED);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_MIXED, 0,
		INTEGRITY_MIXED, INTEGRITY_MIXED);

	memset(result, 0, sizeof(struct task_verification_result));
	task_integrity_set(intg, INTEGRITY_NONE);
	KUNIT_EXPECT_FALSE(test, set_next_state(iint, intg, result));
	KUNIT_EXPECT_EQ_RESULT(INTEGRITY_NONE, 0,
		INTEGRITY_NONE, INTEGRITY_NONE);
}

static void five_state_proceed_no_iint_test(struct kunit *test)
{
	DECLARE_NEW(test, struct file_verification_result, file_result);

	file_result->iint = NULL;

	five_state_proceed(NULL, file_result);
}

static void five_state_proceed_set_next_state_returns_false_test(
	struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct integrity_iint_cache, iint);
	DECLARE_NEW(test, struct file_verification_result, file_result);

	iint->inode = NEW(test, struct inode);
	iint->version = 0;
	iint->inode->i_version.counter = 0;
	iint->five_status = FIVE_FILE_RSA;  // set_next_state() returns false

	file_result->iint = iint;
	file_result->fn = MMAP_CHECK;

	five_state_proceed(intg, file_result);
}

static void five_state_proceed_set_first_state_not_ret_intg_none_test(
	struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct integrity_iint_cache, iint);
	DECLARE_NEW(test, struct file_verification_result, file_result);

	task_integrity_set(intg, INTEGRITY_NONE);

	iint->inode = NEW(test, struct inode);
	iint->version = 0;
	iint->inode->i_version.counter = 0;
	// set_first_state() updates tint = INTEGRITY_MIXED
	iint->five_status = FIVE_FILE_HMAC;

	file_result->iint = iint;
	file_result->fn = BPRM_CHECK;
	file_result->task = NEW(test, struct task_struct);
	file_result->file = NEW(test, struct file);
	file_result->five_result = FIVE_RESULT;

	KunitReturns(KUNIT_EXPECT_CALL(five_audit_verbose(
		ptr_eq(test, file_result->task),
		ptr_eq(test, file_result->file),
		streq(test, five_get_string_fn(file_result->fn)),
		any(test), any(test), any(test),
		int_eq(test, file_result->five_result))),
		ptr_return(test, 0));

	five_state_proceed(intg, file_result);
}

static void five_state_proceed_set_first_state_returns_intg_none_test(
	struct kunit *test)
{
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct integrity_iint_cache, iint);
	DECLARE_NEW(test, struct file_verification_result, file_result);

	task_integrity_set(intg, INTEGRITY_NONE);
	intg->reset_cause = CAUSE_UNSET;

	iint->inode = NEW(test, struct inode);
	iint->version = 0;
	iint->inode->i_version.counter = 0;
	// set_first_state() updates tint = INTEGRITY_NONE
	iint->five_status = FIVE_FILE_UNKNOWN;

	file_result->iint = iint;
	file_result->fn = BPRM_CHECK;
	file_result->task = NEW(test, struct task_struct);
	file_result->file = NEW(test, struct file);
	file_result->five_result = FIVE_RESULT;

	KunitReturns(KUNIT_EXPECT_CALL(five_hook_integrity_reset(
		ptr_eq(test, file_result->task),
		ptr_eq(test, file_result->file),
		int_eq(test, CAUSE_NO_CERT))),
		int_return(test, 0));

	KunitReturns(KUNIT_EXPECT_CALL(five_audit_verbose(
		ptr_eq(test, file_result->task),
		ptr_eq(test, file_result->file),
		streq(test, five_get_string_fn(file_result->fn)),
		any(test), any(test), any(test),
		int_eq(test, file_result->five_result))),
		ptr_return(test, 0));

	five_state_proceed(intg, file_result);

	KUNIT_EXPECT_EQ(test,
		intg->reset_cause, state_to_reason_cause(STATE_CAUSE_NOCERT));
}

static void five_state_proceed_set_next_state_returns_intg_none_test(
	struct kunit *test)
{
	char pathname[] = "yyy";
	char comm[TASK_COMM_LEN] = "zzz";
	char dsms_msg[MESSAGE_BUFFER_SIZE] = "bbb";
	DECLARE_NEW(test, struct task_integrity, intg);
	DECLARE_NEW(test, struct integrity_iint_cache, iint);
	DECLARE_NEW(test, struct file_verification_result, file_result);
	int msg_size = snprintf(dsms_msg, MESSAGE_BUFFER_SIZE, "%s|%d|%s",
		comm, STATE_CAUSE_TAMPERED, kbasename(pathname));

	task_integrity_set(intg, INTEGRITY_NONE);
	intg->reset_cause = CAUSE_UNSET;

	iint->inode = NEW(test, struct inode);
	iint->version = 0;
	iint->inode->i_version.counter = 0;
	// set_next_state() updates tint = INTEGRITY_NONE
	iint->five_status = FIVE_FILE_FAIL;

	file_result->iint = iint;
	file_result->fn = MMAP_CHECK;
	file_result->task = NEW(test, struct task_struct);
	strncpy(file_result->task->comm, comm, TASK_COMM_LEN);
	file_result->file = NEW(test, struct file);
	file_result->five_result = FIVE_RESULT;

	KunitReturns(KUNIT_EXPECT_CALL(five_hook_integrity_reset(
		ptr_eq(test, file_result->task),
		ptr_eq(test, file_result->file),
		int_eq(test, CAUSE_TAMPERED))),
		int_return(test, 0));

	KunitReturns(KUNIT_EXPECT_CALL(five_audit_verbose(
		ptr_eq(test, file_result->task),
		ptr_eq(test, file_result->file),
		streq(test, five_get_string_fn(file_result->fn)),
		any(test), any(test), any(test),
		int_eq(test, file_result->five_result))),
		ptr_return(test, 0));

	KunitReturns(KUNIT_EXPECT_CALL(five_d_path(
		ptr_eq(test, &file_result->file->f_path),
		any(test), any(test))),
		ptr_return(test, pathname));

	KunitReturns(KUNIT_EXPECT_CALL(call_crc16(
		int_eq(test, 0), streq(test, dsms_msg),
		int_eq(test, msg_size))),
		u32_return(test, CRC_VALUE_NO_MATTER));

	five_state_proceed(intg, file_result);

	KUNIT_EXPECT_EQ(test, intg->reset_cause,
		state_to_reason_cause(STATE_CAUSE_TAMPERED));
}

static struct kunit_case five_state_test_cases[] = {
	KUNIT_CASE(five_state_task_integrity_state_str_test),
	KUNIT_CASE(five_state_to_reason_cause_test),
	KUNIT_CASE(five_state_is_system_label_test),
	KUNIT_CASE(five_state_integrity_label_cmp_test),
	KUNIT_CASE(five_state_verify_or_update_label_test),
	KUNIT_CASE(five_state_set_first_state_test),
	KUNIT_CASE(five_state_set_next_state_test),
	KUNIT_CASE(five_state_proceed_no_iint_test),
	KUNIT_CASE(five_state_proceed_set_next_state_returns_false_test),
	KUNIT_CASE(five_state_proceed_set_first_state_not_ret_intg_none_test),
	KUNIT_CASE(five_state_proceed_set_first_state_returns_intg_none_test),
	KUNIT_CASE(five_state_proceed_set_next_state_returns_intg_none_test),
	{},
};

static int five_state_test_init(struct kunit *test)
{
	return 0;
}

static void five_state_test_exit(struct kunit *test)
{
}

static struct kunit_suite five_state_test_module = {
	.name = "five_state_test",
	.init = five_state_test_init,
	.exit = five_state_test_exit,
	.test_cases = five_state_test_cases,
};

kunit_test_suites(&five_state_test_module);

MODULE_LICENSE("GPL v2");
