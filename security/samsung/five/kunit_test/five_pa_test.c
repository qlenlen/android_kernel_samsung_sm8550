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
#include "five.h"
#include "five_pa.h"
#include "five_hooks.h"
#include "five_lv.h"
#include "five_porting.h"
#include "test_helpers.h"

#ifdef CONFIG_FIVE_GKI_10
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
#define F_SIGNATURE(file) ((file)->android_oem_data1)
#define F_SIGNATURE_ASSIGN(file, ptr) ((file)->android_oem_data1 = (u64)ptr)
#else
#define F_SIGNATURE(file) ((file)->android_vendor_data1)
#define F_SIGNATURE_ASSIGN(file, ptr) ((file)->android_vendor_data1 = (u64)ptr)
#endif
#else
#define F_SIGNATURE(file) ((file)->f_signature)
#define F_SIGNATURE_ASSIGN(file, ptr) ((file)->f_signature = (void *)ptr)
#endif

void pa_process_file(struct task_struct *task, struct file *file);
int proca_fcntl_setxattr(struct file *file, void __user *lv_xattr);

DEFINE_FUNCTION_MOCK(
	METHOD(call_five_read_xattr), RETURNS(int),
	PARAMS(struct dentry *, char **));

DEFINE_FUNCTION_MOCK(
	METHOD(call_task_integrity_allow_sign), RETURNS(bool),
	PARAMS(struct task_integrity *));

DEFINE_FUNCTION_MOCK(
	METHOD(call_vfs_setxattr_noperm), RETURNS(int),
	PARAMS(struct dentry *, const char *, const void *, size_t, int));

#define CORRECT_PTR 2
#define NOT_S_IFREG	11
#define OVERLENGTH (PAGE_SIZE + 1)
#define LV_XATTR_SIZE 12
#define XATTR_VALUE	22

static void five_pa_process_file_no_file_test(struct kunit *test)
{
	pa_process_file(NULL, NULL);
}

static void five_pa_process_file_no_imode_test(struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);

	p_file->f_inode = NEW(test, struct inode);
	p_file->f_inode->i_mode = NOT_S_IFREG;

	pa_process_file(NULL, p_file);
}

static void five_pa_process_file_has_sign_test(struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);

	p_file->f_inode = NEW(test, struct inode);
	p_file->f_inode->i_mode = S_IFREG;

	F_SIGNATURE_ASSIGN(p_file, CORRECT_PTR);

	pa_process_file(NULL, p_file);
}

static char xattr_val[] = "xyz";
static int ret;
static void  *five_read_xattr_action(
	struct mock_action *this, const void **params, int len)
{
	void *foo;

	if (2 != len) {
		pr_err("Wrong number of params!");
		return NULL;
	}
	foo = (void *)params[1];
	*(char **)(*(void **)foo) = xattr_val;
	ret = 0;
	return &ret;
}

static void five_pa_process_file_no_sign_test(struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);

	p_file->f_inode = NEW(test, struct inode);
	p_file->f_path.dentry = NEW(test, struct dentry);
	p_file->f_inode->i_mode = S_IFREG;
	p_file->f_path.dentry->d_flags = 0;

	F_SIGNATURE_ASSIGN(p_file, NULL);

	ActionOnMatch(KUNIT_EXPECT_CALL(call_five_read_xattr(
		ptr_eq(test, p_file->f_path.dentry), any(test))),
		new_mock_action(test, five_read_xattr_action));

	pa_process_file(NULL, p_file);

	KUNIT_EXPECT_EQ(test, F_SIGNATURE(p_file), (u64)xattr_val);
}

static void five_pafsignature_free_test(struct kunit *test)
{
	// This memory should be released in tested function. Pointer type doesn't matter here
	struct file *p_fake_sign = kzalloc(sizeof(struct file), GFP_KERNEL);

	DECLARE_NEW(test, struct file, p_file);

	F_SIGNATURE_ASSIGN(p_file, p_fake_sign);

	fivepa_fsignature_free(p_file);

	KUNIT_EXPECT_EQ(test, F_SIGNATURE(p_file), (u64)NULL);
}

static void five_pa_proca_fcntl_setxattr_no_file_test(struct kunit *test)
{
	struct lv lv_hdr = {0};

	KUNIT_EXPECT_EQ(test, proca_fcntl_setxattr(NULL, &lv_hdr), -EINVAL);
}

static void five_pa_proca_fcntl_setxattr_no_lv_xattr_test(struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);

	KUNIT_EXPECT_EQ(test, proca_fcntl_setxattr(p_file, NULL), -EINVAL);
}

static void five_pa_proca_fcntl_setxattr_overlength_test(struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);
	struct lv lv_hdr = {OVERLENGTH};

	p_file->f_inode = NEW(test, struct inode);
	KUNIT_EXPECT_EQ(test, proca_fcntl_setxattr(p_file, &lv_hdr), -EINVAL);
}

static int fake_flush_ret_1(struct file *p_file, fl_owner_t id)
{
	return 1;
}

static void five_pa_proca_fcntl_setxattr_flush_returns_error_test(
		struct kunit *test)
{
	struct {
		uint16_t length;
		uint8_t value[LV_XATTR_SIZE];
	} __packed header_lv;

	DECLARE_NEW(test, struct file, p_file);
	DECLARE_NEW(test, struct file_operations, p_file_operations);

	header_lv.length = LV_XATTR_SIZE;
	p_file->f_inode = NEW(test, struct inode);
	p_file_operations->flush = fake_flush_ret_1;
	p_file->f_op = p_file_operations;

	KUNIT_EXPECT_EQ(test,
		proca_fcntl_setxattr(p_file, &header_lv), -EOPNOTSUPP);
}

static int fake_flush_ret_0(struct file *p_file, fl_owner_t id)
{
	return 0;
}

static void five_pa_proca_fcntl_setxattr_allow_sign_test(
		struct kunit *test)
{
	int i;
	struct {
		uint16_t length;
		uint8_t value[LV_XATTR_SIZE];
	} __packed header_lv;

	DECLARE_NEW(test, struct file, p_file);
	DECLARE_NEW(test, struct file_operations, p_file_operations);

	header_lv.length = LV_XATTR_SIZE;
	for (i = 0; i < LV_XATTR_SIZE; ++i)
		header_lv.value[i] = i+1;

	p_file->f_inode = NEW(test, struct inode);
	p_file->f_path.dentry = NEW(test, struct dentry);
	p_file_operations->flush = fake_flush_ret_0;
	p_file->f_op = p_file_operations;
	p_file->f_path.dentry->d_flags = 0;

	KunitReturns(KUNIT_EXPECT_CALL(call_task_integrity_allow_sign(
		ptr_eq(test, TASK_INTEGRITY(current)))),
		bool_return(test, 1));

	KunitReturns(KUNIT_EXPECT_CALL(call_vfs_setxattr_noperm(
		ptr_eq(test, d_real_comp(p_file->f_path.dentry)),
		streq(test, XATTR_NAME_PA),
		memeq(test, header_lv.value, header_lv.length),
		int_eq(test, LV_XATTR_SIZE), int_eq(test, 0))),
		int_return(test, XATTR_VALUE));

	KUNIT_EXPECT_EQ(test,
		proca_fcntl_setxattr(p_file, &header_lv), XATTR_VALUE);
}

static void five_pa_proca_fcntl_setxattr_not_allow_sign_test(
		struct kunit *test)
{
	struct {
		uint16_t length;
		uint8_t value[LV_XATTR_SIZE];
	} __packed header_lv;

	DECLARE_NEW(test, struct file, p_file);

	header_lv.length = LV_XATTR_SIZE;
	p_file->f_inode = NEW(test, struct inode);
	p_file->f_path.dentry = NEW(test, struct dentry);
	p_file->f_path.dentry->d_flags = 0;

	KunitReturns(KUNIT_EXPECT_CALL(call_task_integrity_allow_sign(
		ptr_eq(test, TASK_INTEGRITY(current)))),
		bool_return(test, 0));

	KUNIT_EXPECT_EQ(test, proca_fcntl_setxattr(p_file, &header_lv), -EPERM);
}

static struct kunit_case five_pa_test_cases[] = {
	KUNIT_CASE(five_pa_process_file_no_file_test),
	KUNIT_CASE(five_pa_process_file_no_imode_test),
	KUNIT_CASE(five_pa_process_file_no_sign_test),
	KUNIT_CASE(five_pa_process_file_has_sign_test),
	KUNIT_CASE(five_pafsignature_free_test),
	KUNIT_CASE(five_pa_proca_fcntl_setxattr_no_file_test),
	KUNIT_CASE(five_pa_proca_fcntl_setxattr_no_lv_xattr_test),
	KUNIT_CASE(five_pa_proca_fcntl_setxattr_overlength_test),
	KUNIT_CASE(five_pa_proca_fcntl_setxattr_flush_returns_error_test),
	KUNIT_CASE(five_pa_proca_fcntl_setxattr_allow_sign_test),
	KUNIT_CASE(five_pa_proca_fcntl_setxattr_not_allow_sign_test),
	{},
};

static int five_pa_test_init(struct kunit *test)
{
	return 0;
}

static void five_pa_test_exit(struct kunit *test)
{
	return;
}

static struct kunit_suite five_pa_test_module = {
	.name = "five_pa_test",
	.init = five_pa_test_init,
	.exit = five_pa_test_exit,
	.test_cases = five_pa_test_cases,
};

kunit_test_suites(&five_pa_test_module);

MODULE_LICENSE("GPL v2");
