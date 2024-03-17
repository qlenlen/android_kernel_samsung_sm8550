/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "include/defex_caches.h"
#include "include/defex_catch_list.h"
#include "include/defex_config.h"
#include "include/defex_internal.h"
#include "include/defex_rules.h"
#include "include/defex_test.h"

#define ROOT_PATH "/"

static int kunit_mock_thread_function(void *ptr)
{
	while (!kthread_should_stop());
	return 42;
}

/* General test functions created by Generate_KUnit.sh */

static void release_defex_context_test(struct kunit *test)
{
	struct defex_context dc;

	init_defex_context(&dc, __DEFEX_execve, current, NULL);
	release_defex_context(&dc);
}


static void local_fread_test(struct kunit *test)
{
	struct file *f;
	loff_t offset = 0;

	f = local_fopen(ROOT_PATH, O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(f));
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	KUNIT_EXPECT_EQ(test, local_fread(f, offset, NULL, 0), -EISDIR);
#else
	KUNIT_EXPECT_EQ(test, local_fread(f, offset, NULL, 0), -EINVAL);
#endif
	filp_close(f, NULL);

	/* Missing test case in which a file is opened for read without error */
}


static void local_fopen_test(struct kunit *test)
{
	struct file *f;

	f = local_fopen(ROOT_PATH, O_RDONLY, 0);
	KUNIT_EXPECT_FALSE(test, IS_ERR_OR_NULL(f));
	if (!IS_ERR_OR_NULL(f))
		filp_close(f, NULL);
}


static void init_defex_context_test(struct kunit *test)
{
	struct defex_context dc;
	struct task_struct *mock_task;
	int res;

	mock_task = kthread_run(kunit_mock_thread_function, NULL, "defex_common_test_thread");
	res = init_defex_context(&dc, __DEFEX_execve, mock_task, NULL);
	KUNIT_EXPECT_EQ(test, res, 0);
	release_defex_context(&dc);

	res = init_defex_context(&dc, __DEFEX_execve, current, NULL);
	KUNIT_EXPECT_EQ(test, res, 1);
	KUNIT_EXPECT_EQ(test, dc.syscall_no, __DEFEX_execve);
	KUNIT_EXPECT_PTR_EQ(test, dc.task, current);
	KUNIT_EXPECT_PTR_EQ(test, dc.process_file, (struct file *)NULL);
	KUNIT_EXPECT_PTR_EQ(test, dc.process_dpath, (const struct path *)NULL);
	KUNIT_EXPECT_PTR_EQ(test, dc.process_name, (char *)NULL);
	KUNIT_EXPECT_PTR_EQ(test, dc.target_file, (struct file *)NULL);
	KUNIT_EXPECT_PTR_EQ(test, dc.target_dpath, (const struct path *)NULL);
	KUNIT_EXPECT_PTR_EQ(test, dc.target_name, (char *)NULL);
	KUNIT_EXPECT_PTR_EQ(test, dc.process_name_buff, (char *)NULL);
	KUNIT_EXPECT_PTR_EQ(test, dc.target_name_buff, (char *)NULL);

	if (res) {
		KUNIT_EXPECT_EQ(test, dc.cred->uid.val, current->cred->uid.val);
		KUNIT_EXPECT_EQ(test, dc.cred->gid.val, current->cred->gid.val);
		KUNIT_EXPECT_EQ(test, dc.cred->suid.val, current->cred->suid.val);
		KUNIT_EXPECT_EQ(test, dc.cred->sgid.val, current->cred->sgid.val);
		KUNIT_EXPECT_EQ(test, dc.cred->euid.val, current->cred->euid.val);
		KUNIT_EXPECT_EQ(test, dc.cred->egid.val, current->cred->egid.val);
		KUNIT_EXPECT_EQ(test, dc.cred->fsuid.val, current->cred->fsuid.val);
		KUNIT_EXPECT_EQ(test, dc.cred->fsgid.val, current->cred->fsgid.val);
	}

	release_defex_context(&dc);
	kthread_stop(mock_task);
}


static void get_dc_target_name_test(struct kunit *test)
{
	struct defex_context dc;
	struct file *test_file;
	char * process_name;

	test_file = local_fopen(ROOT_PATH, O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(test_file));

	/* Target name != "<unknown filename>" */
	init_defex_context(&dc, __DEFEX_execve, current, test_file);
	process_name = get_dc_target_name(&dc);
	KUNIT_EXPECT_NE(test, strncmp(process_name, "<unknown filename>", 18), 0);
	release_defex_context(&dc);
	filp_close(test_file, NULL);

	/* Target name == "<unknown filename>" */
	init_defex_context(&dc, __DEFEX_execve, current, NULL);
	process_name = get_dc_target_name(&dc);
	KUNIT_EXPECT_EQ(test, strncmp(process_name, "<unknown filename>", 18), 0);
	release_defex_context(&dc);
}


static void get_dc_target_dpath_test(struct kunit *test)
{
	struct defex_context dc;
	struct file *test_file;

	test_file = local_fopen(ROOT_PATH, O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(test_file));

	/* With target file, get_dc_target_dpath != NULL */
	init_defex_context(&dc, __DEFEX_execve, current, test_file);
	KUNIT_EXPECT_PTR_NE(test, get_dc_target_dpath(&dc), (const struct path *)NULL);
	release_defex_context(&dc);
	filp_close(test_file, NULL);

	/* Without target file, get_dc_target_dpath == NULL */
	init_defex_context(&dc, __DEFEX_execve, current, NULL);
	KUNIT_EXPECT_PTR_EQ(test, get_dc_target_dpath(&dc), (const struct path *)NULL);
	release_defex_context(&dc);
}


static void get_dc_process_name_test(struct kunit *test)
{
	struct defex_context dc;
	char *process_name;

	init_defex_context(&dc, __DEFEX_execve, current, NULL);
	process_name = get_dc_process_name(&dc);
	KUNIT_EXPECT_EQ(test, strncmp(process_name, "<unknown filename>", 18), 0);
	release_defex_context(&dc);
}


static void get_dc_process_file_test(struct kunit *test)
{
	struct defex_context dc;

	init_defex_context(&dc, __DEFEX_execve, current, NULL);
	KUNIT_EXPECT_PTR_EQ(test, get_dc_process_file(&dc), (struct file *)NULL);
	release_defex_context(&dc);
}


static void get_dc_process_dpath_test(struct kunit *test)
{
	struct defex_context dc;

	init_defex_context(&dc, __DEFEX_execve, current, NULL);
	KUNIT_EXPECT_PTR_EQ(test, get_dc_process_dpath(&dc), (const struct path *)NULL);
	release_defex_context(&dc);

	/* Need a situation in which get_dc_process_dpath != NULL to increase coverage */
}


static void defex_resolve_filename_test(struct kunit *test)
{
	char *filename = NULL;
	char *buff = NULL;

	filename = defex_resolve_filename("/test.txt", &buff);
	KUNIT_EXPECT_PTR_EQ(test, filename, (char *)NULL);

	/* Missing case where dpath in defex_resolve_filename returns != NULL */
}


static void defex_get_source_file_test(struct kunit *test)
{
	KUNIT_EXPECT_PTR_EQ(test, defex_get_source_file(current), (struct file *)NULL);
	/* Not able to test a source file != NULL */
}


static void defex_get_filename_test(struct kunit *test)
{
	char *filename;

	filename = defex_get_filename(current);
	KUNIT_EXPECT_EQ(test, strncmp(filename, "<unknown filename>", 18), 0);

	/* Could not set up a situation where defex_get_source_file is != NULL */
}


static void defex_files_identical_test(struct kunit *test)
{
	/* KUNIT_EXPECT_EQ(test, 1, defex_files_identical()); */
}


static void __vfs_read_test(struct kunit *test)
{
	/* KUNIT_EXPECT_EQ(test, 1, __vfs_read()); */
}


static int defex_common_test_init(struct kunit *test)
{
	/*
	 * test->priv = a_struct_pointer;
	 * if (!test->priv)
	 *    return -ENOMEM;
	 */

	return 0;
}

static void defex_common_test_exit(struct kunit *test)
{
}

static struct kunit_case defex_common_test_cases[] = {
	/* TEST FUNC DEFINES */
	KUNIT_CASE(release_defex_context_test),
	KUNIT_CASE(local_fread_test),
	KUNIT_CASE(local_fopen_test),
	KUNIT_CASE(init_defex_context_test),
	KUNIT_CASE(get_dc_target_name_test),
	KUNIT_CASE(get_dc_target_dpath_test),
	KUNIT_CASE(get_dc_process_name_test),
	KUNIT_CASE(get_dc_process_file_test),
	KUNIT_CASE(get_dc_process_dpath_test),
	KUNIT_CASE(defex_resolve_filename_test),
	KUNIT_CASE(defex_get_source_file_test),
	KUNIT_CASE(defex_get_filename_test),
	KUNIT_CASE(defex_files_identical_test),
	KUNIT_CASE(__vfs_read_test),
	{},
};

static struct kunit_suite defex_common_test_module = {
	.name = "defex_common_test",
	.init = defex_common_test_init,
	.exit = defex_common_test_exit,
	.test_cases = defex_common_test_cases,
};
kunit_test_suites(&defex_common_test_module);

