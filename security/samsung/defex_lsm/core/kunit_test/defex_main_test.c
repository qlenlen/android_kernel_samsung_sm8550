/*
 * Copyright (c) 2020-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/defex.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include "include/defex_internal.h"
#include "include/defex_test.h"
#include "include/defex_rules.h"
#include "include/defex_catch_list.h"

#define SAMPLE_PATH "/system/bin/umh/dsms"
#define DUMMY_FILE  "/dummy.txt"
#define SHELL_PATH  "/system/bin/sh"
#define ROOT_PATH   "/"
#define REBOOT_PATH "/system/bin/reboot"
#define dead_uid 0xDEADBEAF

static int kunit_mock_thread_function(void *ptr)
{
	while (!kthread_should_stop()) {
		msleep(100);
	}
	return 42;
}

/* General test functions created by Generate_KUnit.sh */

static void verifiedboot_state_setup_test(struct kunit *test)
{
	/* KUNIT_EXPECT_EQ(test, 1, verifiedboot_state_setup()); */
	KUNIT_SUCCEED(test);
}


static void task_defex_zero_creds_test(struct kunit *test)
{
	struct task_struct *mock_task;
	unsigned int backup_flags;

	mock_task = kthread_run(kunit_mock_thread_function, NULL, "task_defex_zero_creds_test_thread");
	get_task_struct(mock_task);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(mock_task));
	ssleep(1);

	/* tsk->flags & (PF_KTHREAD | PF_WQ_WORKER) */
	KUNIT_EXPECT_EQ(test, task_defex_zero_creds(current), 0);

	backup_flags = mock_task->flags;
	mock_task->flags &= ~PF_KTHREAD;
	mock_task->flags &= ~PF_WQ_WORKER;
#ifdef TASK_NEW
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
	/* is_fork = 0 (mock_task->state & TASK_NEW) == true */
	mock_task->state |= TASK_NEW;
#else
	mock_task->__state |= TASK_NEW;
#endif
#endif
	KUNIT_EXPECT_EQ(test, task_defex_zero_creds(mock_task), 0);
	mock_task->flags = backup_flags;

	/* Finalize */
	kthread_stop(mock_task);
	put_task_struct(mock_task);
}


static void task_defex_user_exec_test(struct kunit *test)
{
#ifdef DEFEX_UMH_RESTRICTION_ENABLE
	/* Non-existant file */
	KUNIT_EXPECT_EQ(test, task_defex_user_exec(DUMMY_FILE), DEFEX_DENY);
	/* /system/bin/sh is a violation */
	KUNIT_EXPECT_EQ(test, task_defex_user_exec(SHELL_PATH), DEFEX_DENY);
	/* /system/bin/umh/dsms is not a violation ONLY after first boot*/
	//It's not clear what to expect with automated testing
	//KUNIT_EXPECT_EQ(test, task_defex_user_exec(SAMPLE_PATH), DEFEX_ALLOW);
#ifdef DEFEX_FACTORY_ENABLE
	KUNIT_EXPECT_EQ(test, task_defex_user_exec(REBOOT_PATH), DEFEX_DENY);
#endif /* DEFEX_FACTORY_ENABLE */
#else
	KUNIT_SUCCEED(test);
#endif /* DEFEX_UMH_RESTRICTION_ENABLE */
}


static void task_defex_src_exception_test(struct kunit *test)
{
#ifdef DEFEX_IMMUTABLE_ENABLE
	struct defex_context dc;

	init_defex_context(&dc, 0, current, NULL);
	KUNIT_EXPECT_EQ(test, task_defex_src_exception(&dc), 1);
	release_defex_context(&dc);
	/* Need a situation in which get_dc_process_dpath != NULL to increase coverage */
#else
	KUNIT_SUCCEED(test);
#endif
}


static void task_defex_safeplace_test(struct kunit *test)
{
#ifdef DEFEX_SAFEPLACE_ENABLE
	struct defex_context dc;
	struct task_struct *mock_task;
	struct cred mock_creds;
	struct file *test_file;

	mock_task = kthread_run(kunit_mock_thread_function, NULL, "task_defex_safeplace_test_thread");
	get_task_struct(mock_task);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(mock_task));
	ssleep(1);
	test_file = local_fopen(ROOT_PATH, O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(test_file));

	init_defex_context(&dc, 0, mock_task, test_file);
	dc.cred = (struct cred *)mock_task->cred;

	/* "/" path is a violation, but only after first boot. */
	KUNIT_EXPECT_EQ(test, task_defex_safeplace(&dc), -DEFEX_DENY);

	/* Create fake, non-root creds */
	mock_creds.uid.val = 1000;
	mock_creds.gid.val = 1000;
	mock_creds.suid.val = 1000;
	mock_creds.sgid.val = 1000;
	mock_creds.euid.val = 1000;
	mock_creds.egid.val = 1000;
	mock_creds.fsuid.val = 1000;
	mock_creds.fsgid.val = 1000;

	/* if dc->cred not root, allow */
	dc.cred = &mock_creds;
	KUNIT_EXPECT_EQ(test, task_defex_safeplace(&dc), DEFEX_ALLOW);
	release_defex_context(&dc);
	filp_close(test_file, NULL);

	/* Another context with no file */
	init_defex_context(&dc, 0, mock_task, NULL);
	dc.cred = (struct cred *)mock_task->cred;
	KUNIT_EXPECT_EQ(test, task_defex_safeplace(&dc), DEFEX_ALLOW);
	release_defex_context(&dc);

	/* Finalize */
	kthread_stop(mock_task);
	put_task_struct(mock_task);
#else
	KUNIT_SUCCEED(test);
#endif
}


static void task_defex_is_secured_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE
	struct defex_context dc;
	struct file *test_file;

	/* The only thing verified in context is dc->target_dpath */
	/* Everything else is not important                       */
	init_defex_context(&dc, 0, current, NULL);

	/* Returns 0 with NULL target_dpath */
	KUNIT_EXPECT_EQ(test, task_defex_is_secured(&dc), 0);
	release_defex_context(&dc);

	/* Could not get a situation which dc->target_dpath != NULL */
	test_file = local_fopen(ROOT_PATH, O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR(test_file));
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(test_file));

	init_defex_context(&dc, 0, current, test_file);
	KUNIT_EXPECT_EQ(test, task_defex_is_secured(&dc), 0);
	release_defex_context(&dc);
#else
	KUNIT_SUCCEED(test);
#endif
}


static void task_defex_immutable_test(struct kunit *test)
{
#ifdef DEFEX_IMMUTABLE_ENABLE
	struct defex_context dc;
	struct file *f;

	/* Allow case - get_dc_target_dpath() == NULL */
	init_defex_context(&dc, 0, current, NULL);
	KUNIT_EXPECT_EQ(test, task_defex_immutable(&dc, 0), DEFEX_ALLOW);
	release_defex_context(&dc);

	f = local_fopen(SHELL_PATH, O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(f));

	/* Allow case - feature_immutable_path_open && task_defex_src_exception == 1 */
	init_defex_context(&dc, 0, current, f);
	KUNIT_EXPECT_EQ(test, task_defex_immutable(&dc, feature_immutable_path_open), DEFEX_ALLOW);

	/* Deny case - !feature_immutable_path_open */
	KUNIT_EXPECT_EQ(test, task_defex_immutable(&dc, feature_immutable_path_write), -DEFEX_DENY);

	/* Finalize */
	release_defex_context(&dc);
	filp_close(f, NULL);
#else
	KUNIT_SUCCEED(test);
#endif
}


static void task_defex_enforce_test(struct kunit *test)
{
#if defined DEFEX_SAFEPLACE_ENABLE || defined DEFEX_IMMUTABLE_ENABLE
	struct file *test_file = NULL;
#endif
	struct task_struct *mock_task = NULL;
	int aux_integer;
	pid_t backup_pid;

	mock_task = kthread_run(kunit_mock_thread_function, NULL, "task_defex_enforce_test_thread");
	get_task_struct(mock_task);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(mock_task));
	ssleep(1);

	/* p == NULL -> DEFEX_ALLOW */
	KUNIT_EXPECT_EQ(test, task_defex_enforce(NULL, NULL, 0), DEFEX_ALLOW);

	/* p->mm == NULL -> DEFEX_ALLOW */
	KUNIT_EXPECT_EQ(test, task_defex_enforce(mock_task, NULL, 0), DEFEX_ALLOW);

	/* pid = 1 -> DEFEX_ALLOW */
	backup_pid = mock_task->pid;
	mock_task->pid = 1;
	KUNIT_EXPECT_EQ(test, task_defex_enforce(mock_task, NULL, 0), DEFEX_ALLOW);
	mock_task->pid = backup_pid;

	/* syscall < 0 && (-syscall >= __NR_syscalls) -> DEFEX_ALLOW */
	aux_integer = -(__NR_syscalls + 1);
	KUNIT_EXPECT_EQ(test, task_defex_enforce(mock_task, NULL, aux_integer), DEFEX_ALLOW);

	/* No checks -> DEFEX_ALLOW */
	KUNIT_EXPECT_EQ(test, task_defex_enforce(mock_task, NULL, __DEFEX_stat), DEFEX_ALLOW);
	kthread_stop(mock_task);
	put_task_struct(mock_task);

#ifdef DEFEX_PED_ENABLE
	/* if task_defex_check_creds(&dc) != 0, kill process group. */
	/* Need to build test that results in violation */
#endif

#ifdef DEFEX_SAFEPLACE_ENABLE
	mock_task = kthread_run(kunit_mock_thread_function, NULL, "task_defex_enforce_test_thread");
	get_task_struct(mock_task);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(mock_task));
	ssleep(1);

	/* If task_defex_safeplace == -DEFEX_DENY and FEATURE_SAFEPLACE_SOFT disabled, kill process */
	/* Open file that will trigger a violation */
	test_file = local_fopen(ROOT_PATH, O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(test_file));

	/* If FEATURE_SAFEPLACE_SOFT not set, the process is killed */
	if (!(defex_get_features() & FEATURE_SAFEPLACE_SOFT)) {
		KUNIT_EXPECT_EQ(test, task_defex_enforce(mock_task, test_file, __DEFEX_execve), -DEFEX_DENY);
		put_task_struct(mock_task);
	}
	else{
		KUNIT_EXPECT_EQ(test, task_defex_enforce(mock_task, test_file, __DEFEX_execve), DEFEX_ALLOW);
		kthread_stop(mock_task);
		put_task_struct(mock_task);
	}
	filp_close(test_file, 0);

#endif
#ifdef DEFEX_IMMUTABLE_ENABLE
	mock_task = kthread_run(kunit_mock_thread_function, NULL, "task_defex_enforce_test_thread");
	get_task_struct(mock_task);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(mock_task));
	ssleep(1);

	test_file = local_fopen(SHELL_PATH, O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(test_file));

	/* Immutable path write returns -DEFEX_DENY */
	/* if FEATURE_IMMUTABLE_SOFT enabled, return DEFEX_ALLOW */
	if (defex_get_features() & FEATURE_IMMUTABLE_SOFT)
		KUNIT_EXPECT_EQ(test, task_defex_enforce(mock_task, test_file, __DEFEX_write), DEFEX_ALLOW);
	else
		KUNIT_EXPECT_EQ(test, task_defex_enforce(mock_task, test_file, __DEFEX_write), -DEFEX_DENY);

	filp_close(test_file, 0);
	kthread_stop(mock_task);
	put_task_struct(mock_task);
#endif
}


static void task_defex_check_creds_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE
	int i;
	struct cred mock_creds;
	struct defex_context dc;
	struct task_struct *mock_task;
	struct task_struct *backup_parent;
	pid_t backup_pid;

	/* Creates a mock task */
	mock_task = kthread_run(kunit_mock_thread_function, NULL, "task_defex_check_creds_test_thread");
	get_task_struct(mock_task);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(mock_task));
	ssleep(1);
	init_defex_context(&dc, 0, mock_task, NULL);
	dc.cred = (struct cred *)mock_task->cred;

	/* Create fake, non-root creds */
	mock_creds.uid.val = 2000;
	mock_creds.gid.val = 2000;
	mock_creds.suid.val = 2000;
	mock_creds.sgid.val = 2000;
	mock_creds.euid.val = 2000;
	mock_creds.egid.val = 2000;
	mock_creds.fsuid.val = 500;
	mock_creds.fsgid.val = 500;

	/* mock_task->uid == 0 && (mock_task->tgid != mock_task->pid && mock_task->tgid != 1) --> -DEFEX_DENY */
	backup_pid = mock_task->pid;
	mock_task->pid = mock_task->pid + 1000;
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), -DEFEX_DENY);
	mock_task->pid = backup_pid;

	/* Allow case: uid = 0, parent is root, dc.cred is root */
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), DEFEX_ALLOW);

	dc.cred = &mock_creds;

	/* Allow case: uid = 0, parent is root, dc.cred not root */
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), DEFEX_ALLOW);

	/* Allow case: uid = 0, no parent, dc.cred not root */
	i = set_task_creds(mock_task, 0, 0, 0, 0);
	KUNIT_ASSERT_EQ(test, i, 0);
	backup_parent = mock_task->parent;
	mock_task->parent = NULL;
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), DEFEX_ALLOW);
	mock_task->parent = backup_parent;

	/* mock_task->uid = 1 -> mock_task receives dc.cred if not root */
	i = set_task_creds(mock_task, 1, 0, 0, 0);
	KUNIT_ASSERT_EQ(test, i, 0);
	/* Task will receive root creds because of its root parent -> No violation. */
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), DEFEX_ALLOW);

	/* Deny case: uid = dead_uid */
	i = set_task_creds(mock_task, dead_uid, 0, 0, 0);
	KUNIT_ASSERT_EQ(test, i, 0);
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), -DEFEX_DENY);

	/* uid != 0, uid != 1, uid != dead_uid */
	i = set_task_creds(mock_task, 2000, 20000, 2000, 0);
	KUNIT_ASSERT_EQ(test, i, 0);
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), DEFEX_ALLOW);

	/* uid != 0, uid != 1, uid != dead_uid, check deeper, dc.cred is not root*/
	i = set_task_creds(mock_task, 2000, 20000, 2000, 0);
	KUNIT_ASSERT_EQ(test, i, 0);
	backup_pid = mock_task->pid;
	mock_task->pid = mock_task->pid + 1000;
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), DEFEX_ALLOW);

	/* uid != 0, uid != 1, uid != dead_uid, check deeper, dc.cred is root*/
	i = set_task_creds(mock_task, 2000, 20000, 2000, 0);
	KUNIT_ASSERT_EQ(test, i, 0);
	dc.cred = (struct cred *)mock_task->cred;
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), DEFEX_ALLOW);
	mock_task->pid = backup_pid;

	/* mock_task->uid = 1, no parent, dc.cred is root */
	i = set_task_creds(mock_task, 1, 0, 0, 0);
	KUNIT_ASSERT_EQ(test, i, 0);
	backup_parent = mock_task->parent;
	mock_task->parent = NULL;
	KUNIT_EXPECT_EQ(test, task_defex_check_creds(&dc), DEFEX_ALLOW);
	mock_task->parent = backup_parent;

	/* Finalize */
	release_defex_context(&dc);
	kthread_stop(mock_task);
	put_task_struct(mock_task);
#else
	KUNIT_SUCCEED(test);
#endif
}


static void lower_adb_permission_test(struct kunit *test)
{
/* NOTE: code encapsulated by DEFEX_PERMISSIVE_LP in defex_main is not covered. */
#if defined DEFEX_PED_ENABLE && defined DEFEX_LP_ENABLE
	struct defex_context dc;
	struct task_struct *parent_backup;

	/* The only thing verified in context is dc->p->parent */
	/* Everything else is not important */
	init_defex_context(&dc, 0, current, NULL);
	KUNIT_EXPECT_EQ(test, lower_adb_permission(&dc, 0), 0);

	parent_backup = current->parent;
	current->parent = NULL;
	KUNIT_EXPECT_EQ(test, lower_adb_permission(&dc, 0), 0);

	current->parent = parent_backup;
	release_defex_context(&dc);
#else
	KUNIT_SUCCEED(test);
#endif
}


static void kill_process_group_test(struct kunit *test)
{
	/* KUNIT_EXPECT_EQ(test, 1, kill_process_group()); */
}


static void kill_process_test(struct kunit *test)
{
#ifdef DEFEX_SAFEPLACE_ENABLE
	struct task_struct *mock_task;

	/* Let's create a new task to kill */
	mock_task = kthread_run(kunit_mock_thread_function, NULL, "kill_process_test_thread");
	get_task_struct(mock_task);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(mock_task));
	ssleep(1);
	KUNIT_ASSERT_PTR_NE(test, mock_task, (struct task_struct *)NULL);
	KUNIT_EXPECT_EQ(test, kill_process(mock_task), (long)0);
#else
	KUNIT_SUCCEED(test);
#endif
}


static void get_warranty_bit_test(struct kunit *test)
{
    /* KUNIT_EXPECT_EQ(test, 1, get_warranty_bit()); */
}


static void get_parent_task_test(struct kunit *test)
{
	static struct task_struct DUMMY_TASK;
	struct task_struct *mock_task = &DUMMY_TASK;
	mock_task->pid = 9787;

	/* No parent first */
	mock_task->parent = NULL;
	KUNIT_EXPECT_PTR_EQ(test, get_parent_task(mock_task), (struct task_struct *)NULL);

	/* Real parent now */
	mock_task->parent = current;
	KUNIT_EXPECT_EQ(test, get_parent_task(mock_task)->pid, current->pid);
}


static void defex_report_violation_test(struct kunit *test)
{
#ifdef DEFEX_DSMS_ENABLE
#define PED_VIOLATION "DFX1" /* from defex_main.c */
	struct defex_context dc;

	init_defex_context(&dc, __NR_uname, current, NULL);
	/* Check if the object was created successfully */
	KUNIT_ASSERT_EQ(test, dc.syscall_no, __NR_uname);
	KUNIT_ASSERT_EQ(test, dc.task->pid, current->pid);

	defex_report_violation(PED_VIOLATION, 1234, &dc, 
				get_current_cred()->uid.val + 10000, 
				get_current_cred()->fsuid.val,
				get_current_cred()->egid.val + 2000,
				0 /* ? */);
	release_defex_context(&dc);
#else
	KUNIT_SUCCEED(test);
#endif
}


static void at_same_group_gid_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE
	/* allow the weaken privilege (gid1 >= 10000 && gid2 < 10000) */
	KUNIT_EXPECT_EQ(test, at_same_group_gid(11000, 5000), 1);
	/* allow traverse in the same class ((gid1 / 1000) == (gid2 / 1000)) */
	KUNIT_EXPECT_EQ(test, at_same_group_gid(11010, 11230), 1);
	/* allow traverse to isolated ranges (gid1 >= 90000) */
	KUNIT_EXPECT_EQ(test, at_same_group_gid(100000, 0), 1);
	/* allow LoD process (LoD_base = 0x61A8) */
	KUNIT_EXPECT_EQ(test, at_same_group_gid(0x61A80010u, 0x61A80100u), 1);
	/* allow LoD process (LoD_base = 0x61A8) */
	KUNIT_EXPECT_EQ(test, at_same_group_gid(3003, 0x61A80100u), 1);
	/* deny test */
	KUNIT_EXPECT_EQ(test, at_same_group_gid(500, 20000), 0);
#else
	KUNIT_SUCCEED(test);
#endif
}


static void at_same_group_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE
	/* allow the weaken privilege (uid1 >= 10000 && uid2 < 10000) */
	KUNIT_EXPECT_EQ(test, at_same_group(11000, 5000), 1);
	/* allow traverse in the same class ((uid1 / 1000) == (uid2 / 1000)) */
	KUNIT_EXPECT_EQ(test, at_same_group(11010, 11230), 1);
	/* allow traverse to isolated ranges (uid1 >= 90000) */
	KUNIT_EXPECT_EQ(test, at_same_group(100000, 0), 1);
	/* allow LoD process (LoD_base = 0x61A8) */
	KUNIT_EXPECT_EQ(test, at_same_group(0x61A80010, 0x61A80100), 1);
	/* deny test */
	KUNIT_EXPECT_EQ(test, at_same_group(500, 20000), 0);
#else
	KUNIT_SUCCEED(test);
#endif
}


static int defex_main_test_init(struct kunit *test)
{
	/*
	 * test->priv = a_struct_pointer;
	 * if (!test->priv)
	 *    return -ENOMEM;
	 */

	return 0;
}

static void defex_main_test_exit(struct kunit *test)
{
}

static struct kunit_case defex_main_test_cases[] = {
	/* TEST FUNC DEFINES */
	KUNIT_CASE(verifiedboot_state_setup_test),
	KUNIT_CASE(task_defex_zero_creds_test),
	KUNIT_CASE(task_defex_user_exec_test),
	KUNIT_CASE(task_defex_src_exception_test),
	KUNIT_CASE(task_defex_safeplace_test),
	KUNIT_CASE(task_defex_is_secured_test),
	KUNIT_CASE(task_defex_immutable_test),
	KUNIT_CASE(task_defex_enforce_test),
	KUNIT_CASE(task_defex_check_creds_test),
	KUNIT_CASE(lower_adb_permission_test),
	KUNIT_CASE(kill_process_group_test),
	KUNIT_CASE(kill_process_test),
	KUNIT_CASE(get_warranty_bit_test),
	KUNIT_CASE(get_parent_task_test),
	KUNIT_CASE(defex_report_violation_test),
	KUNIT_CASE(at_same_group_gid_test),
	KUNIT_CASE(at_same_group_test),
	{},
};

static struct kunit_suite defex_main_test_module = {
	.name = "defex_main_test",
	.init = defex_main_test_init,
	.exit = defex_main_test_exit,
	.test_cases = defex_main_test_cases,
};
kunit_test_suites(&defex_main_test_module);

