/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
*/

#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include "include/defex_catch_list.h"

#ifdef DEFEX_KUNIT_ENABLED
#ifndef __NR_syscalls
#define __NR_syscalls   436
#endif
#endif

#define DEFEX_CATCH_COUNT	__NR_syscalls
const int defex_nr_syscalls = DEFEX_CATCH_COUNT;

#include "defex_catch_list.inc"

const struct local_syscall_struct *get_local_syscall(int syscall_no)
{
	if ((unsigned int)syscall_no >= __NR_syscalls)
		return NULL;

	if (!syscall_catch_arr[syscall_no].local_syscall && !syscall_catch_arr[syscall_no].err_code && syscall_no) {
		return &syscall_catch_arr[0];
	}

	return &syscall_catch_arr[syscall_no];
}

int syscall_local2global(int syscall_no)
{
	int i;
	for (i = 0; i < __NR_syscalls; i++) {
		if (syscall_catch_arr[i].local_syscall == syscall_no)
			return i;
	}
	return 0;
}
