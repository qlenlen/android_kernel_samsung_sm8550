// SPDX-License-Identifier: GPL-2.0
/*
 * sec_mm/
 *
 * Copyright (C) 2020 Samsung Electronics
 *
 */

#include <linux/module.h>
#include "sec_mm.h"

static int __init sec_mm_init(void)
{
	init_lowfile_detect();
	init_panic_handler();
	pr_info("sec_mm init was done\n");
	return 0;
}

static void __exit sec_mm_exit(void)
{
	exit_lowfile_detect();
	exit_panic_handler();
}

module_init(sec_mm_init);
module_exit(sec_mm_exit);

MODULE_LICENSE("GPL");
