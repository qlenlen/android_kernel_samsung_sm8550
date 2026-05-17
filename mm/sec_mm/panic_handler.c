// SPDX-License-Identifier: GPL-2.0
/*
 * sec_mm/
 *
 * Copyright (C) 2020 Samsung Electronics
 *
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/panic_notifier.h>
#include "sec_mm.h"

static int sec_mm_panic_handler(struct notifier_block *nb, unsigned long action,
				void *str_buf)
{
#ifdef CONFIG_SEC_MM
	show_mem(0, NULL);
#endif
	mm_debug_dump_tasks();

	return NOTIFY_DONE;
}

static struct notifier_block panic_block = {
	.notifier_call = sec_mm_panic_handler,
	.priority = 1 /* prior to priority 0 */
};

void init_panic_handler(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &panic_block);
}

void exit_panic_handler(void)
{
	atomic_notifier_chain_unregister(&panic_notifier_list, &panic_block);
}

MODULE_LICENSE("GPL");
