/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/async.h>
#include <linux/delay.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/time.h>
#include <linux/version.h>

#include "include/defex_debug.h"
#include "include/defex_internal.h"
#include "include/defex_rules.h"

static struct kset *defex_kset;

int __init defex_init_sysfs(void)
{
	defex_kset = kset_create_and_add("defex", NULL, NULL);
	if (!defex_kset)
		return -ENOMEM;

#if defined(DEFEX_DEBUG_ENABLE)
	if (defex_create_debug(defex_kset) != DEFEX_OK)
		goto kset_error;
#endif /* DEFEX_DEBUG_ENABLE */

	return 0;

kset_error:
	kset_unregister(defex_kset);
	defex_kset = NULL;

	return -ENOMEM;
}


