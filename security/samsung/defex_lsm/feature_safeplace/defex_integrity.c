/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include "include/defex_internal.h"

#ifdef DEFEX_PERMISSIVE_INT
unsigned char global_integrity_status = 2;
#else
unsigned char global_integrity_status = 1;
#endif /* DEFEX_PERMISSIVE_INT */

int integrity_status_store(const char *status_str)
{
	int ret;
	unsigned int status;

	if (!status_str)
		return -EINVAL;

	ret = kstrtouint(status_str, 10, &status);
	if (ret != 0 || status > 2)
		return -EINVAL;

	global_integrity_status = status;

	return 0;
}
