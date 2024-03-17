/*
 * This code is based on IMA's code
 *
 * Copyright (C) 2016 Samsung Electronics, Inc.
 *
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
 * Viacheslav Vovchenko <v.vovchenko@samsung.com>
 * Yevgen Kopylov <y.kopylov@samsung.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <crypto/hash_info.h>
#include "five.h"

int __init five_init(void)
{
	int rc;

	rc = five_keyring_init();
	if (rc)
		return rc;
	rc = five_load_built_x509();
	if (rc)
		return rc;
	rc = five_task_integrity_cache_init();
	if (rc)
		return rc;
	rc = five_init_crypto();

	return rc;
}
