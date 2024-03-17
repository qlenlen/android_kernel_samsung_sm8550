/*
 * FIVE dmverity functions
 *
 * Copyright (C) 2019 Samsung Electronics, Inc.
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

#ifndef __LINUX_FIVE_DMVERITY_H
#define __LINUX_FIVE_DMVERITY_H

#include <linux/init.h>

struct file;

enum five_dmverity_codes {
	FIVE_DMV_PARTITION,
	FIVE_DMV_BAD_INPUT,
	FIVE_DMV_NO_DM_DEVICE,
	FIVE_DMV_NO_DM_DISK,
	FIVE_DMV_NOT_READONLY_DM_DISK,
	FIVE_DMV_BAD_DM_PREFIX_NAME,
	FIVE_DMV_NO_DM_TABLE,
	FIVE_DMV_NOT_READONLY_DM_TABLE,
	FIVE_DMV_NO_DM_TARGET,
	FIVE_DMV_NOT_SINGLE_TARGET,
	FIVE_DMV_NO_DM_TARGET_NAME,
	FIVE_DMV_NO_SB_LOOP_DEVICE,
	FIVE_DMV_NO_BD_LOOP_DEVICE,
	FIVE_DMV_NO_BD_DISK,
	FIVE_DMV_NO_LOOP_DEV,
	FIVE_DMV_NO_LOOP_BACK_FILE
};

int __init five_init_dmverity(void);
bool five_is_dmverity_protected(const struct file *file);

#endif // __LINUX_FIVE_DMVERITY_H
