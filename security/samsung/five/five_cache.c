/*
 * FIVE cache functions
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

#include "five_cache.h"
#include "five_porting.h"

enum five_file_integrity five_get_cache_status(
		const struct integrity_iint_cache *iint)
{
	if (unlikely(!iint))
		return FIVE_FILE_UNKNOWN;

	if (!inode_eq_iversion(iint->inode, iint->version))
		return FIVE_FILE_UNKNOWN;

	return iint->five_status;
}

void five_set_cache_status(struct integrity_iint_cache *iint,
		enum five_file_integrity status)
{
	if (unlikely(!iint))
		return;

	iint->version = inode_query_iversion(iint->inode);
	iint->five_status = status;
}

