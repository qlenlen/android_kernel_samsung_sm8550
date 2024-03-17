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

#ifndef __LINUX_FIVE_CACHE_H
#define __LINUX_FIVE_CACHE_H

#include "security/integrity/integrity.h"

enum five_file_integrity five_get_cache_status(
		const struct integrity_iint_cache *iint);
void five_set_cache_status(struct integrity_iint_cache *iint,
		enum five_file_integrity status);

#endif // __LINUX_FIVE_CACHE_H
