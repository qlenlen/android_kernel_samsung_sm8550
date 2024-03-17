
/*
 * FIVE-DSMS integration.
 *
 * Copyright (C) 2020 Samsung Electronics, Inc.
 * Yevgen Kopylov, <y.kopylov@samsung.com>
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

#ifndef __LINUX_FIVE_DSMS_H
#define __LINUX_FIVE_DSMS_H

#ifdef CONFIG_FIVE_DSMS
void five_dsms_sign_err(const char *app, int result);
void five_dsms_reset_integrity(const char *task_name, int result,
				const char *file_name);
void five_dsms_init(const char *version, int result);
#else
static inline void five_dsms_sign_err(const char *app, int result)
{
}

static inline void five_dsms_reset_integrity(const char *task_name, int result,
						const char *file_name)
{
}

static inline void five_dsms_init(const char *version, int result)
{
	pr_debug("FIVE: DSMS is not supported\n");
}
#endif

#endif
