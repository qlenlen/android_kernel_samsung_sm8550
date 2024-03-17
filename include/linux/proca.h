/*
 * PROCA fnctl declarations
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 * Hryhorii Tur, <hryhorii.tur@partner.samsung.com>
 * Ivan Vorobiov, <i.vorobiov@samsung.com>
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

#ifndef _LINUX_PROCA_H
#define _LINUX_PROCA_H

#include <linux/sched.h>
#include <linux/file.h>

#if defined(CONFIG_FIVE_PA_FEATURE) || defined(CONFIG_PROCA)
int proca_fcntl_setxattr(struct file *file, void __user *lv_xattr);
#else
static inline int proca_fcntl_setxattr(struct file *file, void __user *lv_xattr)
{
	return 0;
}
#endif

#if defined(CONFIG_PROCA)
int proca_get_task_cert(const struct task_struct *task,
			const char **cert, size_t *cert_size);
#else
static inline int proca_get_task_cert(const struct task_struct *task,
				      const char **cert, size_t *cert_size)
{
	return -ESRCH;
}
#endif

void proca_compat_task_free_hook(struct task_struct *task);
void proca_compat_file_free_security_hook(struct file *file);

#endif /* _LINUX_PROCA_H */
