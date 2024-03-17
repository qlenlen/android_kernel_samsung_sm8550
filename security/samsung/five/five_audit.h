/*
 * Audit calls for FIVE audit subsystem.
 *
 * Copyright (C) 2017 Samsung Electronics, Inc.
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
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

#ifndef __LINUX_FIVE_AUDIT_H
#define __LINUX_FIVE_AUDIT_H

#include <linux/task_integrity.h>

void five_audit_verbose(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result);
void five_audit_info(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result);
void five_audit_err(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result);
void five_audit_sign_err(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result);
void five_audit_tee_msg(const char *func, const char *cause, int rc,
							uint32_t origin);

void five_audit_hexinfo(struct file *file,
		const char *msg, char *data, size_t data_length);

#endif
