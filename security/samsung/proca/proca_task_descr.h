/*
 * PROCA task descriptor interface
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 * Hryhorii Tur, <hryhorii.tur@partner.samsung.com>
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

#ifndef __LINUX_PROCA_TASK_DESCR_H
#define __LINUX_PROCA_TASK_DESCR_H

#include <linux/file.h>
#include <linux/types.h>
#include <linux/sched.h>

#include "proca_identity.h"

struct proca_task_descr {
	struct task_struct *task;
	struct proca_identity proca_identity;
	struct hlist_node pid_map_node;
	struct hlist_node app_name_map_node;
};

struct proca_task_descr *create_proca_task_descr(struct task_struct *task,
						 struct proca_identity *ident);

void destroy_proca_task_descr(struct proca_task_descr *proca_task_descr);

#endif /* __LINUX_PROCA_H */
