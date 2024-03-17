/*
 * PROCA task descriptor
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

#include "proca_task_descr.h"
#include "proca_identity.h"
#include "proca_log.h"

#include <linux/slab.h>
#include <linux/string.h>

struct proca_task_descr *create_proca_task_descr(struct task_struct *task,
						 struct proca_identity *ident)
{
	struct proca_task_descr *task_descr = kzalloc(sizeof(*task_descr),
							GFP_KERNEL);
	if (unlikely(!task_descr))
		return NULL;

	task_descr->task = task;
	task_descr->proca_identity = *ident;

	PROCA_DEBUG_LOG("Task descriptor for task %d was created\n",
			task->pid);
	PROCA_DEBUG_LOG("Task %d has application name %s\n",
			task->pid, ident->parsed_cert.app_name);

	return task_descr;
}

void destroy_proca_task_descr(struct proca_task_descr *proca_task_descr)
{
	if (!proca_task_descr)
		return;

	PROCA_DEBUG_LOG("Destroying proca task descriptor for task %d\n",
			proca_task_descr->task->pid);
	deinit_proca_identity(&proca_task_descr->proca_identity);
	kfree(proca_task_descr);
}
