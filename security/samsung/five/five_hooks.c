/*
 * Five Event interface
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
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

#include "five_hooks.h"
#include "five_porting.h"
#include "five_testing.h"

#include <linux/fs.h>
#include <linux/slab.h>

#define call_void_hook(FUNC, ...)				\
	do {							\
		struct five_hook_list *P;			\
								\
		list_for_each_entry(P, &five_hook_heads.FUNC, list)	\
			P->hook.FUNC(__VA_ARGS__);		\
	} while (0)

struct five_hook_heads five_hook_heads = {
	.file_processed =
		LIST_HEAD_INIT(five_hook_heads.file_processed),
	.file_skipped =
		LIST_HEAD_INIT(five_hook_heads.file_skipped),
	.file_signed =
		LIST_HEAD_INIT(five_hook_heads.file_signed),
	.task_forked =
		LIST_HEAD_INIT(five_hook_heads.task_forked),
	.integrity_reset =
		LIST_HEAD_INIT(five_hook_heads.integrity_reset),
	.integrity_reset2 =
		LIST_HEAD_INIT(five_hook_heads.integrity_reset2),
};
EXPORT_SYMBOL_GPL(five_hook_heads);

enum five_hook_event {
	FILE_PROCESSED,
	FILE_SKIPPED,
	FILE_SIGNED,
	TASK_FORKED,
	INTEGRITY_RESET
};

struct hook_wq_event {
	enum five_hook_event event;
	union {
		struct {
			struct task_struct *task;
			enum task_integrity_value tint_value;
			struct file *file;
			void *xattr;
			size_t xattr_size;
			int result;
		} processed;
		struct {
			struct task_struct *task;
			enum task_integrity_value tint_value;
			struct file *file;
		} skipped;
		struct {
			struct task_struct *parent;
			enum task_integrity_value parent_tint_value;
			struct task_struct *child;
			enum task_integrity_value child_tint_value;
		} forked;
		struct {
			struct task_struct *task;
			struct file *file;
			enum task_integrity_reset_cause cause;
		} reset;
	};
};

static void hook_wq_event_destroy(struct hook_wq_event *event)
{
	switch (event->event) {
	case FILE_PROCESSED: {
		fput(event->processed.file);
		put_task_struct(event->processed.task);
		kfree(event->processed.xattr);
		break;
	}
	case FILE_SKIPPED: {
		fput(event->skipped.file);
		put_task_struct(event->skipped.task);
		break;
	}
	case FILE_SIGNED: {
		fput(event->processed.file);
		put_task_struct(event->processed.task);
		kfree(event->processed.xattr);
		break;
	}
	case TASK_FORKED: {
		put_task_struct(event->forked.parent);
		put_task_struct(event->forked.child);
		break;
	}
	case INTEGRITY_RESET: {
		if (event->reset.file)
			fput(event->reset.file);
		put_task_struct(event->reset.task);
		break;
	}
	}
}

struct hook_wq_context {
	struct work_struct data_work;
	struct hook_wq_event payload;
};

static struct workqueue_struct *g_hook_workqueue;

static void hook_handler(struct work_struct *in_data)
{
	struct hook_wq_event *event;
	struct hook_wq_context *context = container_of(in_data,
		struct hook_wq_context, data_work);

	if (unlikely(!context))
		return;
	event = &context->payload;

	switch (event->event) {
	case FILE_PROCESSED: {
		call_void_hook(file_processed,
			event->processed.task,
			event->processed.tint_value,
			event->processed.file,
			event->processed.xattr,
			event->processed.xattr_size,
			event->processed.result);
		break;
	}
	case FILE_SKIPPED: {
		call_void_hook(file_skipped,
			event->skipped.task,
			event->skipped.tint_value,
			event->skipped.file);
		break;
	}
	case FILE_SIGNED: {
		call_void_hook(file_signed,
			event->processed.task,
			event->processed.tint_value,
			event->processed.file,
			event->processed.xattr,
			event->processed.xattr_size,
			event->processed.result);
		break;
	}
	case TASK_FORKED: {
		call_void_hook(task_forked,
			event->forked.parent,
			event->forked.parent_tint_value,
			event->forked.child,
			event->forked.child_tint_value);
		break;
	}
	case INTEGRITY_RESET: {
		call_void_hook(integrity_reset,
			event->reset.task);
		call_void_hook(integrity_reset2, event->reset.task,
			       event->reset.file, event->reset.cause);
		break;
	}
	}

	hook_wq_event_destroy(event);
	kfree(context);
}

static int __push_event(struct hook_wq_event *event, gfp_t flags)
{
	struct hook_wq_context *context;

	if (!g_hook_workqueue)
		return -ENAVAIL;

	context = kmalloc(sizeof(struct hook_wq_context), flags);
	if (unlikely(!context))
		return -ENOMEM;

	context->payload = *event;

	INIT_WORK(&context->data_work, hook_handler);
	return queue_work(g_hook_workqueue, &context->data_work) ? 0 : 1;
}

void five_hook_file_processed(struct task_struct *task,
				struct file *file, void *xattr,
				size_t xattr_size, int result)
{
	struct hook_wq_event event = {0};

	event.event = FILE_PROCESSED;
	get_task_struct(task);
	get_file(file);
	event.processed.task = task;
	event.processed.tint_value = task_integrity_read(TASK_INTEGRITY(task));
	event.processed.file = file;
	/*
	 * xattr parameters are optional, because FIVE could get results
	 * from cache where xattr absents, so we may ignore kmemdup errors
	 */
	if (xattr) {
		event.processed.xattr = kmemdup(xattr, xattr_size, GFP_KERNEL);
		if (event.processed.xattr)
			event.processed.xattr_size = xattr_size;
	}
	event.processed.result = result;

	if (__push_event(&event, GFP_KERNEL) < 0)
		hook_wq_event_destroy(&event);
}

void five_hook_file_signed(struct task_struct *task,
				struct file *file, void *xattr,
				size_t xattr_size, int result)
{
	struct hook_wq_event event = {0};

	event.event = FILE_SIGNED;
	get_task_struct(task);
	get_file(file);
	event.processed.task = task;
	event.processed.tint_value = task_integrity_read(TASK_INTEGRITY(task));
	event.processed.file = file;
	/* xattr parameters are optional, so we may ignore kmemdup errors */
	if (xattr) {
		event.processed.xattr = kmemdup(xattr, xattr_size, GFP_KERNEL);
		if (event.processed.xattr)
			event.processed.xattr_size = xattr_size;
	}
	event.processed.result = result;

	if (__push_event(&event, GFP_KERNEL) < 0)
		hook_wq_event_destroy(&event);
}

void five_hook_file_skipped(struct task_struct *task, struct file *file)
{
	struct hook_wq_event event = {0};

	event.event = FILE_SKIPPED;
	get_task_struct(task);
	get_file(file);
	event.skipped.task = task;
	event.skipped.tint_value = task_integrity_read(TASK_INTEGRITY(task));
	event.skipped.file = file;

	if (__push_event(&event, GFP_KERNEL) < 0)
		hook_wq_event_destroy(&event);
}

void five_hook_task_forked(struct task_struct *parent,
				struct task_struct *child)
{
	struct hook_wq_event event = {0};

	event.event = TASK_FORKED;
	get_task_struct(parent);
	get_task_struct(child);
	event.forked.parent = parent;
	event.forked.parent_tint_value =
				task_integrity_read(TASK_INTEGRITY(parent));
	event.forked.child = child;
	event.forked.child_tint_value =
				task_integrity_read(TASK_INTEGRITY(child));

	if (__push_event(&event, GFP_ATOMIC) < 0)
		hook_wq_event_destroy(&event);
}

int five_hook_wq_init(void)
{
	g_hook_workqueue = alloc_ordered_workqueue("%s",
				WQ_MEM_RECLAIM | WQ_FREEZABLE, "five_hook_wq");
	if (!g_hook_workqueue)
		return -ENOMEM;

	return 0;
}

__mockable
void five_hook_integrity_reset(struct task_struct *task,
			       struct file *file,
			       enum task_integrity_reset_cause cause)
{
	struct hook_wq_event event = {0};

	if (task == NULL)
		return;

	event.event = INTEGRITY_RESET;
	get_task_struct(task);
	if (file)
		get_file(file);
	event.reset.task = task;
	event.reset.file = file;
	event.reset.cause = cause;

	if (__push_event(&event, GFP_KERNEL) < 0)
		hook_wq_event_destroy(&event);
}
