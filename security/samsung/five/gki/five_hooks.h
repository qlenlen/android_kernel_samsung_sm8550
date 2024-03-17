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

#ifndef _FIVE_HOOKS_H
#define _FIVE_HOOKS_H

#include <linux/file.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/task_integrity.h>

void five_hook_file_processed(struct task_struct *task,
				struct file *file, void *xattr,
				size_t xattr_size, int result);

void five_hook_task_forked(struct task_struct *parent,
				struct task_struct *child);

void five_hook_file_skipped(struct task_struct *task,
				struct file *file);

void five_hook_file_signed(struct task_struct *task,
				struct file *file, void *xattr,
				size_t xattr_size, int result);

void five_hook_integrity_reset(struct task_struct *task,
			       struct file *file,
			       enum task_integrity_reset_cause cause);

union five_list_options {
	void (*file_processed)(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file,
				void *xattr,
				size_t xattr_size,
				int result);

	void (*file_skipped)(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file);

	void (*task_forked)(struct task_struct *parent,
				enum task_integrity_value parent_tint_value,
				struct task_struct *child,
				enum task_integrity_value child_tint_value);

	void (*file_signed)(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file, void *xattr,
				size_t xattr_size, int result);
	void (*integrity_reset)(struct task_struct *task);
	void (*integrity_reset2)(struct task_struct *task,
				 struct file *file,
				 enum task_integrity_reset_cause cause);
};

struct five_hook_heads {
	struct list_head file_processed;
	struct list_head file_skipped;
	struct list_head file_signed;
	struct list_head task_forked;
	struct list_head integrity_reset;
	struct list_head integrity_reset2;
};

/*
 * FIVE module hook list structure.
 * For use with generic list macros for common operations.
 */
struct five_hook_list {
	struct list_head list;
	struct list_head *head;
	union five_list_options hook;
};

/*
 * Initializing a five_hook_list structure takes
 * up a lot of space in a source file. This macro takes
 * care of the common case and reduces the amount of
 * text involved.
 */
#define FIVE_HOOK_INIT(HEAD, HOOK) \
	{ .head = &five_hook_heads.HEAD, .hook = { .HEAD = HOOK } }

extern struct five_hook_heads five_hook_heads;

static inline void five_add_hooks(struct five_hook_list *hooks,
				      int count)
{
	int i;

	for (i = 0; i < count; i++)
		list_add_tail_rcu(&hooks[i].list, hooks[i].head);
}

int five_hook_wq_init(void);

#endif /* _FIVE_HOOKS_H */
