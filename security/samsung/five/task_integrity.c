/*
 * Task Integrity Verifier
 *
 * Copyright (C) 2016 Samsung Electronics, Inc.
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

#include <linux/task_integrity.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include "five_porting.h"
#include "five_testing.h"

static struct kmem_cache *task_integrity_cache;

__visible_for_testing
void init_once(void *foo)
{
	struct task_integrity *intg = foo;

	memset(intg, 0, sizeof(*intg));
	spin_lock_init(&intg->value_lock);
	spin_lock_init(&intg->list_lock);
}

static int __init task_integrity_cache_init(void)
{
	task_integrity_cache = kmem_cache_create("task_integrity_cache",
			sizeof(struct task_integrity), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, init_once);

	if (!task_integrity_cache)
		return -ENOMEM;

	return 0;
}

security_initcall(task_integrity_cache_init);

struct task_integrity *task_integrity_alloc(void)
{
	struct task_integrity *intg;

	intg = kmem_cache_alloc(task_integrity_cache, GFP_KERNEL);
	if (intg) {
		atomic_set(&intg->usage_count, 1);
		INIT_LIST_HEAD(&intg->events.list);
	}

	return intg;
}

void task_integrity_free(struct task_integrity *intg)
{
	if (intg) {
		/* These values should be changed under "value_lock" spinlock.
		   But then lockdep prints warning because this function can be called
		   from sw-irq (from function free_task).
		   Actually deadlock never happens because this function is called
		   only if usage_count is 0 (no reference to this struct),
		   so changing these values without spinlock is safe.
		*/
		kfree(intg->label);
		intg->label = NULL;
		intg->user_value = INTEGRITY_NONE;
		intg->value = INTEGRITY_NONE;
		atomic_set(&intg->usage_count, 0);

		intg->reset_cause = CAUSE_UNSET;
		if (intg->reset_file) {
			fput(intg->reset_file);
			intg->reset_file = NULL;
		}

		kmem_cache_free(task_integrity_cache, intg);
	}
}

void task_integrity_clear(struct task_integrity *tint)
{
	task_integrity_set(tint, INTEGRITY_NONE);
	spin_lock(&tint->value_lock);
	kfree(tint->label);
	tint->label = NULL;
	spin_unlock(&tint->value_lock);

	tint->reset_cause = CAUSE_UNSET;
	if (tint->reset_file) {
		fput(tint->reset_file);
		tint->reset_file = NULL;
	}
}

__visible_for_testing
int copy_label(struct task_integrity *from, struct task_integrity *to)
{
	int ret = 0;
	struct integrity_label *l = NULL;

	if (task_integrity_read(from) && from->label)
		l = from->label;

	if (l) {
		struct integrity_label *label;

		label = kmalloc(sizeof(*label) + l->len, GFP_ATOMIC);
		if (!label) {
			ret = -ENOMEM;
			goto exit;
		}

		label->len = l->len;
		memcpy(label->data, l->data, label->len);
		to->label = label;
	}

exit:
	return ret;
}

int task_integrity_copy(struct task_integrity *from, struct task_integrity *to)
{
	int rc = -EPERM;
	enum task_integrity_value value = task_integrity_read(from);

	task_integrity_set(to, value);

	if (list_empty(&from->events.list))
		to->user_value = value;

	rc = copy_label(from, to);

	to->reset_cause = from->reset_cause;
	if (from->reset_file) {
		get_file(from->reset_file);
		to->reset_file = from->reset_file;
	}

	return rc;
}

char const * const tint_reset_cause_to_string(
	enum task_integrity_reset_cause cause)
{
	static const char * const tint_cause2str[] = {
		[CAUSE_UNSET] = "unset",
		[CAUSE_UNKNOWN] = "unknown",
		[CAUSE_MISMATCH_LABEL] = "mismatch-label",
		[CAUSE_BAD_FS] = "bad-fs",
		[CAUSE_NO_CERT] = "no-cert",
		[CAUSE_INVALID_HASH_LENGTH] = "invalid-hash-length",
		[CAUSE_INVALID_HEADER] = "invalid-header",
		[CAUSE_CALC_HASH_FAILED] = "calc-hash-failed",
		[CAUSE_INVALID_LABEL_DATA] = "invalid-label-data",
		[CAUSE_INVALID_SIGNATURE_DATA] = "invalid-signature-data",
		[CAUSE_INVALID_HASH] = "invalid-hash",
		[CAUSE_INVALID_CALC_CERT_HASH] = "invalid-calc-cert-hash",
		[CAUSE_INVALID_UPDATE_LABEL] = "invalid-update-label",
		[CAUSE_INVALID_SIGNATURE] = "invalid-signature",
		[CAUSE_UKNOWN_FIVE_DATA] = "unknown-five-data",
		[CAUSE_PTRACE] = "ptrace",
		[CAUSE_VMRW] = "vmrw",
		[CAUSE_EXEC] = "exec",
		[CAUSE_TAMPERED] = "tampered",
		[CAUSE_MAX] = "incorrect-cause",
	};

	if (cause > CAUSE_MAX)
		cause = CAUSE_MAX;

	return tint_cause2str[cause];
}

/*
 * task_integrity_set_reset_reason
 *
 * Only first call of this function per task will have effect, because first
 * reason will be root cause.
 */
void task_integrity_set_reset_reason(struct task_integrity *intg,
	enum task_integrity_reset_cause cause, struct file *file)
{
	if (intg->reset_cause != CAUSE_UNSET)
		return;

	intg->reset_cause = cause;
	if (file) {
		get_file(file);
		intg->reset_file = file;
	}
}
