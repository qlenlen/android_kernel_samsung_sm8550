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

#ifndef _LINUX_TASK_INTEGRITY_H
#define _LINUX_TASK_INTEGRITY_H

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/dcache.h>
#include <linux/version.h>

struct linux_binprm;
struct task_integrity;

struct integrity_label {
	uint16_t len;
	uint8_t data[0];
} __packed;

enum five_event {
	FIVE_RESET_INTEGRITY,
	FIVE_VERIFY_BUNCH_FILES,
};

/*
 * This is list of numbers which Hamming distance is 16
 *
 * 0x00000000 <-- used
 * 0x0f0f0f0f,
 * 0xf0f0f0f0,
 * 0x0000ffff,
 * 0xffff0000,
 * 0xff00ff00,
 * 0x00ff00ff,
 * 0x33333333,<-- used
 * 0xcccccccc,<-- used
 * 0x55555555,<-- used
 * 0x5a5a5a5a,<-- used
 * 0xa5a5a5a5,
 * 0xaaaaaaaa,<-- used
 * 0x3c3c3c3c,<-- used
 * 0xc3c3c3c3,
 * 0xffffffff <-- used
 */
enum task_integrity_value {
	INTEGRITY_NONE                = 0x00000000,
	INTEGRITY_PRELOAD             = 0x33333333,
	INTEGRITY_PRELOAD_ALLOW_SIGN  = 0xcccccccc,
	INTEGRITY_MIXED               = 0x55555555,
	INTEGRITY_MIXED_ALLOW_SIGN    = 0x5a5a5a5a,
	INTEGRITY_DMVERITY            = 0xaaaaaaaa,
	INTEGRITY_DMVERITY_ALLOW_SIGN = 0x3c3c3c3c,
	INTEGRITY_PROCESSING          = 0xffffffff
};

struct processing_event_list {
	enum five_event event;
	struct task_struct *task;
	struct file *file;
	int function;
	struct list_head list;
};

enum task_integrity_reset_cause {
	CAUSE_UNSET,
	CAUSE_UNKNOWN,
	CAUSE_MISMATCH_LABEL,
	CAUSE_BAD_FS,
	CAUSE_NO_CERT,
	CAUSE_INVALID_HASH_LENGTH,
	CAUSE_INVALID_HEADER,
	CAUSE_CALC_HASH_FAILED,
	CAUSE_INVALID_LABEL_DATA,
	CAUSE_INVALID_SIGNATURE_DATA,
	CAUSE_INVALID_HASH,
	CAUSE_INVALID_CALC_CERT_HASH,
	CAUSE_INVALID_UPDATE_LABEL,
	CAUSE_INVALID_SIGNATURE,
	CAUSE_UKNOWN_FIVE_DATA,
	CAUSE_PTRACE,
	CAUSE_VMRW,
	CAUSE_EXEC,
	CAUSE_TAMPERED,
	CAUSE_MAX,
};

struct task_integrity {
	enum task_integrity_value user_value;
	enum task_integrity_value value;
	atomic_t usage_count;
	spinlock_t value_lock;
	spinlock_t list_lock;
	struct integrity_label *label;
	struct processing_event_list events;
	enum task_integrity_reset_cause reset_cause;
	struct file *reset_file;
};

#ifdef CONFIG_FIVE

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
#define TASK_INTEGRITY(task) \
	((struct task_integrity *)((task)->android_oem_data1[2]))

static inline void task_integrity_assign(struct task_struct *task,
					 struct task_integrity *tint)
{
	task->android_oem_data1[2] = (u64)tint;
}
#else
#define TASK_INTEGRITY(task) \
	((struct task_integrity *)((task)->android_vendor_data1[2]))

static inline void task_integrity_assign(struct task_struct *task,
					 struct task_integrity *tint)
{
	task->android_vendor_data1[2] = (u64)tint;
}
#endif

extern void task_integrity_set_reset_reason(struct task_integrity *tint,
	enum task_integrity_reset_cause cause, struct file *file);

struct task_integrity *task_integrity_alloc(void);
void task_integrity_free(struct task_integrity *tint);
void task_integrity_clear(struct task_integrity *tint);

static inline void task_integrity_get(struct task_integrity *tint)
{
	BUG_ON(!atomic_read(&tint->usage_count));
	atomic_inc(&tint->usage_count);
}

static inline void task_integrity_put(struct task_integrity *tint)
{
	BUG_ON(!atomic_read(&tint->usage_count));
	if (atomic_dec_and_test(&tint->usage_count))
		task_integrity_free(tint);
}

static inline void __task_integrity_set(struct task_integrity *tint,
					enum task_integrity_value value)
{
	tint->value = value;
}

static inline void task_integrity_set(struct task_integrity *tint,
					enum task_integrity_value value)
{
	spin_lock(&tint->value_lock);
	tint->value = value;
	spin_unlock(&tint->value_lock);
}

static inline void task_integrity_reset(struct task_integrity *tint)
{
	task_integrity_set(tint, INTEGRITY_NONE);
	// If cause is already set, this function will be skipped
	task_integrity_set_reset_reason(tint, CAUSE_UNKNOWN, NULL);
}

extern void task_integrity_delayed_reset(struct task_struct *task,
		enum task_integrity_reset_cause cause, struct file *file);

static inline enum task_integrity_value task_integrity_read(
						struct task_integrity *tint)
{
	enum task_integrity_value value;

	spin_lock(&tint->value_lock);
	value = tint->value;
	spin_unlock(&tint->value_lock);

	return value;
}

static inline bool task_integrity_value_allow_sign(
					enum task_integrity_value value)
{
	if (value == INTEGRITY_PRELOAD_ALLOW_SIGN
			|| value == INTEGRITY_MIXED_ALLOW_SIGN
			|| value == INTEGRITY_DMVERITY_ALLOW_SIGN) {
		return true;
	}

	return false;
}

/**
 * task_integrity_allow_sign - check whether application is allowed to sign
 * @tint: pointer to the corresponding integrity struct (Should not be NULL)
 *
 * On success return true.
 */
static inline bool task_integrity_allow_sign(struct task_integrity *tint)
{
	enum task_integrity_value value = task_integrity_read(tint);

	return task_integrity_value_allow_sign(value);
}

static inline enum task_integrity_value task_integrity_user_read(
						struct task_integrity *tint)
{
	return tint->user_value;
}

static inline void task_integrity_user_set(struct task_integrity *tint,
					   enum task_integrity_value value)
{
	tint->user_value = value;
}

static inline void task_integrity_reset_both(struct task_integrity *tint)
{
	task_integrity_reset(tint);
	tint->user_value = INTEGRITY_NONE;
}

extern int task_integrity_copy(struct task_integrity *from,
				struct task_integrity *to);
extern int five_bprm_check(struct linux_binprm *bprm);
extern void five_file_free(struct file *file);
extern int five_file_mmap(struct file *file, unsigned long prot);
extern int five_file_open(struct file *file);
extern int five_file_verify(struct task_struct *task, struct file *file);
extern void five_task_free(struct task_struct *task);

extern void five_inode_post_setattr(struct task_struct *tsk,
					struct dentry *dentry);
extern int five_inode_setxattr(struct dentry *dentry, const char *xattr_name,
			const void *xattr_value, size_t xattr_value_len);
extern int five_inode_removexattr(struct dentry *dentry,
					const char *xattr_name);
extern int five_fcntl_sign(struct file *file,
				struct integrity_label __user *label);
extern int five_fcntl_verify_async(struct file *file);
extern int five_fcntl_verify_sync(struct file *file);
extern int five_fcntl_edit(struct file *file);
extern int five_fcntl_close(struct file *file);
extern int five_fcntl_debug(struct file *file, void __user *arg);
extern int five_fork(struct task_struct *task, struct task_struct *child_task);
extern int five_ptrace(struct task_struct *task, long request);
extern int five_process_vm_rw(struct task_struct *task, int write);
extern char const * const tint_reset_cause_to_string(
	enum task_integrity_reset_cause cause);
#else
#define TASK_INTEGRITY(task) (NULL)

static inline void task_integrity_assign(struct task_struct *task,
					 struct task_integrity *tint)
{
}

static inline struct task_integrity *task_integrity_alloc(void)
{
	return NULL;
}

static inline void task_integrity_free(struct task_integrity *tint)
{
}

static inline void task_integrity_clear(struct task_integrity *tint)
{
}

static inline void task_integrity_set(struct task_integrity *tint,
						enum task_integrity_value value)
{
}

static inline void task_integrity_reset(struct task_integrity *tint)
{
}

static inline enum task_integrity_value task_integrity_read(
						struct task_integrity *tint)
{
	return INTEGRITY_NONE;
}

static inline void task_integrity_user_set(struct task_integrity *tint,
						enum task_integrity_value value)
{
}

static inline enum task_integrity_value task_integrity_user_read(
						struct task_integrity *tint)
{
	return INTEGRITY_NONE;
}

static inline void task_integrity_delayed_reset(struct task_struct *task,
		enum task_integrity_reset_cause cause, struct file *file)
{
}

static inline void task_integrity_reset_both(struct task_integrity *tint)
{
}

static inline void task_integrity_add_file(struct task_integrity *tint)
{
}

static inline void task_integrity_report_file(struct task_integrity *tint)
{
}

static inline int five_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

static inline void five_file_free(struct file *file)
{
}

static inline int five_file_mmap(struct file *file, unsigned long prot)
{
	return 0;
}

static inline int five_file_open(struct file *file)
{
	return 0;
}

static inline int five_file_verify(struct task_struct *task, struct file *file)
{
	return 0;
}

static inline void five_task_free(struct task_struct *task)
{
}

static inline void five_inode_post_setattr(struct task_struct *tsk,
							struct dentry *dentry)
{
}

static inline int five_inode_setxattr(struct dentry *dentry,
					const char *xattr_name,
					const void *xattr_value,
					size_t xattr_value_len)
{
	return 0;
}

static inline int five_inode_removexattr(struct dentry *dentry,
					const char *xattr_name)
{
	return 0;
}

static inline int five_fcntl_sign(struct file *file,
					struct integrity_label __user *label)
{
	return 0;
}

static inline int five_fcntl_verify_async(struct file *file)
{
	return 0;
}

static inline int five_fcntl_verify_sync(struct file *file)
{
	return 0;
}

static inline int five_fcntl_edit(struct file *file)
{
	return 0;
}

static inline int five_fcntl_close(struct file *file)
{
	return 0;
}

static inline int five_fcntl_debug(struct file *file, void __user *arg)
{
	return 0;
}

static inline int five_fork(struct task_struct *task,
				struct task_struct *child_task)
{
	return 0;
}

static inline int five_ptrace(struct task_struct *task, long request)
{
	return 0;
}

static inline int five_process_vm_rw(struct task_struct *task, int write)
{
	return 0;
}

static inline int task_integrity_copy(struct task_integrity *from,
				struct task_integrity *to)
{
	return 0;
}

static inline char const * const tint_reset_cause_to_string(
	enum task_integrity_reset_cause cause)
{
	return NULL;
}

static inline void task_integrity_set_reset_reason(struct task_integrity *tint,
	enum task_integrity_reset_cause cause, struct file *file)
{
}
#endif

#endif /* _LINUX_TASK_INTEGRITY_H */
