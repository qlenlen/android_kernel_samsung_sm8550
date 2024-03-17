/*
 * This code is based on IMA's code
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

#include <linux/module.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <crypto/hash_info.h>
#include <linux/ptrace.h>
#include <linux/task_integrity.h>
#include <linux/reboot.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/shmem_fs.h>
#include <linux/version.h>

#include "five.h"
#include "five_audit.h"
#include "five_hooks.h"
#include "five_state.h"
#include "five_pa.h"
#include "five_porting.h"
#include "five_cache.h"
#include "five_dmverity.h"
#include "five_dsms.h"
#include "five_testing.h"

/* crash_dump in Android 12 uses this request even if Kernel doesn't
 * support it */
#ifndef PTRACE_PEEKMTETAGS
#define PTRACE_PEEKMTETAGS 33
#endif

static const bool check_dex2oat_binary = true;
static const bool check_memfd_file = true;

static struct file *memfd_file __ro_after_init;

static struct workqueue_struct *g_five_workqueue;

static inline void task_integrity_processing(struct task_integrity *tint);
static inline void task_integrity_done(struct task_integrity *tint);
static void process_measurement(const struct processing_event_list *params);
static inline struct processing_event_list *five_event_create(
		enum five_event event, struct task_struct *task,
		struct file *file, int function, gfp_t flags);
static inline void five_event_destroy(
		const struct processing_event_list *file);

#ifdef CONFIG_FIVE_DEBUG
static int five_enabled = 1;

static ssize_t five_enabled_write(struct file *file, const char __user *buf,
				size_t count, loff_t *pos)
{
	char command;

	if (get_user(command, buf))
		return -EFAULT;

	switch (command) {
	case '0':
		five_enabled = 0;
		break;
	case '1':
		five_enabled = 1;
		break;
	default:
		pr_err("FIVE: %s: unknown cmd: %hhx\n", __func__, command);
		return -EINVAL;
	}

	pr_info("FIVE debug: FIVE %s\n", five_enabled ? "enabled" : "disabled");
	return count;
}

static ssize_t five_enabled_read(struct file *file, char __user *user_buf,
				size_t count, loff_t *pos)
{
	char buf[2];

	buf[0] = five_enabled ? '1' : '0';
	buf[1] = '\n';

	return simple_read_from_buffer(user_buf, count, pos, buf, sizeof(buf));
}

static const struct file_operations five_enabled_fops = {
	.owner = THIS_MODULE,
	.read  = five_enabled_read,
	.write = five_enabled_write
};

static int __init init_fs(void)
{
	struct dentry *debug_file = NULL;
	umode_t umode = (S_IRUGO | S_IWUSR | S_IWGRP);

	debug_file = debugfs_create_file(
		"five_enabled", umode, NULL, NULL, &five_enabled_fops);
	if (IS_ERR_OR_NULL(debug_file))
		goto error;

	return 0;
error:
	if (debug_file)
		return -PTR_ERR(debug_file);

	return -EEXIST;
}

static inline int is_five_enabled(void)
{
	return five_enabled;
}

int five_fcntl_debug(struct file *file, void __user *argp)
{
	struct inode *inode;
	struct five_stat stat = {0};
	struct integrity_iint_cache *iint;

	if (unlikely(!file || !argp))
		return -EINVAL;

	inode = file_inode(file);

	inode_lock(inode);
	iint = integrity_inode_get(inode);
	if (unlikely(!iint)) {
		inode_unlock(inode);
		return -ENOMEM;
	}

	stat.cache_status = five_get_cache_status(iint);
	stat.cache_iversion = inode_query_iversion(iint->inode);
	stat.inode_iversion = inode_query_iversion(inode);

	inode_unlock(inode);

	if (unlikely(copy_to_user(argp, &stat, sizeof(stat))))
		return -EFAULT;

	return 0;
}
#else
static int __init init_fs(void)
{
	return 0;
}

static inline int is_five_enabled(void)
{
	return 1;
}
#endif

static void work_handler(struct work_struct *in_data)
{
	struct worker_context *context = container_of(in_data,
			struct worker_context, data_work);
	struct task_integrity *intg;

	if (unlikely(!context))
		return;

	intg = context->tint;

	spin_lock(&intg->list_lock);
	while (!list_empty(&(intg->events.list))) {
		struct processing_event_list *five_file;

		five_file = list_entry(intg->events.list.next,
				struct processing_event_list, list);
		spin_unlock(&intg->list_lock);
		switch (five_file->event) {
		case FIVE_VERIFY_BUNCH_FILES: {
			process_measurement(five_file);
			break;
		}
		case FIVE_RESET_INTEGRITY: {
			task_integrity_reset(intg);
			five_hook_integrity_reset(five_file->task,
						  NULL, CAUSE_UNKNOWN);
			break;
		}
		default:
			break;
		}
		spin_lock(&intg->list_lock);
		list_del(&five_file->list);
		five_event_destroy(five_file);
	}

	task_integrity_done(intg);
	spin_unlock(&intg->list_lock);
	task_integrity_put(intg);

	kfree(context);
}

__mockable
const char *five_d_path(const struct path *path, char **pathbuf, char *namebuf)
{
	char *pathname = NULL;

	*pathbuf = __getname();
	if (*pathbuf) {
		pathname = d_absolute_path(path, *pathbuf, PATH_MAX);
		if (IS_ERR(pathname)) {
			__putname(*pathbuf);
			*pathbuf = NULL;
			pathname = NULL;
		}
	}

	if (!pathname) {
		strlcpy(namebuf, path->dentry->d_name.name, NAME_MAX);
		pathname = namebuf;
	}

	return pathname;
}

int five_check_params(struct task_struct *task, struct file *file)
{
	struct inode *inode;

	if (unlikely(!file))
		return 1;

	inode = file_inode(file);
	if (!S_ISREG(inode->i_mode))
		return 1;

	return 0;
}

/* cut a list into two
 * @cur_list: a list with entries
 * @new_list: a new list to add all removed entries. Should be an empty list
 *
 * Use it under spin_lock
 *
 * The function moves second entry and following entries to new list.
 * First entry is left in cur_list.
 *
 * Initial state:
 * [cur_list]<=>[first]<=>[second]<=>[third]<=>...<=>[last]    [new_list]
 *    ^=================================================^        ^====^
 * Result:
 * [cur_list]<=>[first]
 *      ^==========^
 * [new_list]<=>[second]<=>[third]<=>...<=>[last]
 *     ^=====================================^
 *
 * the function is similar to kernel list_cut_position, but there are few
 * differences:
 * - cut position is second entry
 * - original list is left with only first entry
 * - moving entries are from second entry to last entry
 */
static void list_cut_tail(struct list_head *cur_list,
		struct list_head *new_list)
{
	if ((!list_empty(cur_list)) &&
			(!list_is_singular(cur_list))) {
		new_list->next = cur_list->next->next;
		cur_list->next->next->prev = new_list;
		cur_list->next->next = cur_list;
		new_list->prev = cur_list->prev;
		cur_list->prev->next = new_list;
		cur_list->prev = cur_list->next;
	}
}

static void free_files_list(struct list_head *list)
{
	struct list_head *tmp, *list_entry;
	struct processing_event_list *file_entry;

	list_for_each_safe(list_entry, tmp, list) {
		file_entry = list_entry(list_entry,
				struct processing_event_list, list);
		list_del(&file_entry->list);
		five_event_destroy(file_entry);
	}
}

static int push_file_event_bunch(struct task_struct *task, struct file *file,
		int function)
{
	int rc = 0;
	struct worker_context *context;
	struct processing_event_list *five_file;

	if (unlikely(!is_five_enabled()) || five_check_params(task, file))
		return 0;

	context = kmalloc(sizeof(struct worker_context), GFP_KERNEL);
	if (unlikely(!context))
		return -ENOMEM;

	five_file = five_event_create(FIVE_VERIFY_BUNCH_FILES, task, file,
			function, GFP_KERNEL);
	if (unlikely(!five_file)) {
		kfree(context);
		return -ENOMEM;
	}

	spin_lock(&TASK_INTEGRITY(task)->list_lock);

	if (list_empty(&(TASK_INTEGRITY(task)->events.list))) {
		task_integrity_get(TASK_INTEGRITY(task));
		task_integrity_processing(TASK_INTEGRITY(task));

		context->tint = TASK_INTEGRITY(task);

		list_add_tail(&five_file->list,
			      &TASK_INTEGRITY(task)->events.list);
		spin_unlock(&TASK_INTEGRITY(task)->list_lock);
		INIT_WORK(&context->data_work, work_handler);
		rc = queue_work(g_five_workqueue, &context->data_work) ? 0 : 1;
	} else {
		struct list_head dead_list;

		INIT_LIST_HEAD(&dead_list);
		if ((function == BPRM_CHECK) &&
		    (!list_is_singular(&(TASK_INTEGRITY(task)->events.list)))) {
			list_cut_tail(&TASK_INTEGRITY(task)->events.list,
					&dead_list);
		}
		list_add_tail(&five_file->list,
			      &TASK_INTEGRITY(task)->events.list);
		spin_unlock(&TASK_INTEGRITY(task)->list_lock);
		free_files_list(&dead_list);
		kfree(context);
	}
	return rc;
}

static int push_reset_event(struct task_struct *task,
		enum task_integrity_reset_cause cause, struct file *file)
{
	struct list_head dead_list;
	struct task_integrity *current_tint;
	struct processing_event_list *five_reset;

	if (unlikely(!is_five_enabled()))
		return 0;

	INIT_LIST_HEAD(&dead_list);
	current_tint = TASK_INTEGRITY(task);
	task_integrity_get(current_tint);

	task_integrity_set_reset_reason(current_tint, cause, file);

	five_reset = five_event_create(FIVE_RESET_INTEGRITY, task, NULL, 0,
		GFP_KERNEL);
	if (unlikely(!five_reset)) {
		task_integrity_reset_both(current_tint);
		five_hook_integrity_reset(task, file, cause);
		task_integrity_put(current_tint);
		return -ENOMEM;
	}

	task_integrity_reset_both(current_tint);
	five_hook_integrity_reset(task, file, cause);
	spin_lock(&current_tint->list_lock);
	if (!list_empty(&current_tint->events.list)) {
		list_cut_tail(&current_tint->events.list, &dead_list);
		five_reset->event = FIVE_RESET_INTEGRITY;
		list_add_tail(&five_reset->list, &current_tint->events.list);
		spin_unlock(&current_tint->list_lock);
	} else {
		spin_unlock(&current_tint->list_lock);
		five_event_destroy(five_reset);
	}

	task_integrity_put(current_tint);
	/* remove dead_list */
	free_files_list(&dead_list);
	return 0;
}

void task_integrity_delayed_reset(struct task_struct *task,
		enum task_integrity_reset_cause cause, struct file *file)
{
	push_reset_event(task, cause, file);
}

static void five_check_last_writer(struct integrity_iint_cache *iint,
				  struct inode *inode, struct file *file)
{
	fmode_t mode = file->f_mode;

	if (!(mode & FMODE_WRITE))
		return;

	inode_lock(inode);
	if (atomic_read(&inode->i_writecount) == 1) {
		if (!inode_eq_iversion(inode, iint->version))
			five_set_cache_status(iint, FIVE_FILE_UNKNOWN);
	}
	iint->five_signing = false;
	inode_unlock(inode);
}

/**
 * five_file_free - called on __fput()
 * @file: pointer to file structure being freed
 *
 * Flag files that changed, based on i_version
 */
void five_file_free(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct integrity_iint_cache *iint;

	if (!S_ISREG(inode->i_mode))
		return;

	fivepa_fsignature_free(file);

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	five_check_last_writer(iint, inode, file);
}

void five_task_free(struct task_struct *task)
{
	task_integrity_put(TASK_INTEGRITY(task));
}

/* Returns string representation of input function */
const char *five_get_string_fn(enum five_hooks fn)
{
	switch (fn) {
	case FILE_CHECK:
		return "file-check";
	case MMAP_CHECK:
		return "mmap-check";
	case BPRM_CHECK:
		return "bprm-check";
	case POST_SETATTR:
		return "post-setattr";
	}
	return "unknown-function";
}

static inline bool is_dex2oat_binary(const struct file *file)
{
	const char *pathname = NULL;
	char *pathbuf = NULL;
	const char * const dex2oat_full_path[] = {
		/* R OS */
		"/apex/com.android.art/bin/dex2oat",
		"/apex/com.android.art/bin/dex2oat32",
		"/apex/com.android.art/bin/dex2oat64",
		/* Q OS */
		"/apex/com.android.runtime/bin/dex2oat"
	};
	char filename[NAME_MAX];
	bool res = false;
	size_t i;

	if (!file || !file->f_path.dentry)
		return false;

	if (strncmp(file->f_path.dentry->d_iname, "dex2oat",
			sizeof("dex2oat")) &&
	    strncmp(file->f_path.dentry->d_iname, "dex2oat32",
			sizeof("dex2oat32")) &&
	    strncmp(file->f_path.dentry->d_iname, "dex2oat64",
			sizeof("dex2oat64")))
		return false;

	pathname = five_d_path(&file->f_path, &pathbuf, filename);

	for (i = 0; i < ARRAY_SIZE(dex2oat_full_path); ++i) {
		if (!strncmp(pathname, dex2oat_full_path[i],
					strlen(dex2oat_full_path[i]) + 1)) {
			res = true;
			break;
		}
	}

	if (pathbuf)
		__putname(pathbuf);

	return res;
}

static inline bool match_trusted_executable(const struct five_cert *cert,
				const struct integrity_iint_cache *iint,
				const struct file *file)
{
	const struct five_cert_header *hdr = NULL;

	if (!cert)
		return check_dex2oat_binary && is_dex2oat_binary(file);

	if (five_get_cache_status(iint) != FIVE_FILE_RSA)
		return false;

	hdr = (const struct five_cert_header *)cert->body.header->value;

	if (hdr->privilege == FIVE_PRIV_ALLOW_SIGN)
		return true;

	return false;
}

static inline void task_integrity_processing(struct task_integrity *tint)
{
	tint->user_value = INTEGRITY_PROCESSING;
}

static inline void task_integrity_done(struct task_integrity *tint)
{
	tint->user_value = task_integrity_read(tint);
}

static void process_file(struct task_struct *task,
			struct file *file,
			int function,
			struct file_verification_result *result)
{
	struct inode *inode = d_real_inode(file_dentry(file));
	struct integrity_iint_cache *iint = NULL;
	struct five_cert cert = { {0} };
	struct five_cert *pcert = NULL;
	int rc = -ENOMEM;
	char *xattr_value = NULL;
	int xattr_len = 0;

	if (!S_ISREG(inode->i_mode)) {
		rc = 0;
		goto out;
	}

	iint = integrity_inode_get(inode);
	if (!iint)
		goto out;

	/* Nothing to do, just return existing appraised status */
	if (five_get_cache_status(iint) != FIVE_FILE_UNKNOWN) {
		rc = 0;
		goto out;
	}

	xattr_len = five_read_xattr(d_real_comp(file->f_path.dentry),
			&xattr_value);
	if (xattr_value) {
		if (xattr_len) {
			rc = five_cert_fillout(&cert, xattr_value, xattr_len);
			if (rc) {
				pr_err("FIVE: certificate is incorrect inode=%lu\n",
								inode->i_ino);
				goto out;
			}

			pcert = &cert;

			if (file->f_flags & O_DIRECT) {
				rc = -EACCES;
				goto out;
			}
		} else {
			five_audit_info(task, file, "zero length", 0, 0,
						"Found a dummy-cert", rc);
		}
	}

	rc = five_appraise_measurement(task, function, iint, file, pcert);
	if (!rc && match_trusted_executable(pcert, iint, file))
		iint->five_flags |= FIVE_TRUSTED_FILE;

out:
	if (rc && iint)
		iint->five_flags &= ~FIVE_TRUSTED_FILE;

	result->file = file;
	result->task = task;
	result->iint = iint;
	result->fn = function;
	result->xattr = xattr_value;
	result->xattr_len = (size_t)xattr_len;

	if (!iint || five_get_cache_status(iint) == FIVE_FILE_UNKNOWN
			|| five_get_cache_status(iint) == FIVE_FILE_FAIL)
		result->five_result = 1;
	else
		result->five_result = 0;
}

static void process_measurement(const struct processing_event_list *params)
{
	struct task_struct *task = params->task;
	struct task_integrity *integrity = TASK_INTEGRITY(task);
	struct file *file = params->file;
	struct inode *inode = file_inode(file);
	int function = params->function;
	struct file_verification_result file_result;

	if (function != BPRM_CHECK) {
		if (task_integrity_read(integrity) == INTEGRITY_NONE)
			return;
	}

	file_verification_result_init(&file_result);
	inode_lock(inode);

	process_file(task, file, function, &file_result);

	five_hook_file_processed(task, file,
		file_result.xattr, file_result.xattr_len,
		file_result.five_result);

	five_state_proceed(integrity, &file_result);

	inode_unlock(inode);
	file_verification_result_deinit(&file_result);
}

#define MFD_NAME_PREFIX "memfd:"
#define MFD_NAME_PREFIX_LEN (sizeof(MFD_NAME_PREFIX) - 1)

static bool is_memfd_file(struct file *file)
{
	struct inode *inode;
	struct inode *memfd_inode;

	if (!file)
		return false;

	memfd_inode = file_inode(memfd_file);
	inode = file_inode(file);
	if (inode && memfd_inode && inode->i_sb == memfd_inode->i_sb)
		if (file->f_path.dentry &&
			!strncmp(file->f_path.dentry->d_iname, MFD_NAME_PREFIX,
							MFD_NAME_PREFIX_LEN))
			return true;

	return false;
}

/**
 * five_file_mmap - measure files being mapped executable based on
 * the process_measurement() policy decision.
 * @file: pointer to the file to be measured (May be NULL)
 * @prot: contains the protection that will be applied by the kernel.
 *
 * On success return 0.
 */
int five_file_mmap(struct file *file, unsigned long prot)
{
	int rc = 0;
	struct task_struct *task = current;
	struct task_integrity *tint = TASK_INTEGRITY(task);

	if (five_check_params(task, file))
		return 0;

	if (check_memfd_file && is_memfd_file(file))
		return 0;

	if (file && task_integrity_user_read(tint)) {
		if (prot & PROT_EXEC) {
			rc = push_file_event_bunch(task, file, MMAP_CHECK);
			if (rc)
				return rc;
		} else {
			five_hook_file_skipped(task, file);
		}
	}

	return rc;
}

/**
 * five_bprm_check - Measure executable being launched based on
 * the process_measurement() policy decision.
 * @bprm: contains the linux_binprm structure
 *
 * Notes:
 * bprm_check could be called few times for one process when few binary loaders
 * are used. Example: execution of shell script.
 * In this case we should process first file (e.g. shell script) as main and
 * use BPRM_CHECK. The second file (interpetator ) will be processed as general
 * mapping (MMAP_CHECK).
 * To implement this option variable bprm->recursion_depth is used.
 *
 * On success return 0.
 */
int __five_bprm_check(struct linux_binprm *bprm, int depth)
{
	int rc = 0;
	struct task_struct *task = current;
	struct task_integrity *old_tint = TASK_INTEGRITY(task);

	if (unlikely(task->ptrace))
		return rc;

	if (depth > 0) {
		rc = push_file_event_bunch(task, bprm->file, MMAP_CHECK);
	} else {
		struct task_integrity *tint = task_integrity_alloc();

		task_integrity_assign(task, tint);
		if (likely(TASK_INTEGRITY(task))) {
			rc = push_file_event_bunch(task,
							bprm->file, BPRM_CHECK);
		} else {
			rc = -ENOMEM;
		}
		task_integrity_put(old_tint);
	}

	return rc;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
int five_bprm_check(struct linux_binprm *bprm, int depth)
{
	return __five_bprm_check(bprm, depth);
}
#else
int five_bprm_check(struct linux_binprm *bprm)
{
	return __five_bprm_check(bprm, bprm->recursion_depth);
}
#endif

/**
 * This function handles two situations:
 * 1. Device had been rebooted before five_sign finished.
 *    Then xattr_len will be zero and iint->five_signing will be false.
 * 2. The file is being signing when another process tries to open it.
 *    Then xattr_len will be zero and iint->five_signing will be true.
 *
 * - five_fcntl_edit stores the xattr with zero length and set
 *   iint->five_signing to true
 * - five_fcntl_sign stores correct certificates and set
 *   iint->five_signing to false
 *
 * On success returns 0
 */
int five_file_open(struct file *file)
{
	ssize_t xattr_len;
	struct inode *inode = file_inode(file);

	if (!S_ISREG(inode->i_mode))
		return 0;

	xattr_len = vfs_getxattr(file->f_path.dentry, XATTR_NAME_FIVE,
					NULL, 0);
	if (xattr_len == 0) {
		five_audit_verbose(current, file, "dummy-cert", 0, 0,
					"Found a dummy-cert", 0);
	}

	return 0;
}

/**
 * five_file_verify - force five integrity measurements for file
 * the process_measurement() policy decision. This check affects
 * task integrity.
 * @file: pointer to the file to be measured (May be NULL)
 *
 * On success return 0.
 */
int five_file_verify(struct task_struct *task, struct file *file)
{
	int rc = 0;
	struct task_integrity *tint = TASK_INTEGRITY(task);

	if (file && task_integrity_user_read(tint))
		rc = push_file_event_bunch(task, file, FILE_CHECK);

	return rc;
}

static struct notifier_block five_reboot_nb = {
	.notifier_call = five_reboot_notifier,
	.priority = INT_MAX,
};

int five_hash_algo __ro_after_init = HASH_ALGO_SHA1;

static int __init hash_setup(const char *str)
{
	int i;

	for (i = 0; i < HASH_ALGO__LAST; i++) {
		if (strcmp(str, hash_algo_name[i]) == 0) {
			five_hash_algo = i;
			break;
		}
	}

	return 1;
}

int __init init_five(void)
{
	int error;

	g_five_workqueue = alloc_workqueue("%s", WQ_FREEZABLE | WQ_MEM_RECLAIM,
						0, "five_wq");
	if (!g_five_workqueue)
		return -ENOMEM;

	hash_setup(CONFIG_FIVE_DEFAULT_HASH);
	error = five_init();
	if (error)
		return error;

	error = five_hook_wq_init();
	if (error)
		return error;

	error = register_reboot_notifier(&five_reboot_nb);
	if (error)
		return error;

/**
 * This empty file is needed in is_memfd_file() function.
 * The only way to check whether the file was created using memfd_create()
 * syscall is to compare its superblock address with address of another memfd
 * file.
 */
	memfd_file = shmem_kernel_file_setup(
				"five_memfd_check", 0, VM_NORESERVE);
	if (IS_ERR(memfd_file)) {
		error = PTR_ERR(memfd_file);
		memfd_file = NULL;
		return error;
	}

	error = init_fs();
	if (error)
		return error;

	five_dsms_init("1", 0);

	error = five_init_dmverity();

	return error;
}

static int fcntl_verify(struct file *file)
{
	int rc = 0;
	struct task_struct *task = current;
	struct task_integrity *tint = TASK_INTEGRITY(task);

	if (task_integrity_user_read(tint))
		rc = push_file_event_bunch(task, file, FILE_CHECK);
	return rc;
}

/* Called from do_fcntl */
int five_fcntl_verify_async(struct file *file)
{
	return fcntl_verify(file);
}

/* Called from do_fcntl */
int five_fcntl_verify_sync(struct file *file)
{
	return -EINVAL;
}

int five_fork(struct task_struct *task, struct task_struct *child_task)
{
	int rc = 0;

	spin_lock(&TASK_INTEGRITY(task)->list_lock);

	if (!list_empty(&TASK_INTEGRITY(task)->events.list)) {
		/*copy the list*/
		struct list_head *tmp;
		struct processing_event_list *from_entry;
		struct worker_context *context;

		context = kmalloc(sizeof(struct worker_context), GFP_ATOMIC);
		if (unlikely(!context)) {
			spin_unlock(&TASK_INTEGRITY(task)->list_lock);
			return -ENOMEM;
		}

		list_for_each(tmp, &TASK_INTEGRITY(task)->events.list) {
			struct processing_event_list *five_file;

			from_entry = list_entry(tmp,
					struct processing_event_list, list);

			five_file = five_event_create(
					from_entry->event,
					child_task,
					from_entry->file,
					from_entry->function,
					GFP_ATOMIC);
			if (unlikely(!five_file)) {
				kfree(context);
				spin_unlock(&TASK_INTEGRITY(task)->list_lock);
				return -ENOMEM;
			}

			list_add_tail(&five_file->list,
				      &TASK_INTEGRITY(child_task)->events.list);
		}

		context->tint = TASK_INTEGRITY(child_task);

		rc = task_integrity_copy(TASK_INTEGRITY(task),
				TASK_INTEGRITY(child_task));
		spin_unlock(&TASK_INTEGRITY(task)->list_lock);
		task_integrity_get(context->tint);
		task_integrity_processing(TASK_INTEGRITY(child_task));
		INIT_WORK(&context->data_work, work_handler);
		rc = queue_work(g_five_workqueue, &context->data_work) ? 0 : 1;
	} else {
		rc = task_integrity_copy(TASK_INTEGRITY(task),
				TASK_INTEGRITY(child_task));
		spin_unlock(&TASK_INTEGRITY(task)->list_lock);
	}

	if (!rc)
		five_hook_task_forked(task, child_task);

	return rc;
}

int five_ptrace(struct task_struct *task, long request)
{
	switch (request) {
	case PTRACE_TRACEME:
	case PTRACE_ATTACH:
	case PTRACE_SEIZE:
	case PTRACE_INTERRUPT:
	case PTRACE_CONT:
	case PTRACE_DETACH:
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
	case PTRACE_PEEKUSR:
	case PTRACE_GETREGSET:
	case PTRACE_GETSIGINFO:
	case PTRACE_PEEKSIGINFO:
	case PTRACE_GETSIGMASK:
	case PTRACE_GETEVENTMSG:
	case PTRACE_PEEKMTETAGS:
#if defined(CONFIG_ARM64) || defined(KUNIT_UML)
	case COMPAT_PTRACE_GETREGS:
	case COMPAT_PTRACE_GET_THREAD_AREA:
	case COMPAT_PTRACE_GETVFPREGS:
	case COMPAT_PTRACE_GETHBPREGS:
#else
	case PTRACE_GETREGS:
	case PTRACE_GET_THREAD_AREA:
	case PTRACE_GETVFPREGS:
	case PTRACE_GETHBPREGS:
#endif
		break;
	default: {
		struct task_integrity *tint = TASK_INTEGRITY(task);

		if (task_integrity_user_read(tint) == INTEGRITY_NONE)
			break;

		task_integrity_delayed_reset(task, CAUSE_PTRACE, NULL);
		five_audit_err(task, NULL, "ptrace", task_integrity_read(tint),
				INTEGRITY_NONE, "reset-integrity", 0);
		break;
	}
	}

	return 0;
}

int five_process_vm_rw(struct task_struct *task, int write)
{
	if (write) {
		struct task_integrity *tint = TASK_INTEGRITY(task);

		if (task_integrity_user_read(tint) == INTEGRITY_NONE)
			goto exit;

		task_integrity_delayed_reset(task, CAUSE_VMRW, NULL);
		five_audit_err(task, NULL, "process_vm_rw",
				task_integrity_read(tint), INTEGRITY_NONE,
							"reset-integrity", 0);
	}

exit:
	return 0;
}

static inline struct processing_event_list *five_event_create(
		enum five_event event, struct task_struct *task,
		struct file *file, int function, gfp_t flags)
{
	struct processing_event_list *five_file;

	five_file = kzalloc(sizeof(struct processing_event_list), flags);
	if (unlikely(!five_file))
		return NULL;

	five_file->event = event;

	switch (five_file->event) {
	case FIVE_VERIFY_BUNCH_FILES: {
		get_task_struct(task);
		get_file(file);
		five_file->task = task;
		five_file->file = file;
		five_file->function = function;
		break;
	}
	case FIVE_RESET_INTEGRITY: {
		get_task_struct(task);
		five_file->task = task;
		break;
	}
	default:
		break;
	}

	return five_file;
}

static inline void five_event_destroy(
		const struct processing_event_list *file)
{
	switch (file->event) {
	case FIVE_VERIFY_BUNCH_FILES: {
		fput(file->file);
		put_task_struct(file->task);
		break;
	}
	case FIVE_RESET_INTEGRITY: {
		put_task_struct(file->task);
		break;
	}
	default:
		break;
	}
	kfree(file);
}

late_initcall(init_five);

MODULE_DESCRIPTION("File-based process Integrity Verifier");
MODULE_LICENSE("GPL");
