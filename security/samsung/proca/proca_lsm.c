/*
 * PROCA LSM module
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

#include <linux/module.h>
#include <linux/file.h>
#include <linux/task_integrity.h>
#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/proca.h>

#include "proca_identity.h"
#include "proca_certificate.h"
#include "proca_task_descr.h"
#include "proca_table.h"
#include "proca_log.h"
#include "proca_config.h"
#include "proca_porting.h"

#define XATTR_FIVE_SUFFIX "five"
#define XATTR_NAME_FIVE (XATTR_SECURITY_PREFIX XATTR_FIVE_SUFFIX)

#define XATTR_PA_SUFFIX "pa"
#define XATTR_NAME_PA (XATTR_USER_PREFIX XATTR_PA_SUFFIX)

#include "five_hooks.h"

#ifdef CONFIG_PROCA_GKI_10
#define F_SIGNATURE(file) ((void *)((file)->android_vendor_data1))

static inline void f_signature_assign(struct file *file, void *f_signature)
{
	file->android_vendor_data1 = (u64)f_signature;
}
#else
#define F_SIGNATURE(file) ((file)->f_signature)

static inline void f_signature_assign(struct file *file, void *f_signature)
{
	file->f_signature = f_signature;
}
#endif

static void proca_task_free_hook(struct task_struct *task);

static void proca_file_free_security_hook(struct file *file);

#ifdef LINUX_LSM_SUPPORTED
static struct security_hook_list proca_ops[] = {
	LSM_HOOK_INIT(task_free, proca_task_free_hook),
	LSM_HOOK_INIT(file_free_security, proca_file_free_security_hook),
};
#endif

static void proca_hook_task_forked(struct task_struct *parent,
				enum task_integrity_value parent_tint_value,
				struct task_struct *child,
				enum task_integrity_value child_tint_value);

static void proca_hook_file_processed(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file, void *xattr,
				size_t xattr_size, int result);

static void proca_hook_file_signed(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file, void *xattr,
				size_t xattr_size, int result);

static void proca_hook_file_skipped(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file);

static struct five_hook_list five_ops[] = {
	FIVE_HOOK_INIT(task_forked, proca_hook_task_forked),
	FIVE_HOOK_INIT(file_processed, proca_hook_file_processed),
	FIVE_HOOK_INIT(file_signed, proca_hook_file_signed),
	FIVE_HOOK_INIT(file_skipped, proca_hook_file_skipped),
};

static struct proca_table g_proca_table;
struct proca_config g_proca_config;

static int g_proca_inited;

static int read_xattr(struct dentry *dentry, const char *name,
			char **xattr_value)
{
	ssize_t ret;
	void *buffer = NULL;

	dentry = d_real_comp(dentry);

	*xattr_value = NULL;
	ret = __vfs_getxattr(dentry, dentry->d_inode, name,
				NULL, 0, XATTR_NOSECURITY);
	if (ret <= 0)
		return 0;

	buffer = kmalloc(ret + 1, GFP_NOFS);
	if (!buffer)
		return 0;

	ret = __vfs_getxattr(dentry, dentry->d_inode, name,
				buffer, ret + 1, XATTR_NOSECURITY);

	if (ret <= 0) {
		ret = 0;
		kfree(buffer);
	} else {
		*xattr_value = buffer;
	}

	return ret;
}

static struct proca_task_descr *prepare_unsigned_proca_task_descr(
					struct task_struct *task,
					struct file *file)
{
	struct proca_identity ident;
	struct proca_task_descr *task_descr = NULL;

	if (init_proca_identity(&ident, file, NULL, 0, NULL))
		return task_descr;

	task_descr = create_proca_task_descr(task, &ident);
	if (!task_descr)
		deinit_proca_identity(&ident);

	return task_descr;
}

static struct proca_task_descr *prepare_proca_task_descr(
				struct task_struct *task, struct file *file,
				const enum task_integrity_value tint_value,
				void *xattr, size_t xattr_size,
				char **out_five_xattr_value)
{
	struct proca_certificate parsed_cert;
	struct proca_identity ident;
	char *pa_xattr_value = NULL;
	size_t pa_xattr_size;
	char *five_sign_xattr_value = NULL;
	size_t five_sign_xattr_size;
	struct proca_task_descr *task_descr = NULL;

	pa_xattr_size = read_xattr(file->f_path.dentry,
				XATTR_NAME_PA, &pa_xattr_value);

	if (!pa_xattr_value) {
		if (task_integrity_value_allow_sign(tint_value))
			return prepare_unsigned_proca_task_descr(task, file);
		else
			return NULL;
	}

	if (xattr) {
		five_sign_xattr_value = kmemdup(
					xattr, xattr_size, GFP_KERNEL);
		five_sign_xattr_size = xattr_size;
	} else {
		five_sign_xattr_size = read_xattr(file->f_path.dentry,
					XATTR_NAME_FIVE,
					&five_sign_xattr_value);
	}

	if (!five_sign_xattr_value) {
		PROCA_INFO_LOG(
			"Failed to read five xattr, pid %d, integrity 0x%x\n",
					task->pid, tint_value);
		goto pa_xattr_cleanup;
	}

	if (parse_proca_certificate(pa_xattr_value, pa_xattr_size,
				    &parsed_cert))
		goto five_xattr_cleanup;

	if (!is_certificate_relevant_to_task(&parsed_cert, task))
		goto proca_cert_cleanup;

	PROCA_DEBUG_LOG("%s xattr was found for task %d\n", XATTR_NAME_PA,
			task->pid);

	if (!compare_with_five_signature(&parsed_cert, five_sign_xattr_value,
					 five_sign_xattr_size)) {
		PROCA_INFO_LOG(
			"Comparison with five signature for %s failed.\n",
			parsed_cert.app_name);
		goto proca_cert_cleanup;
	}

	if (init_proca_identity(&ident, file,
			pa_xattr_value, pa_xattr_size,
			&parsed_cert))
		goto proca_cert_cleanup;

	task_descr = create_proca_task_descr(task, &ident);
	if (!task_descr)
		goto proca_identity_cleanup;

	*out_five_xattr_value = five_sign_xattr_value;

	return task_descr;

proca_identity_cleanup:;
	deinit_proca_identity(&ident);

proca_cert_cleanup:;
	deinit_proca_certificate(&parsed_cert);

five_xattr_cleanup:;
	kfree(five_sign_xattr_value);

pa_xattr_cleanup:;
	kfree(pa_xattr_value);

	return NULL;
}

static bool is_bprm(struct task_struct *task, struct file *old_file,
				struct file *new_file)
{
	struct file *exe;
	bool res;

	exe = get_task_exe_file(task);
	if (!exe)
		return false;

	res = locks_inode(exe) == locks_inode(new_file) &&
		locks_inode(old_file) != locks_inode(new_file);

	fput(exe);
	return res;
}

static struct file *get_real_file(struct file *file)
{
	if (locks_inode(file)->i_sb->s_magic == OVERLAYFS_SUPER_MAGIC &&
					file->private_data)
		file = (struct file *)file->private_data;

	return file;
}

static void proca_hook_file_processed(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file, void *xattr,
				size_t xattr_size, int result)
{
	char *five_xattr_value = NULL;
	bool need_set_five = false;
	struct proca_task_descr *target_task_descr = NULL;

	file = get_real_file(file);
	if (!file)
		return;

	if (task->flags & PF_KTHREAD)
		return;

	target_task_descr = proca_table_get_by_task(&g_proca_table, task);
	if (target_task_descr &&
		is_bprm(task, target_task_descr->proca_identity.file, file)) {
		PROCA_DEBUG_LOG(
			"Task descr for task %d already exists before exec\n",
			task->pid);

		proca_table_remove_task_descr(&g_proca_table,
					      target_task_descr);
		destroy_proca_task_descr(target_task_descr);
		target_task_descr = NULL;
	}

	if (!target_task_descr) {
		target_task_descr = prepare_proca_task_descr(
						task, file, tint_value,
						xattr, xattr_size,
						&five_xattr_value);
		if (target_task_descr)
			proca_table_add_task_descr(&g_proca_table,
						target_task_descr);
	}

	need_set_five |= task_integrity_value_allow_sign(tint_value);

	if ((five_xattr_value || need_set_five) && !F_SIGNATURE(file)) {
		if (!five_xattr_value && xattr)
			five_xattr_value = kmemdup(
						xattr, xattr_size, GFP_KERNEL);
		else if (!five_xattr_value && !xattr)
			read_xattr(file->f_path.dentry, XATTR_NAME_FIVE,
					&five_xattr_value);
		f_signature_assign(file, five_xattr_value);
	} else if (five_xattr_value && F_SIGNATURE(file)) {
		kfree(five_xattr_value);
	}
}

static void proca_hook_file_signed(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file, void *xattr,
				size_t xattr_size, int result)
{
	char *xattr_value = NULL;

	if (!file || result != 0 || !xattr)
		return;

	file = get_real_file(file);
	if (!file)
		return;

	kfree(F_SIGNATURE(file));

	xattr_value = kmemdup(xattr, xattr_size, GFP_KERNEL);
	f_signature_assign(file, xattr_value);
}

static void proca_hook_file_skipped(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file)
{
	char *xattr_value = NULL;
	struct dentry *dentry;

	if (!task || !file)
		return;

	if (F_SIGNATURE(file))
		return;

	file = get_real_file(file);
	if (!file)
		return;

	dentry = file->f_path.dentry;

	if (task_integrity_value_allow_sign(tint_value) &&
		read_xattr(dentry, XATTR_NAME_FIVE, &xattr_value) != 0) {
		// PROCA get FIVE signature for runtime provisioning
		// from kernel, so
		// we should set f_signature for each signed file
		f_signature_assign(file, xattr_value);
	} else if (__vfs_getxattr(dentry, dentry->d_inode, XATTR_NAME_PA,
				NULL, 0, XATTR_NOSECURITY) > 0) {
		// Workaround for Android applications.
		// If file has user.pa - check it.
		five_file_verify(task, file);
	}
}

static void proca_hook_task_forked(struct task_struct *parent,
			enum task_integrity_value parent_tint_value,
			struct task_struct *child,
			enum task_integrity_value child_tint_value)
{
	struct proca_task_descr *target_task_descr = NULL;
	struct proca_identity ident;

	if (!parent || !child)
		return;

	target_task_descr = proca_table_get_by_task(&g_proca_table, parent);
	if (!target_task_descr)
		return;

	PROCA_DEBUG_LOG("Going to clone proca identity from task %d to %d\n",
			parent->pid, child->pid);

	if (proca_identity_copy(&ident, &target_task_descr->proca_identity))
		return;

	target_task_descr = create_proca_task_descr(child, &ident);
	if (!target_task_descr) {
		deinit_proca_identity(&ident);
		return;
	}

	proca_table_add_task_descr(&g_proca_table, target_task_descr);
}

static void proca_task_free_hook(struct task_struct *task)
{
	struct proca_task_descr *target_task_descr = NULL;

	target_task_descr = proca_table_remove_by_task(&g_proca_table, task);

	destroy_proca_task_descr(target_task_descr);
}

static void proca_file_free_security_hook(struct file *file)
{
	kfree(F_SIGNATURE(file));
	f_signature_assign(file, NULL);
}

#ifndef LINUX_LSM_SUPPORTED
void proca_compat_task_free_hook(struct task_struct *task)
{
	if (unlikely(!g_proca_inited))
		return;

	proca_task_free_hook(task);
}

void proca_compat_file_free_security_hook(struct file *file)
{
	if (unlikely(!g_proca_inited))
		return;

	proca_file_free_security_hook(file);
}
#endif

int proca_get_task_cert(const struct task_struct *task,
			const char **cert, size_t *cert_size)
{
	struct proca_task_descr *task_descr = NULL;

	BUG_ON(!task || !cert || !cert_size);

	task_descr = proca_table_get_by_task(&g_proca_table, task);
	if (!task_descr)
		return -ESRCH;

	*cert = task_descr->proca_identity.certificate;
	*cert_size = task_descr->proca_identity.certificate_size;
	return 0;
}

static __init int proca_module_init(void)
{
	int ret;

	ret = init_proca_config(&g_proca_config, &g_proca_table);
	if (ret)
		return ret;

	ret = init_certificate_validation_hash();
	if (ret)
		return ret;

	proca_table_init(&g_proca_table);

	security_add_hooks(proca_ops, ARRAY_SIZE(proca_ops), "proca_lsm");
	five_add_hooks(five_ops, ARRAY_SIZE(five_ops));

	PROCA_INFO_LOG("LSM module was initialized\n");
	g_proca_inited = 1;

	return 0;
}
late_initcall(proca_module_init);

MODULE_DESCRIPTION("PROCA LSM module");
MODULE_LICENSE("GPL");

