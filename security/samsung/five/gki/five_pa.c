/*
 * Process Authentificator helpers
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

#include <linux/file.h>
#include <linux/module.h>
#include <linux/task_integrity.h>
#include <linux/proca.h>
#include <linux/xattr.h>
#include <linux/version.h>

#include "five.h"
#include "five_pa.h"
#include "five_hooks.h"
#include "five_lv.h"
#include "five_porting.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
#define F_SIGNATURE(file) ((void *)((file)->android_oem_data1))

static inline void f_signature_assign(struct file *file, void *f_signature)
{
	file->android_oem_data1 = (u64)f_signature;
}
#else
#define F_SIGNATURE(file) ((void *)((file)->android_vendor_data1))

static inline void f_signature_assign(struct file *file, void *f_signature)
{
	file->android_vendor_data1 = (u64)f_signature;
}
#endif

static void process_file(struct task_struct *task, struct file *file)
{
	char *xattr_value = NULL;

	if (F_SIGNATURE(file))
		return;

	if (five_check_params(task, file))
		return;

	five_read_xattr(d_real_comp(file->f_path.dentry), &xattr_value);
	f_signature_assign(file, xattr_value);
}

void fivepa_fsignature_free(struct file *file)
{
	kfree(F_SIGNATURE(file));
	f_signature_assign(file, NULL);
}

int proca_fcntl_setxattr(struct file *file, void __user *lv_xattr)
{
	struct inode *inode = file_inode(file);
	struct lv lv_hdr = {0};
	int rc = -EPERM;
	void *x = NULL;

	if (unlikely(!file || !lv_xattr))
		return -EINVAL;

	if (unlikely(copy_from_user(&lv_hdr, lv_xattr, sizeof(lv_hdr))))
		return -EFAULT;

	if (unlikely(lv_hdr.length > PAGE_SIZE))
		return -EINVAL;

	x = kmalloc(lv_hdr.length, GFP_NOFS);
	if (unlikely(!x))
		return -ENOMEM;

	if (unlikely(copy_from_user(x, lv_xattr + sizeof(lv_hdr),
		lv_hdr.length))) {
		rc = -EFAULT;
		goto out;
	}

	if (file->f_op && file->f_op->flush)
		if (file->f_op->flush(file, current->files)) {
			rc = -EOPNOTSUPP;
			goto out;
		}

	inode_lock(inode);

	if (task_integrity_allow_sign(TASK_INTEGRITY(current))) {
		rc = __vfs_setxattr_noperm(d_real_comp(file->f_path.dentry),
						XATTR_NAME_PA,
						x,
						lv_hdr.length,
						0);
	}
	inode_unlock(inode);

out:
	kfree(x);

	return rc;
}

static void proca_hook_file_processed(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file, void *xattr,
				size_t xattr_size, int result);

static void proca_hook_file_skipped(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file);

static struct five_hook_list five_ops[] = {
	FIVE_HOOK_INIT(file_processed, proca_hook_file_processed),
	FIVE_HOOK_INIT(file_skipped, proca_hook_file_skipped),
};

static void proca_hook_file_processed(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file, void *xattr,
				size_t xattr_size, int result)
{
	process_file(task, file);
}

static void proca_hook_file_skipped(struct task_struct *task,
				enum task_integrity_value tint_value,
				struct file *file)
{
	process_file(task, file);
}

static __init int proca_module_init(void)
{
	five_add_hooks(five_ops, ARRAY_SIZE(five_ops));
	pr_info("PROCA was initialized\n");

	return 0;
}
late_initcall(proca_module_init);

MODULE_DESCRIPTION("PROCA module");
MODULE_LICENSE("GPL");
