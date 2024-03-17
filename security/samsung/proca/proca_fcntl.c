/*
 * PROCA fcntl implementation
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

#include <linux/proca.h>
#include <linux/task_integrity.h>
#include <linux/xattr.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define XATTR_PA_SUFFIX "pa"
#define XATTR_NAME_PA (XATTR_USER_PREFIX XATTR_PA_SUFFIX)

#include "proca_porting.h"

/**
 * Length/Value structure
 */
struct lv {
	uint16_t length;
	uint8_t value[];
} __packed;

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
