/*
 * FIVE vfs functions
 *
 * Copyright (C) 2020 Samsung Electronics, Inc.
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

#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/uio.h>
#include "five_vfs.h"

/* This function is an alternative implementation of vfs_getxattr_alloc() */
ssize_t five_getxattr_alloc(struct dentry *dentry, const char *name,
			    char **xattr_value, size_t xattr_size, gfp_t flags)
{
	struct inode *inode = dentry->d_inode;
	char *value = *xattr_value;
	int error;

	error = __vfs_getxattr(dentry, inode, name, NULL, 0, XATTR_NOSECURITY);
	if (error < 0)
		return error;

	if (!value || (error > xattr_size)) {
		value = krealloc(*xattr_value, error + 1, flags);
		if (!value)
			return -ENOMEM;
		memset(value, 0, error + 1);
	}

	error = __vfs_getxattr(dentry, inode, name, value, error,
			       XATTR_NOSECURITY);
	*xattr_value = value;
	return error;
}

/* This function is copied from new_sync_read() */
static ssize_t new_sync_read(struct file *filp, char __user *buf,
			     size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = (ppos ? *ppos : 0);
	iov_iter_init(&iter, READ, &iov, 1, len);

	ret = call_read_iter(filp, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ppos)
		*ppos = kiocb.ki_pos;
	return ret;
}

/* This function is copied from __vfs_read() */
ssize_t five_vfs_read(struct file *file, char __user *buf, size_t count,
		   loff_t *pos)
{
	if (file->f_op->read)
		return file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		return new_sync_read(file, buf, count, pos);
	else
		return -EINVAL;
}

/* This function is copied from __vfs_setxattr_noperm() */
int five_setxattr_noperm(struct dentry *dentry, const char *name,
			 const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	int error = -EAGAIN;
	int issec = !strncmp(name, XATTR_SECURITY_PREFIX,
			     XATTR_SECURITY_PREFIX_LEN);

	if (issec)
		inode->i_flags &= ~S_NOSEC;
	if (inode->i_opflags & IOP_XATTR) {
		error = __vfs_setxattr(dentry, inode, name, value, size, flags);
	} else {
		if (unlikely(is_bad_inode(inode)))
			return -EIO;
	}

	return error;
}

/*
 * five_kernel_read - read data from the file
 *
 * This is a function for reading file content instead of kernel_read().
 * It does not perform locking checks to ensure it cannot be blocked.
 * It does not perform security checks because it is irrelevant for IMA.
 *
 * This function is copied from integrity_kernel_read()
 */
int five_kernel_read(struct file *file, loff_t offset,
			  void *addr, unsigned long count)
{
	mm_segment_t old_fs;
	char __user *buf = (char __user *)addr;
	ssize_t ret;
	struct inode *inode = file_inode(file);

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	if (inode->i_sb->s_magic == OVERLAYFS_SUPER_MAGIC && file->private_data)
		file = (struct file *)file->private_data;

	ret = five_vfs_read(file, buf, count, &offset);
	set_fs(old_fs);

	return ret;
}
