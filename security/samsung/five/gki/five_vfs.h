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

ssize_t five_getxattr_alloc(struct dentry *dentry, const char *name,
			    char **xattr_value, size_t xattr_size, gfp_t flags);
ssize_t five_vfs_read(struct file *file, char __user *buf,
		      size_t count, loff_t *pos);
int five_kernel_read(struct file *file, loff_t offset,
			  void *addr, unsigned long count);
int five_setxattr_noperm(struct dentry *dentry, const char *name,
			 const void *value, size_t size, int flags);
