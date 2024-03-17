/*
 * This is needed backporting of source code from Kernel version 4.x
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 *
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

#ifndef __LINUX_FIVE_PORTING_H
#define __LINUX_FIVE_PORTING_H

#include <linux/version.h>
#include <linux/magic.h>

/* fallthrough is defined since v5.4.0 */
#ifndef fallthrough
#define fallthrough                    do {} while (0)  /* fallthrough */
#endif


/* OVERLAYFS_SUPER_MAGIC is defined since v4.5.0 */
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif

/* EROFS_SUPER_MAGIC_V1 is defined since v5.4 */
#ifndef EROFS_SUPER_MAGIC_V1
#define EROFS_SUPER_MAGIC_V1 0xE0F5E1E2
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 21)
/* d_backing_inode is absent on some Linux Kernel 3.x. but it back porting for
 * few Samsung kernels:
 * Exynos7570 (3.18.14): CL 13680422
 * Exynos7870 (3.18.14): CL 14632149
 * SDM450 (3.18.71): initially
 */
#if !defined(CONFIG_SOC_EXYNOS7570) && !defined(CONFIG_ARCH_SDM450) && \
	!defined(CONFIG_SOC_EXYNOS7870)
#define d_backing_inode(dentry)	((dentry)->d_inode)
#endif
#define inode_lock(inode)	mutex_lock(&(inode)->i_mutex)
#define inode_lock_nested(inode, subclass) \
				mutex_lock_nested(&(inode)->i_mutex, subclass)
#define inode_unlock(inode)	mutex_unlock(&(inode)->i_mutex)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
#include <linux/fs.h>

#ifndef IS_VERITY
#define IS_VERITY(inode) 0
#endif
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 20, 0)
/* It is added for initialization purposes.
 * For developing LSM, please, use DEFINE_LSM
 */
#define security_initcall(fn) late_initcall(fn)
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 20, 17)
/* This file was added in v5.0.0 */
#include <uapi/linux/mount.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 20)
/* kmemcheck is gone.
 * Since Kernel 4.14.21 SLAB_NOTRACK isn't present in Kernel.
 * But for backward compatibility with old Kernels
 * we have to define it here.
 */
#define SLAB_NOTRACK 0
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 17)
/* Some linux headers are moved.
 * Since Kernel 4.11 get_task_struct moved to sched/ folder.
 */
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
#include <linux/fs.h>

static inline int __vfs_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = d_inode(dentry);

	if (!inode->i_op->removexattr)
		return -EOPNOTSUPP;

	return inode->i_op->removexattr(dentry, name);
}

static inline ssize_t __vfs_getxattr(struct dentry *dentry, struct inode *inode,
				     const char *name, void *value, size_t size)
{
	if (!inode->i_op->getxattr)
		return -EOPNOTSUPP;

	return inode->i_op->getxattr(dentry, name, value, size);
}
#endif

#if (defined(CONFIG_ANDROID) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) || \
				LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))) || \
				LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
/*
 * __vfs_getxattr was changed in Android Kernel v5.4
 * https://android.googlesource.com/kernel/common/+/3484eba91d6b529cc606486a2db79513f3db6c67
 * and was reverted in Android Kernel v5.15
 * https://android.googlesource.com/kernel/common/+/e884438aa554219a6d0df3a18ff0b23ea678c36c
 */
#define XATTR_NOSECURITY 0x4	/* get value, do not involve security check */
#define __vfs_getxattr(dentry, inode, name, value, size, flags) \
		__vfs_getxattr(dentry, inode, name, value, size)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define vfs_getxattr_alloc(dentry, name, xattr_value, size, flags) \
	vfs_getxattr_alloc(&init_user_ns, dentry, name, xattr_value, \
			   size, flags)
#define __vfs_setxattr_noperm(dentry, name, value, size, flags) \
	__vfs_setxattr_noperm(&init_user_ns, dentry, name, value, size, flags)
#define __vfs_removexattr(dentry, name) \
		__vfs_removexattr(&init_user_ns, dentry, name)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
/* __GFP_WAIT was changed to __GFP_RECLAIM in
 * https://lore.kernel.org/patchwork/patch/592262/
 */
#define __GFP_RECLAIM __GFP_WAIT
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
#include <linux/uaccess.h>

static inline ssize_t __vfs_read(struct file *file, char __user *buf,
				 size_t count, loff_t *pos)
{
	ssize_t ret;

	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->aio_read)
		ret = do_sync_read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		ret = new_sync_read(file, buf, count, pos);
	else
		ret = -EINVAL;

	return ret;
}

static inline int integrity_kernel_read(struct file *file, loff_t offset,
					char *addr, unsigned long count)
{
	mm_segment_t old_fs;
	char __user *buf = (char __user *)addr;
	ssize_t ret;
	struct inode *inode = file_inode(file);

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;

	old_fs = get_fs();
	set_fs(get_ds());

	if (inode->i_sb->s_magic == OVERLAYFS_SUPER_MAGIC && file->private_data)
		file = (struct file *)file->private_data;

	ret = __vfs_read(file, buf, count, &offset);
	set_fs(old_fs);

	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#include <linux/fs.h>

static inline bool
inode_eq_iversion(const struct inode *inode, u64 old)
{
	return inode->i_version == old;
}

static inline u64
inode_query_iversion(struct inode *inode)
{
	return inode->i_version;
}
#else
#include <linux/iversion.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 8)
static inline struct dentry *file_dentry(const struct file *file)
{
	return file->f_path.dentry;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 2)
static inline struct dentry *d_real_comp(struct dentry *dentry)
{
	return dentry;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
static inline struct dentry *d_real_comp(struct dentry *dentry)
{
	return d_real(dentry);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline struct dentry *d_real_comp(struct dentry *dentry)
{
	return d_real(dentry, NULL, 0);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
static inline struct dentry *d_real_comp(struct dentry *dentry)
{
	return d_real(dentry, NULL, 0, 0);
}
#else
static inline struct dentry *d_real_comp(struct dentry *dentry)
{
	return d_real(dentry, d_real_inode(dentry));
}
#endif

/* d_real_inode was added in v4.4.16, removed in v4.5.0 and added again in v4.6.5 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 16) || \
	(LINUX_VERSION_CODE > KERNEL_VERSION(4, 5, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 5))
static inline struct inode *d_real_inode(struct dentry *dentry)
{
	return d_backing_inode(d_real_comp(dentry));
}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#include "drivers/md/dm-core.h"
#include "uapi/linux/major.h"
#include "uapi/linux/loop.h"
#include "linux/device-mapper.h"

struct loop_device {
	int		lo_number;
	loff_t		lo_offset;
	loff_t		lo_sizelimit;
	int		lo_flags;
	char		lo_file_name[LO_NAME_SIZE];

	struct file *	lo_backing_file;
	struct block_device *lo_device;

	gfp_t		old_gfp_mask;

	spinlock_t		lo_lock;
	int			lo_state;
	spinlock_t              lo_work_lock;
	struct workqueue_struct *workqueue;
	struct work_struct      rootcg_work;
	struct list_head        rootcg_cmd_list;
	struct list_head        idle_worker_list;
	struct rb_root          worker_tree;
	struct timer_list       timer;
	bool			use_dio;
	bool			sysfs_inited;

	struct request_queue	*lo_queue;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*lo_disk;
	struct mutex		lo_mutex;
	bool			idr_visible;
};
#else
#include "drivers/block/loop.h"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#define dm_table_get_num_targets(t) t->num_targets
#endif
#endif /* __LINUX_FIVE_PORTING_H */
