/*
 * FIVE dmverity functions
 *
 * Copyright (C) 2019 Samsung Electronics, Inc.
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

#include "five_dmverity.h"
#include "five.h"
#include "five_testing.h"
#include "five_porting.h"
#include "drivers/md/dm.h"

#ifdef CONFIG_FIVE_DEBUG
#include <linux/debugfs.h>
#endif

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP) || defined(CONFIG_FIVE_DEBUG)
__visible_for_testing
bool check_prebuilt_paths_dmverity;
#endif

static inline int __init init_fs(void);

__visible_for_testing __mockable
struct mapped_device *call_dm_get_md(dev_t dev)
{
	return dm_get_md(dev);
}

__visible_for_testing __mockable
struct dm_table *call_dm_get_live_table(
	struct mapped_device *md, int *srcu_idx)
{
	return dm_get_live_table(md, srcu_idx);
}

__visible_for_testing __mockable
fmode_t call_dm_table_get_mode(struct dm_table *t)
{
	return dm_table_get_mode(t);
}

__visible_for_testing __mockable
unsigned int call_dm_table_get_num_targets(struct dm_table *t)
{
	return dm_table_get_num_targets(t);
}

__visible_for_testing __mockable
struct dm_target *call_dm_table_get_target(
		struct dm_table *t, unsigned int index)
{
	return dm_table_get_target(t, index);
}

__visible_for_testing __mockable
void call_dm_put_live_table(struct mapped_device *md, int srcu_idx)
{
	dm_put_live_table(md, srcu_idx);
	return;
}

__visible_for_testing __mockable
void call_dm_put(struct mapped_device *md)
{
	dm_put(md);
	return;
}

__visible_for_testing __mockable
struct block_device *call_blkdev_get_by_dev(
		dev_t dev, fmode_t mode, void *holder)
{
	return blkdev_get_by_dev(dev, mode, holder);
}

__visible_for_testing __mockable
void call_blkdev_put(struct block_device *bdev, fmode_t mode)
{
	blkdev_put(bdev, mode);
	return;
}

int __init five_init_dmverity(void)
{
	return init_fs();
}

__visible_for_testing
bool is_loop_device(const struct file *file)
{
	const struct inode *inode;

	inode = file_inode(file);
	if (unlikely(!inode || !inode->i_sb))
		return false;

	return MAJOR(inode->i_sb->s_dev) == LOOP_MAJOR ? true : false;
}

/* Check whether the file belongs to the device mapper's enabled target
 * Need to check:
 * - Super block points to a block device.
 * - The block device is created by the device mapper
 *   (dm_get_md/dm_put_md functions).
 * - The block device is a disk with a name "dm-[1-9]".
 * - The disk is in readonly mode.
 * - There is only one enabled target in the device mapper table.
 * - The target name is known target name.
 */
__visible_for_testing
enum five_dmverity_codes is_dmverity_partition(
		const struct file *file)
{
	const char dm_dev_prefix[] = "dm-";
	const char * const dm_targets_name[] = {
		"verity", "verity-fec"
	};
	enum five_dmverity_codes result = FIVE_DMV_NO_DM_TARGET_NAME;
	int srcu_idx;
	unsigned int num_targets;
	size_t i;
	const struct inode *inode;
	struct super_block *i_sb;
	struct mapped_device *md;
	struct gendisk *disk;
	struct dm_table *table;
	struct dm_target *target;

	inode = file_inode(file);
	if (unlikely(!inode)) {
		result = FIVE_DMV_BAD_INPUT;
		goto exit;
	}

	i_sb = inode->i_sb;
	if (unlikely(!i_sb)) {
		result = FIVE_DMV_BAD_INPUT;
		goto exit;
	}

	md = call_dm_get_md(i_sb->s_dev);
	if (!md) {
		result = FIVE_DMV_NO_DM_DEVICE;
		goto exit;
	}

	disk = dm_disk(md);
	if (!disk) {
		result = FIVE_DMV_NO_DM_DISK;
		goto exit_free_dm;
	}

	if (!get_disk_ro(disk)) {
		result = FIVE_DMV_NOT_READONLY_DM_DISK;
		goto exit_free_dm;
	}

	if (strncmp(disk->disk_name, dm_dev_prefix,
			sizeof(dm_dev_prefix) - 1)) {
		result = FIVE_DMV_BAD_DM_PREFIX_NAME;
		goto exit_free_dm;
	}

	table = call_dm_get_live_table(md, &srcu_idx);
	if (!table) {
		result = FIVE_DMV_NO_DM_TABLE;
		goto exit_free_dm;
	}

	if (call_dm_table_get_mode(table) & ~FMODE_READ) {
		result = FIVE_DMV_NOT_READONLY_DM_TABLE;
		goto exit_free_table;
	}

	num_targets = call_dm_table_get_num_targets(table);
	target = call_dm_table_get_target(table, 0);
	if (!target) {
		result = FIVE_DMV_NO_DM_TARGET;
		goto exit_free_table;
	}

	/* Only support devices that have a single target */
	if (num_targets != 1) {
		result = FIVE_DMV_NOT_SINGLE_TARGET;
		goto exit_free_table;
	}

	/* Checks the specific target name from available targets
	 * in device mapper.
	 */
	for (i = 0; i < ARRAY_SIZE(dm_targets_name); ++i) {
		if (!strncmp(target->type->name, dm_targets_name[i],
				strlen(dm_targets_name[i]) + 1)) {
			result = FIVE_DMV_PARTITION;
			break;
		}
	}

exit_free_table:
	call_dm_put_live_table(md, srcu_idx);
exit_free_dm:
	call_dm_put(md);
exit:
	return result;
}

__visible_for_testing
enum five_dmverity_codes is_dmverity_loop(
	const struct file *file)
{
	const fmode_t mode_bdev = FMODE_READ;
	enum five_dmverity_codes result = FIVE_DMV_NO_SB_LOOP_DEVICE;
	struct super_block *i_sb;
	const struct inode *inode;
	struct block_device *bdev;
	struct gendisk *bd_disk;
	struct file *file_mount_to_lo_dev;
	struct loop_device *lo_dev;

	inode = file_inode(file);
	i_sb = inode->i_sb;

	if (MAJOR(i_sb->s_dev) != LOOP_MAJOR)
		goto exit;

	bdev = call_blkdev_get_by_dev(i_sb->s_dev, mode_bdev, NULL);
	if (IS_ERR_OR_NULL(bdev) || MAJOR(bdev->bd_dev) != LOOP_MAJOR) {
		result = FIVE_DMV_NO_BD_LOOP_DEVICE;
		goto exit;
	}

	bd_disk = bdev->bd_disk;
	if (unlikely(!bd_disk)) {
		result = FIVE_DMV_NO_BD_DISK;
		goto exit_free_blkdev;
	}

	lo_dev = bd_disk->private_data;
	if (unlikely(!lo_dev)) {
		result = FIVE_DMV_NO_LOOP_DEV;
		goto exit_free_blkdev;
	}

	file_mount_to_lo_dev = lo_dev->lo_backing_file;
	if (unlikely(!file_mount_to_lo_dev)) {
		result = FIVE_DMV_NO_LOOP_BACK_FILE;
		goto exit_free_blkdev;
	}

	result = is_dmverity_partition(file_mount_to_lo_dev);

exit_free_blkdev:
	call_blkdev_put(bdev, mode_bdev);
exit:
	return result;
}

#if defined(CONFIG_SAMSUNG_PRODUCT_SHIP) && !defined(CONFIG_FIVE_DEBUG)
bool five_is_dmverity_protected(const struct file *file)
{
	enum five_dmverity_codes dmv_file_status;
	bool result = false;

	if (unlikely(!file))
		return result;

	/* Checks is loop device /dev/block/loopX or no */
	if (is_loop_device(file))
		/* Checks /dev/block/loopX mounted to /apex/name@version and
		 * it should specify to /system/apex/[name].apex under dmverity
		 * protection.
		 */
		dmv_file_status = is_dmverity_loop(file);
	else
		/* Checks file on dmverity partition, in case of dmverity is
		 * disabled need to check prebuilt paths of dmverity.
		 */
		dmv_file_status = is_dmverity_partition(file);

	if (dmv_file_status == FIVE_DMV_PARTITION)
		result = true;

	return result;
}
#else
static bool is_dmverity_prebuit_path(const struct file *file)
{
	const char * const paths[] = {
		"/system/", "/system_ext/", "/vendor/", "/apex/",
		"/product/", "/odm/", "/prism/", "/optics/"
	};
	const char *pathname = NULL;
	char *pathbuf = NULL;
	char filename[NAME_MAX];
	bool result = false;
	size_t i;

	pathname = five_d_path(&file->f_path, &pathbuf, filename);

	for (i = 0; i < ARRAY_SIZE(paths); ++i) {
		if (!strncmp(pathname, paths[i], strlen(paths[i]))) {
			result = true;
			break;
		}
	}

	if (pathbuf)
		__putname(pathbuf);

	return result;
}

bool five_is_dmverity_protected(const struct file *file)
{
	enum five_dmverity_codes dmv_file_status;
	bool result = false;

	if (unlikely(!file))
		return result;

	if (check_prebuilt_paths_dmverity)
		return is_dmverity_prebuit_path(file);

	/* Checks is loop device /dev/block/loopX or no */
	if (is_loop_device(file))
		/* Checks /dev/block/loopX mounted to /apex/name@version/ and
		 * it should specify to /system/apex/[name].apex under dmverity
		 * protection.
		 */
		dmv_file_status = is_dmverity_loop(file);
	else
		/* Checks file on dmverity partition, in case of dmverity is
		 * disabled need to check prebuilt paths dmverity.
		 */
		dmv_file_status = is_dmverity_partition(file);

	if (dmv_file_status == FIVE_DMV_PARTITION)
		result = true;
	else
		result = is_dmverity_prebuit_path(file);

	return result;
}
#endif

#ifdef CONFIG_FIVE_DEBUG
static ssize_t five_check_prebuilt_paths_dmverity_read(struct file *file,
		char __user *user_buf, size_t count, loff_t *pos)
{
	char buf[2];

	buf[0] = check_prebuilt_paths_dmverity ? '1' : '0';
	buf[1] = '\n';

	return simple_read_from_buffer(user_buf, count, pos, buf, sizeof(buf));
}

static ssize_t five_check_prebuilt_paths_dmverity_write(struct file *file,
		const char __user *buf, size_t count, loff_t *pos)
{
	char command;

	if (get_user(command, buf))
		return -EFAULT;

	switch (command) {
	case '0':
		check_prebuilt_paths_dmverity = false;
		break;
	case '1':
		check_prebuilt_paths_dmverity = true;
		break;
	default:
		pr_err("FIVE: %s: unknown cmd: %hhx\n", __func__, command);
		return -EINVAL;
	}

	pr_info("FIVE debug: Check dm-verity file paths %s\n",
		check_prebuilt_paths_dmverity ? "enabled" : "disabled");
	return count;
}

static const struct file_operations five_dmverity_fops = {
	.owner = THIS_MODULE,
	.read = five_check_prebuilt_paths_dmverity_read,
	.write = five_check_prebuilt_paths_dmverity_write
};

static inline int __init init_fs(void)
{
	struct dentry *debug_file = NULL;
	const umode_t umode = 0664;

	debug_file = debugfs_create_file("five_prebuilt_paths_dmverity",
			umode, NULL, NULL, &five_dmverity_fops);
	if (IS_ERR_OR_NULL(debug_file))
		goto error;

	return 0;
error:
	if (debug_file)
		return -PTR_ERR(debug_file);

	return -EEXIST;
}
#else
static inline int __init init_fs(void)
{
	return 0;
}
#endif
