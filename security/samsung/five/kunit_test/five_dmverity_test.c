/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */
#include "drivers/md/dm.h"
#include "drivers/md/dm-core.h"
#include "drivers/block/loop.h"

#include "five_dmverity.h"
#include "test_helpers.h"

bool is_loop_device(const struct file *file);
enum five_dmverity_codes is_dmverity_partition(const struct file *file);
enum five_dmverity_codes is_dmverity_loop(const struct file *file);
bool five_is_dmverity_protected(const struct file *file);
#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP) || defined(CONFIG_FIVE_DEBUG)
extern bool check_prebuilt_paths_dmverity;
#endif

#define MAJOR_INV(dev)	((unsigned int) ((dev) << MINORBITS))

// any random dev different from MAJOR_INV(LOOP_MAJOR)
#define RANDOM_DEV (LOOP_MAJOR + 1)
#define SRCU_IDX 2020  // any int number
#define S_DEV 2019 // any int number

DEFINE_FUNCTION_MOCK(
	METHOD(call_dm_get_md), RETURNS(struct mapped_device *),
	PARAMS(dev_t));

DEFINE_FUNCTION_MOCK(
	METHOD(call_dm_get_live_table), RETURNS(struct dm_table *),
	PARAMS(struct mapped_device *, int *));

DEFINE_FUNCTION_MOCK(
	METHOD(call_dm_table_get_mode), RETURNS(fmode_t),
	PARAMS(struct dm_table *));

DEFINE_FUNCTION_MOCK(
	METHOD(call_dm_table_get_num_targets), RETURNS(unsigned int),
	PARAMS(struct dm_table *));

DEFINE_FUNCTION_MOCK(
	METHOD(call_dm_table_get_target), RETURNS(struct dm_target *),
	PARAMS(struct dm_table *, unsigned int));

DEFINE_FUNCTION_MOCK(
	METHOD(call_blkdev_get_by_dev), RETURNS(struct block_device *),
	PARAMS(dev_t, fmode_t, void *));

DEFINE_FUNCTION_MOCK_VOID_RETURN(
	METHOD(call_dm_put_live_table), PARAMS(struct mapped_device *, int));

DEFINE_FUNCTION_MOCK_VOID_RETURN(
	METHOD(call_dm_put), PARAMS(struct mapped_device *));

DEFINE_FUNCTION_MOCK_VOID_RETURN(
	METHOD(call_blkdev_put), PARAMS(struct block_device *, fmode_t));

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP) || defined(CONFIG_FIVE_DEBUG)
DECLARE_FUNCTION_MOCK(
	METHOD(five_d_path), RETURNS(const char *),
	PARAMS(const struct path *, char **, char *));
#endif

typedef struct {int foo; } fake_dm_table_t;

static struct file *create_file_obj(struct kunit *test)
{
	DECLARE_NEW(test, struct file, foo);

	foo->f_inode = NEW(test, struct inode);
	foo->f_inode->i_sb = NEW(test, struct super_block);
	return foo;
}

static struct mapped_device *create_mapped_device_obj(
	struct kunit *test, int policy, char *disk_name)
{
	DECLARE_NEW(test, struct mapped_device, foo);

	foo->disk = NEW(test, struct gendisk);
	foo->disk->part0.policy = policy;
	if (strlen(disk_name) < DISK_NAME_LEN)
		strncpy(foo->disk->disk_name, disk_name, strlen(disk_name) + 1);
	return foo;
}

static void five_dmverity_is_loop_device_null_inode_test(struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);

	p_file->f_inode = NULL;
	KUNIT_EXPECT_FALSE(test, is_loop_device(p_file));
}

static void five_dmverity_is_loop_device_null_sb_test(struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);

	p_file->f_inode = NEW(test, struct inode);;
	p_file->f_inode->i_sb = NULL;

	KUNIT_EXPECT_FALSE(test, is_loop_device(p_file));
}

static void five_dmverity_is_loop_device_wrong_s_dev_test(struct kunit *test)
{
	struct file *p_file = create_file_obj(test);

	p_file->f_inode->i_sb->s_dev = RANDOM_DEV;

	KUNIT_EXPECT_FALSE(test, is_loop_device(p_file));
}

static void five_dmverity_is_loop_device_correct_s_dev_test(struct kunit *test)
{
	struct file *p_file = create_file_obj(test);

	p_file->f_inode->i_sb->s_dev = MAJOR_INV(LOOP_MAJOR);

	KUNIT_EXPECT_TRUE(test, is_loop_device(p_file));
}

static void five_dmverity_is_dmverity_partition_null_inode_test(
	struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);

	p_file->f_inode = NULL;

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_BAD_INPUT);
}

static void five_dmverity_is_dmverity_partition_null_sb_test(
	struct kunit *test)
{
	DECLARE_NEW(test, struct file, p_file);

	p_file->f_inode = NEW(test, struct inode);
	p_file->f_inode->i_sb = NULL;

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_BAD_INPUT);
}

static void five_dmverity_is_dmverity_partition_null_md_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);

	p_file->f_inode->i_sb->s_dev = RANDOM_DEV;
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_get_md(
		int_eq(test, RANDOM_DEV))), ptr_return(test, NULL));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_DM_DEVICE);
}

static void five_dmverity_is_dmverity_partition_null_disc_test(
		struct kunit *test)
{
	DECLARE_NEW(test, struct mapped_device, md);
	struct file *p_file = create_file_obj(test);

	md->disk = NULL;

	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_get_md(any(test))), ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_DM_DISK);
}

static void five_dmverity_is_dmverity_partition_not_ro_disc_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, 0, "");

	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_get_md(any(test))), ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NOT_READONLY_DM_DISK);
}

static void five_dmverity_is_dmverity_partition_bad_prefix_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "xxxxx");

	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_get_md(any(test))), ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_BAD_DM_PREFIX_NAME);
}

static void five_dmverity_is_dmverity_partition_no_table_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "dm-xxx");

	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(
		any(test))), ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_live_table(
		ptr_eq(test, md), any(test))), ptr_return(test, NULL));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_DM_TABLE);
}

static fake_dm_table_t *fke_table;
void *dm_get_live_table_action(
		struct mock_action *this, const void **params, int len)
{
	const int **foo;

	if (2 != len) {
		pr_err("Wrong number of params!");
		return NULL;
	}
	foo = (const int **)params[1];
	*(int *)(*foo) = SRCU_IDX;
	return &fke_table;
}

static void five_dmverity_is_dmverity_partition_not_ro_table_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "dm-xxx");

	fke_table = NEW(test, fake_dm_table_t);

	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(any(test))),
		ptr_return(test, md));
	ActionOnMatch(KUNIT_EXPECT_CALL(call_dm_get_live_table(
		any(test), any(test))),
		new_mock_action(test, dm_get_live_table_action));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_mode(
		ptr_eq(test, fke_table))), int_return(test, 2));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_put_live_table(
		ptr_eq(test, md), int_eq(test, SRCU_IDX))),
		int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NOT_READONLY_DM_TABLE);
}

static void five_dmverity_is_dmverity_partition_no_target_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "dm-xxx");
	fake_dm_table_t *fake_table = NEW(test, fake_dm_table_t);

	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(any(test))),
		ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_live_table(
		any(test), any(test))),
		ptr_return(test, fake_table));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_mode(any(test))),
		int_return(test, 1)); // return any value <= 1
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_num_targets(
		ptr_eq(test, fake_table))),
		int_return(test, 8841)); // any value. Won't be analyzed.
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_target(
		any(test), int_eq(test, 0))),
		ptr_return(test, NULL));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_put_live_table(
		ptr_eq(test, md), any(test))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_DM_TARGET);
}

static void five_dmverity_is_dmverity_partition_not_single_target_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "dm-xxx");
	fake_dm_table_t *fake_table = NEW(test, fake_dm_table_t);
	struct dm_target *target = NEW(test, struct dm_target);

	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(any(test))),
		ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_live_table(
		any(test), any(test))),
		ptr_return(test, fake_table));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_mode(any(test))),
		int_return(test, 1)); // return any value <= 1
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_table_get_num_targets(any(test))),
		int_return(test, 2020)); // any value. Won't be analyzed.
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_target(
		any(test), int_eq(test, 0))),
		ptr_return(test, target));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_put_live_table(
		ptr_eq(test, md), any(test))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NOT_SINGLE_TARGET);
}

static void five_dmverity_is_dmverity_partition_no_target_name_test(
	struct kunit *test)
{
	const char target_name[] = "wrong name";
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "dm-xxx");
	fake_dm_table_t *fake_table = NEW(test, fake_dm_table_t);
	struct dm_target *target = NEW(test, struct dm_target);

	target->type = NEW(test, struct target_type);
	target->type->name = target_name;

	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(any(test))),
		ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_live_table(
		any(test), any(test))),
		ptr_return(test, fake_table));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_mode(any(test))),
		int_return(test, 1)); // return any value <= 1
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_table_get_num_targets(any(test))),
		int_return(test, 1)); // any value equal to 1
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_target(
		any(test), int_eq(test, 0))),
		ptr_return(test, target));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_put_live_table(
		ptr_eq(test, md), any(test))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_DM_TARGET_NAME);
}

static void five_dmverity_is_dmverity_partition_verity_test(struct kunit *test)
{
	const char target_name[] = "verity";
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "dm-xxx");
	fake_dm_table_t *fake_table = NEW(test, fake_dm_table_t);
	struct dm_target *target = NEW(test, struct dm_target);

	target->type = NEW(test, struct target_type);
	target->type->name = target_name;

	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(any(test))),
		ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_live_table(
		any(test), any(test))),
		ptr_return(test, fake_table));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_mode(any(test))),
		int_return(test, 1)); // return any value <= 1
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_table_get_num_targets(any(test))),
		int_return(test, 1)); // any value equal to 1
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_target(
		any(test), int_eq(test, 0))),
		ptr_return(test, target));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_put_live_table(
		ptr_eq(test, md), any(test))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_PARTITION);
}

static void five_dmverity_is_dmverity_partition_verity_fec_test(
	struct kunit *test)
{
	const char target_name[] = "verity-fec";
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "dm-xxx");
	fake_dm_table_t *fake_table = NEW(test, fake_dm_table_t);
	struct dm_target *target = NEW(test, struct dm_target);

	target->type = NEW(test, struct target_type);
	target->type->name = target_name;

	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(any(test))),
		ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_live_table(
		any(test), any(test))),
		ptr_return(test, fake_table));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_mode(any(test))),
		int_return(test, 1)); // return any value <= 1
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_table_get_num_targets(any(test))),
		int_return(test, 1)); // any value equal to 1
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_target(
		any(test), int_eq(test, 0))),
		ptr_return(test, target));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_put_live_table(
		ptr_eq(test, md), any(test))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_partition(p_file),
		(enum five_dmverity_codes)FIVE_DMV_PARTITION);
}

static void five_dmverity_is_dmverity_loop_wrong_bdev_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);

	p_file->f_inode->i_sb->s_dev = MAJOR_INV(LOOP_MAJOR);

	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_get_by_dev(
		int_eq(test, p_file->f_inode->i_sb->s_dev),
		int_eq(test, FMODE_READ), ptr_eq(test, NULL))),
		ptr_return(test, NULL));

	KUNIT_EXPECT_EQ(test, is_dmverity_loop(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_BD_LOOP_DEVICE);
}

static void five_dmverity_is_dmverity_loop_wrong_bd_dev_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct block_device *bdev = NEW(test, struct block_device);

	p_file->f_inode->i_sb->s_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_dev = RANDOM_DEV;

	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_get_by_dev(
		int_eq(test, p_file->f_inode->i_sb->s_dev),
		int_eq(test, FMODE_READ), ptr_eq(test, NULL))),
		ptr_return(test, bdev));

	KUNIT_EXPECT_EQ(test, is_dmverity_loop(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_BD_LOOP_DEVICE);
}

static void five_dmverity_is_dmverity_loop_null_bd_disk_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct block_device *bdev = NEW(test, struct block_device);

	p_file->f_inode->i_sb->s_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_disk = NULL;

	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_get_by_dev(
		int_eq(test, p_file->f_inode->i_sb->s_dev),
		int_eq(test, FMODE_READ), ptr_eq(test, NULL))),
		ptr_return(test, bdev));
	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_put(
		ptr_eq(test, bdev),
		int_eq(test, FMODE_READ))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_loop(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_BD_DISK);
}

static void five_dmverity_is_dmverity_loop_null_private_data_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
	struct block_device *bdev = NEW(test, struct block_device);

	p_file->f_inode->i_sb->s_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_disk = NEW(test, struct gendisk);
	bdev->bd_disk->private_data = NULL;

	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_get_by_dev(
		int_eq(test, p_file->f_inode->i_sb->s_dev),
		int_eq(test, FMODE_READ), ptr_eq(test, NULL))),
		ptr_return(test, bdev));
	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_put(
		ptr_eq(test, bdev),
		int_eq(test, FMODE_READ))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_loop(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_LOOP_DEV);
}

static void five_dmverity_is_dmverity_loop_null_back_file_test(
	struct kunit *test)
{
	struct loop_device *p_loop_device;
	struct file *p_file = create_file_obj(test);
	struct block_device *bdev = NEW(test, struct block_device);

	p_file->f_inode->i_sb->s_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_disk = NEW(test, struct gendisk);
	bdev->bd_disk->private_data = NEW(test, struct loop_device);
	p_loop_device = bdev->bd_disk->private_data;
	p_loop_device->lo_backing_file = NULL;

	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_get_by_dev(
		int_eq(test, p_file->f_inode->i_sb->s_dev),
		int_eq(test, FMODE_READ), ptr_eq(test, NULL))),
		ptr_return(test, bdev));
	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_put(
		ptr_eq(test, bdev),
		int_eq(test, FMODE_READ))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_loop(p_file),
		(enum five_dmverity_codes)FIVE_DMV_NO_LOOP_BACK_FILE);
}

static void five_dmverity_is_dmverity_loop_correct_back_file_test(
	struct kunit *test)
{
	struct loop_device *p_loop_device;
	struct file *p_file = create_file_obj(test);
	struct block_device *bdev = NEW(test, struct block_device);

	p_file->f_inode->i_sb->s_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_dev = MAJOR_INV(LOOP_MAJOR);
	bdev->bd_disk = NEW(test, struct gendisk);
	bdev->bd_disk->private_data = NEW(test, struct loop_device);
	p_loop_device = bdev->bd_disk->private_data;
	p_loop_device->lo_backing_file = NEW(test, struct file);
	p_loop_device->lo_backing_file->f_inode = NULL;

	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_get_by_dev(
		int_eq(test, p_file->f_inode->i_sb->s_dev),
		int_eq(test, FMODE_READ), ptr_eq(test, NULL))),
		ptr_return(test, bdev));
	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_put(
		ptr_eq(test, bdev),
		int_eq(test, FMODE_READ))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, is_dmverity_loop(p_file),
		(enum five_dmverity_codes)FIVE_DMV_BAD_INPUT);
}

static void five_dmverity_is_dmverity_protected_null_file_test(
	struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, five_is_dmverity_protected(NULL));
}

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP) || defined(CONFIG_FIVE_DEBUG)
static void five_check_prebuilt_paths_false_test(
	struct kunit *test)
{
	char pathname[] = "xxx";
	DECLARE_NEW(test, struct file, p_file);

	check_prebuilt_paths_dmverity = true;

	KunitReturns(KUNIT_EXPECT_CALL(five_d_path(
	ptr_eq(test, &p_file->f_path),
	any(test), any(test))),
	ptr_return(test, pathname));

	KUNIT_EXPECT_FALSE(test, five_is_dmverity_protected(p_file));
	check_prebuilt_paths_dmverity = false;
}

static void five_check_prebuilt_paths_true_test(
	struct kunit *test)
{
	char pathname[] = "/apex/";
	DECLARE_NEW(test, struct file, p_file);

	check_prebuilt_paths_dmverity = true;

	KunitReturns(KUNIT_EXPECT_CALL(five_d_path(
	ptr_eq(test, &p_file->f_path),
	any(test), any(test))),
	ptr_return(test, pathname));

	KUNIT_EXPECT_TRUE(test, five_is_dmverity_protected(p_file));

	check_prebuilt_paths_dmverity = false;
}
#endif

static void five_dmverity_is_dmverity_protected_loop_device_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP) || defined(CONFIG_FIVE_DEBUG)
	char pathname[] = "xxx";

	KunitReturns(KUNIT_EXPECT_CALL(five_d_path(
		ptr_eq(test, &p_file->f_path),
		any(test), any(test))),
		ptr_return(test, pathname));
#endif

	p_file->f_inode->i_sb->s_dev = MAJOR_INV(LOOP_MAJOR);
	KunitReturns(KUNIT_EXPECT_CALL(call_blkdev_get_by_dev(
		int_eq(test, p_file->f_inode->i_sb->s_dev),
		int_eq(test, FMODE_READ), ptr_eq(test, NULL))),
		ptr_return(test, NULL));

	KUNIT_EXPECT_FALSE(test, five_is_dmverity_protected(p_file));
}

static void five_dmvrt_is_dmverity_protected_non_loop_device_false_test(
	struct kunit *test)
{
	struct file *p_file = create_file_obj(test);
#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP) || defined(CONFIG_FIVE_DEBUG)
	char pathname[] = "xxx";

	KunitReturns(KUNIT_EXPECT_CALL(five_d_path(
		ptr_eq(test, &p_file->f_path),
		any(test), any(test))),
		ptr_return(test, pathname));
#endif

	p_file->f_inode->i_sb->s_dev = RANDOM_DEV;
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(
		int_eq(test, p_file->f_inode->i_sb->s_dev))),
		ptr_return(test, NULL));

	KUNIT_EXPECT_FALSE(test, five_is_dmverity_protected(p_file));
}

static void five_dmvrt_is_dmverity_protected_non_loop_device_true_test(
	struct kunit *test)
{
	const char target_name[] = "verity";
	struct file *p_file = create_file_obj(test);
	struct mapped_device *md = create_mapped_device_obj(test, !0, "dm-xxx");
	struct fake_dm_table {} *fake_table = NEW(test, struct fake_dm_table);
	struct dm_target *target = NEW(test, struct dm_target);

	target->type = NEW(test, struct target_type);
	target->type->name = target_name;

	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_md(any(test))),
		ptr_return(test, md));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_get_live_table(
		any(test), any(test))),
		ptr_return(test, fake_table));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_mode(any(test))),
		int_return(test, 1)); // return any value <= 1
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_table_get_num_targets(any(test))),
		int_return(test, 1)); // any value equal to 1
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_table_get_target(
		any(test), int_eq(test, 0))),
		ptr_return(test, target));
	KunitReturns(KUNIT_EXPECT_CALL(call_dm_put_live_table(
		ptr_eq(test, md), any(test))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(
		call_dm_put(ptr_eq(test, md))), int_return(test, 0));

	KUNIT_EXPECT_TRUE(test, five_is_dmverity_protected(p_file));
}

static struct kunit_case five_dmverity_test_cases[] = {
	KUNIT_CASE(five_dmverity_is_loop_device_null_inode_test),
	KUNIT_CASE(five_dmverity_is_loop_device_null_sb_test),
	KUNIT_CASE(five_dmverity_is_loop_device_wrong_s_dev_test),
	KUNIT_CASE(five_dmverity_is_loop_device_correct_s_dev_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_null_inode_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_null_sb_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_null_md_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_null_disc_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_not_ro_disc_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_bad_prefix_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_no_table_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_not_ro_table_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_no_target_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_not_single_target_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_no_target_name_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_verity_test),
	KUNIT_CASE(five_dmverity_is_dmverity_partition_verity_fec_test),
	KUNIT_CASE(five_dmverity_is_dmverity_loop_wrong_bdev_test),
	KUNIT_CASE(five_dmverity_is_dmverity_loop_wrong_bd_dev_test),
	KUNIT_CASE(five_dmverity_is_dmverity_loop_null_bd_disk_test),
	KUNIT_CASE(five_dmverity_is_dmverity_loop_null_private_data_test),
	KUNIT_CASE(five_dmverity_is_dmverity_loop_null_back_file_test),
	KUNIT_CASE(five_dmverity_is_dmverity_loop_correct_back_file_test),
	KUNIT_CASE(five_dmverity_is_dmverity_protected_null_file_test),
#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP) || defined(CONFIG_FIVE_DEBUG)
	KUNIT_CASE(five_check_prebuilt_paths_false_test),
	KUNIT_CASE(five_check_prebuilt_paths_true_test),
#endif
	KUNIT_CASE(five_dmverity_is_dmverity_protected_loop_device_test),
	KUNIT_CASE(five_dmvrt_is_dmverity_protected_non_loop_device_false_test),
	KUNIT_CASE(five_dmvrt_is_dmverity_protected_non_loop_device_true_test),
	{},
};

static int five_dmverity_test_init(struct kunit *test)
{
	return 0;
}

static void five_dmverity_test_exit(struct kunit *test)
{
	return;
}

static struct kunit_suite five_dmverity_test_module = {
	.name = "five_dmverity_test",
	.init = five_dmverity_test_init,
	.exit = five_dmverity_test_exit,
	.test_cases = five_dmverity_test_cases,
};

kunit_test_suites(&five_dmverity_test_module);

MODULE_LICENSE("GPL v2");
