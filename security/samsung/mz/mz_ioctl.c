/*
 * Copyright (c) 2019 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/cdev.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include "mz_internal.h"
#include "mz_log.h"
#include "mz_page.h"

#define MZ_DEV "mz_ioctl"

static struct class *driver_class, *driver_class_old;
static dev_t mz_ioctl_device_no, mz_ioctl_device_no_old;
static struct cdev mz_ioctl_cdev;

__visible_for_testing long mz_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = MZ_SUCCESS;
#ifndef CONFIG_SEC_KUNIT
	vainfo mzvainfo = { 0, 0};

	uint64_t ava, va, ptwi = 0, len;
	uint64_t cur_len;
	unsigned long pfn, old_pfn = 0;
#endif /* CONFIG_SEC_KUNIT */
	struct mm_struct *mm = current->mm;
	pid_t cur_tid = current->pid;
	uint8_t __user *buf;
	uint8_t pname[MAX_PROCESS_NAME] = "";

	if (!mm) {
		MZ_LOG(err_level_error, "%s mm_struct fail\n", __func__);
		ret = MZ_GENERAL_ERROR;
		return ret;
	}

#ifndef CONFIG_SEC_KUNIT
	ret = mz_kget_process_name(current->tgid, pname);
	if (ret != MZ_SUCCESS) {
		MZ_LOG(err_level_error, "%s get name fail %d %d %d\n", __func__, current->tgid, cur_tid, ret);
		return ret;
	}
#endif /* CONFIG_SEC_KUNIT */
	MZ_LOG(err_level_info, "%s start %s %d %d", __func__, pname, current->tgid, cur_tid);

	switch (cmd) {
	case IOCTL_MZ_SET_CMD:
#if IS_ENABLED(CONFIG_MEMORY_ZEROISATION)
#ifndef CONFIG_SEC_KUNIT
		ret = copy_from_user(&mzvainfo, (void *)arg, sizeof(mzvainfo));
		if (ret)
			MZ_LOG(err_level_error, "%s copy from user error\n", __func__);
		else ret=MZ_SUCCESS;

		va = mzvainfo.va;
		len = mzvainfo.len;
		buf = mzvainfo.buf;
#endif /* CONFIG_SEC_KUNIT */

#ifndef CONFIG_SEC_KUNIT
		if (!isaddrset()) {
			ret = set_mz_mem();
			if (ret != MZ_SUCCESS) {
				MZ_LOG(err_level_error, "%s global list set fail %d\n", __func__, ret);
				goto out;
			}
		}

		while (len > 0) {
			ava = va + ptwi;
			pfn = mz_ptw(ava, mm);
			if (pfn == 0) {
				MZ_LOG(err_level_error, "%s mz_ptw fail\n", __func__);
				goto out;
			}

			//pfn should be different from old one in normal case.  It's for checking system error.
			if (old_pfn != pfn) {
				if (PAGE_SIZE - (ava & (PAGE_SIZE - 1)) < len)
					cur_len = (PAGE_SIZE - (ava & (PAGE_SIZE - 1)));
				else
					cur_len = len;

				MZ_LOG(err_level_debug, "%s %d %llx %d %llx %d\n",
						__func__, pfn, va, len, ava, cur_len);

				ret = mz_add_target_pfn(cur_tid, pfn, ava & (PAGE_SIZE - 1), cur_len, ava, buf);
				if (ret != MZ_SUCCESS) {
					MZ_LOG(err_level_error, "%s fail %d\n", __func__, ret);
					goto out;
				}

				len -= cur_len;
				ptwi += cur_len;

				old_pfn = pfn;
			} else {
				MZ_LOG(err_level_debug, "%s recheck %d %llx %d %llx %d\n",
						__func__, pfn, va, len, ava, cur_len);
				ptwi++;
				len--;
			}
		}
#endif /* CONFIG_SEC_KUNIT */
out:
#endif /* IS_ENABLED(CONFIG_MEMORY_ZEROISATION) */
		break;
	case IOCTL_MZ_ALL_SET_CMD:
#if IS_ENABLED(CONFIG_MEMORY_ZEROISATION)
		mz_all_zero_set(cur_tid);
#endif /* IS_ENABLED(CONFIG_MEMORY_ZEROISATION) */
		break;
	default:
		MZ_LOG(err_level_error, "%s unknown cmd\n", __func__);
		ret = MZ_INVALID_INPUT_ERROR;
		break;
	}
	MZ_LOG(err_level_info, "%s end %s %d %d\n", __func__, pname, current->tgid, cur_tid);

	return ret;
}

static const struct file_operations mz_ioctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = mz_ioctl,
	.compat_ioctl = mz_ioctl,
};

#ifdef CONFIG_SEC_KUNIT
int mz_ioctl_init(void)
#else
static int __init mz_ioctl_init(void)
#endif
{
	int rc;
	struct device *class_dev;

	MZ_LOG(err_level_info, "%s mz_ioctl\n", __func__);

	mz_ioctl_device_no_old = mz_ioctl_device_no;
	driver_class_old = driver_class;
	rc = alloc_chrdev_region(&mz_ioctl_device_no, 0, 1, MZ_DEV);
	if (rc < 0) {
		MZ_LOG(err_level_error, "%s alloc_chrdev_region failed %d\n", __func__, rc);
		return rc;
	}

	driver_class = class_create(THIS_MODULE, MZ_DEV);
	if (IS_ERR(driver_class)) {
		rc = -ENOMEM;
		MZ_LOG(err_level_error, "%s class_create failed %d\n", __func__, rc);
		goto unregister_chrdev_region;
	}

	class_dev = device_create(driver_class, NULL, mz_ioctl_device_no, NULL, MZ_DEV);
	if (!class_dev) {
		rc = -ENOMEM;
		MZ_LOG(err_level_error, "%s class_device_create failed %d\n", __func__, rc);
		goto class_destroy;
	}

	cdev_init(&mz_ioctl_cdev, &mz_ioctl_fops);
	mz_ioctl_cdev.owner = THIS_MODULE;

	rc = cdev_add(&mz_ioctl_cdev, MKDEV(MAJOR(mz_ioctl_device_no), 0), 1);
	if (rc < 0) {
		MZ_LOG(err_level_error, "%s cdev_add failed %d\n", __func__, rc);
		goto class_device_destroy;
	}

	mzinit();

	return 0;

class_device_destroy:
	device_destroy(driver_class, mz_ioctl_device_no);
class_destroy:
	class_destroy(driver_class);
unregister_chrdev_region:
	if (driver_class_old != NULL) {
		device_destroy(driver_class_old, mz_ioctl_device_no_old);
		class_destroy(driver_class_old);
		driver_class_old = NULL;
		unregister_chrdev_region(mz_ioctl_device_no_old, 1);
	}
	driver_class = NULL;
	unregister_chrdev_region(mz_ioctl_device_no, 1);
	return rc;
}

#ifdef CONFIG_SEC_KUNIT
void mz_ioctl_exit(void)
#else
static void __exit mz_ioctl_exit(void)
#endif
{
	MZ_LOG(err_level_info, "%s mz_ioctl\n", __func__);
	device_destroy(driver_class, mz_ioctl_device_no);
	class_destroy(driver_class);
	driver_class = NULL;
	unregister_chrdev_region(mz_ioctl_device_no, 1);
}


MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Samsung MZ Driver");
MODULE_VERSION("1.00");

#ifndef CONFIG_SEC_KUNIT
module_init(mz_ioctl_init);
module_exit(mz_ioctl_exit);
#endif /* CONFIG_SEC_KUNIT */



