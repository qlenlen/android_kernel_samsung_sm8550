// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIVE task integrity
 *
 * Copyright (C) 2020 Samsung Electronics, Inc.
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
 * Viacheslav Vovchenko <v.vovchenko@samsung.com>
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
#include <linux/platform_device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/file.h>

#include "task_integrity.h"
#include "five_tint_dev.h"

struct tint_message {
	uint32_t version;
	uint32_t param;
	uint64_t reserved;
	union __packed {
		enum task_integrity_value value;
		struct __packed {
			uint64_t value_ptr;
			uint16_t len_buf;
		} label;
		struct __packed {
			uint64_t i_ino;
			enum task_integrity_reset_cause cause;
			struct __packed {
				uint64_t pathname_ptr;
				uint16_t len_buf;
			} path;
		} reset_file;
		struct __packed {
			uint64_t label_ptr;
		} sign;
	} data;
} __packed;

#define TINT_VERSION 1
#define TINT_DEV		"task_integrity"
#define TINT_IOC_MAGIC		'f'
#define TINT_IOCTL_GET_VALUE \
	_IOWR(TINT_IOC_MAGIC, 1, struct tint_message)
#define TINT_IOCTL_GET_LABEL \
	_IOWR(TINT_IOC_MAGIC, 2, struct tint_message)
#define TINT_IOCTL_GET_RESET_FILE \
	_IOWR(TINT_IOC_MAGIC, 3, struct tint_message)
#define TINT_IOCTL_SIGN_FILE \
	_IOWR(TINT_IOC_MAGIC, 4, struct tint_message)
#define TINT_IOCTL_EDIT_FILE \
	_IOWR(TINT_IOC_MAGIC, 5, struct tint_message)
#define TINT_IOCTL_CLOSE_FILE \
	_IOWR(TINT_IOC_MAGIC, 6, struct tint_message)
#define TINT_IOCTL_VERIFY_SYNC_FILE \
	_IOWR(TINT_IOC_MAGIC, 7, struct tint_message)
#define TINT_IOCTL_VERIFY_ASYNC_FILE \
	_IOWR(TINT_IOC_MAGIC, 8, struct tint_message)

static struct tint_control {
	struct device *pdev;
	struct class *driver_class;
	dev_t device_no;
	struct cdev cdev;
} dev_ctrl;

static struct task_struct *get_task_by_pid(pid_t pid)
{
	struct task_struct *task = NULL;
	struct pid *pid_data;

	pid_data = find_get_pid(pid);
	if (unlikely(!pid_data)) {
		pr_err("FIVE: Can't find PID: %u\n", pid);
		return NULL;
	}

	task = get_pid_task(pid_data, PIDTYPE_PID);
	if (unlikely(!task))
		pr_err("FIVE: Can't find task by PID: %u\n", pid);

	put_pid(pid_data);

	return task;
}

static struct task_struct *get_tint_and_task(pid_t pid)
{
	struct task_struct *task = get_task_by_pid(pid);

	if (!task)
		return NULL;

	task_integrity_get(TASK_INTEGRITY(task));

	return task;
}

static void put_tint_and_task(struct task_struct *task)
{
	if (!task)
		return;

	task_integrity_put(TASK_INTEGRITY(task));
	put_task_struct(task);
}

static int do_command_file(unsigned int cmd, unsigned int fd,
			   struct integrity_label __user *label)
{
	int ret = 0;
	struct file *file;

	file = fget(fd);
	if (!file) {
		pr_err("FIVE: Can't get file struct: %u\n", cmd);
		return -EFAULT;
	}

	switch (cmd) {
	case TINT_IOCTL_SIGN_FILE: {
		ret = five_fcntl_sign(file, label);
		break;
	}
	case TINT_IOCTL_EDIT_FILE: {
		ret = five_fcntl_edit(file);
		break;
	}
	case TINT_IOCTL_CLOSE_FILE: {
		ret = five_fcntl_close(file);
		break;
	}
	case TINT_IOCTL_VERIFY_SYNC_FILE: {
		ret = five_fcntl_verify_sync(file);
		break;
	}
	case TINT_IOCTL_VERIFY_ASYNC_FILE: {
		ret = five_fcntl_verify_async(file);
		break;
	}
	default: {
		pr_err("FIVE: Invalid IOCTL command: %u\n", cmd);
		ret = -ENOIOCTLCMD;
	}
	}

	if (ret)
		pr_err("FIVE: Command failed: %u %d\n", cmd, ret);

	fput(file);

	return ret;
}

static long tint_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct tint_message __user *argp = (void __user *) arg;
	struct task_struct *task;
	struct tint_message msg = {0};

	if (_IOC_TYPE(cmd) != TINT_IOC_MAGIC) {
		pr_err("FIVE: IOCTL type is wrong\n");
		return -ENOTTY;
	}

	ret = copy_from_user(&msg, argp, sizeof(msg));
	if (ret) {
		pr_err("FIVE: copy_from_user failed ret: %ld\n", ret);
		return -EFAULT;
	}

	if (msg.version != TINT_VERSION) {
		pr_err("FIVE: Unsupported protocol version: %u\n", msg.version);
		return -EINVAL;
	}

	switch (cmd) {
	case TINT_IOCTL_GET_VALUE: {
		task = get_tint_and_task(msg.param);
		if (!task) {
			ret = -ESRCH;
			break;
		}

		msg.data.value = task_integrity_user_read(TASK_INTEGRITY(task));

		ret = copy_to_user(
			(void __user *) &argp->data.value, &msg.data.value,
			sizeof(msg.data.value));
		if (unlikely(ret)) {
			pr_err("FIVE: copy_to_user failed: %u %ld\n",
				cmd, ret);
			ret = -EFAULT;
		}

		put_tint_and_task(task);
		break;
	}
	case TINT_IOCTL_GET_LABEL: {
		const struct integrity_label *label;

		task = get_tint_and_task(msg.param);
		if (!task) {
			ret = -ESRCH;
			break;
		}

		spin_lock(&TASK_INTEGRITY(task)->value_lock);
		label = TASK_INTEGRITY(task)->label;
		spin_unlock(&TASK_INTEGRITY(task)->value_lock);

		if (!label) {
			ret = -ENOENT;
			put_tint_and_task(task);
			break;
		}

		if (msg.data.label.len_buf < sizeof(label->len) + label->len) {
			pr_err("FIVE: User buffer is small for label: %u %u",
				cmd, msg.data.label.len_buf);
			ret = -EINVAL;
			put_tint_and_task(task);
			break;
		}

		ret = copy_to_user(
			(void __user *) msg.data.label.value_ptr, label,
			sizeof(label->len) + label->len);
		if (unlikely(ret)) {
			pr_err("FIVE: copy_to_user failed len: %u %ld\n",
				cmd, ret);
			ret = -EFAULT;
		}

		put_tint_and_task(task);
		break;
	}
	case TINT_IOCTL_GET_RESET_FILE: {
		const struct file *reset_file;
		const struct inode *inode;
		uint16_t len_buf;
		char *buf, *pathname;

		task = get_tint_and_task(msg.param);
		if (!task) {
			ret = -ESRCH;
			break;
		}

		reset_file = TASK_INTEGRITY(task)->reset_file;
		if (!reset_file) {
			ret = -ENOENT;
			put_tint_and_task(task);
			break;
		}

		inode = file_inode(reset_file);
		msg.data.reset_file.i_ino = inode->i_ino;
		msg.data.reset_file.cause = TASK_INTEGRITY(task)->reset_cause;
		len_buf = msg.data.reset_file.path.len_buf;

		if (!len_buf || len_buf > PAGE_SIZE) {
			pr_err("FIVE: Bad size of user buffer: %u %u",
				cmd, len_buf);
			ret = -EINVAL;
			put_tint_and_task(task);
			break;
		}

		buf = kmalloc(len_buf, GFP_KERNEL);
		if (unlikely(!buf)) {
			pr_err("FIVE: Can't allocate memory: %u %u",
				cmd, len_buf);
			ret = -ENOMEM;
			put_tint_and_task(task);
			break;
		}

		pathname = d_path(&reset_file->f_path, buf, len_buf);
		if (IS_ERR(pathname)) {
			pr_err("FIVE: Can't obtain path: %u", len_buf);
			ret = -ENOMEM;
			kfree(buf);
			put_tint_and_task(task);
			break;
		}

		len_buf = strnlen(pathname, len_buf) + 1;

		ret = copy_to_user(
			(void __user *) msg.data.reset_file.path.pathname_ptr,
			pathname, len_buf);
		if (unlikely(ret)) {
			pr_err("FIVE: copy_to_user failed path: %u %ld\n",
				cmd, ret);
			ret = -EFAULT;
			kfree(buf);
			put_tint_and_task(task);
			break;
		}

		ret = copy_to_user((void __user *) &argp->data.reset_file,
				   &msg.data.reset_file,
				   sizeof(msg.data.reset_file));

		if (unlikely(ret)) {
			pr_err("FIVE: copy_to_user failed: %u %ld\n",
				cmd, ret);
			ret = -EFAULT;
		}

		kfree(buf);
		put_tint_and_task(task);
		break;
	}
	case TINT_IOCTL_SIGN_FILE:
	case TINT_IOCTL_EDIT_FILE:
	case TINT_IOCTL_CLOSE_FILE:
	case TINT_IOCTL_VERIFY_SYNC_FILE:
	case TINT_IOCTL_VERIFY_ASYNC_FILE: {
		ret = do_command_file(cmd, msg.param,
		(struct integrity_label __user *) msg.data.sign.label_ptr);
		break;
	}
	default: {
		pr_err("FIVE: Invalid IOCTL command: %u\n", cmd);
		ret = -ENOIOCTLCMD;
	}
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static long tint_compact_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	return tint_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

static const struct file_operations tint_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tint_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tint_compact_ioctl,
#endif
};

int __init five_tint_init_dev(void)
{
	int rc = 0;

	rc = alloc_chrdev_region(&dev_ctrl.device_no, 0, 1, TINT_DEV);
	if (unlikely(rc < 0)) {
		pr_err("FIVE: alloc_chrdev_region failed %d\n", rc);
		return rc;
	}

	dev_ctrl.driver_class = class_create(THIS_MODULE, TINT_DEV);
	if (IS_ERR(dev_ctrl.driver_class)) {
		rc = PTR_ERR(dev_ctrl.driver_class);
		pr_err("FIVE: class_create failed %d\n", rc);
		goto exit_unreg_chrdev_region;
	}

	dev_ctrl.pdev = device_create(dev_ctrl.driver_class, NULL,
				      dev_ctrl.device_no, NULL, TINT_DEV);
	if (IS_ERR(dev_ctrl.pdev)) {
		rc = PTR_ERR(dev_ctrl.pdev);
		pr_err("FIVE: class_device_create failed %d\n", rc);
		goto exit_destroy_class;
	}

	cdev_init(&dev_ctrl.cdev, &tint_fops);
	dev_ctrl.cdev.owner = THIS_MODULE;

	rc = cdev_add(&dev_ctrl.cdev,
		      MKDEV(MAJOR(dev_ctrl.device_no), 0), 1);
	if (unlikely(rc < 0)) {
		pr_err("FIVE: cdev_add failed %d\n", rc);
		goto exit_destroy_device;
	}

	return 0;

exit_destroy_device:
	device_destroy(dev_ctrl.driver_class, dev_ctrl.device_no);
exit_destroy_class:
	class_destroy(dev_ctrl.driver_class);
exit_unreg_chrdev_region:
	unregister_chrdev_region(dev_ctrl.device_no, 1);

	return rc;
}

void __exit five_tint_deinit_dev(void)
{
	cdev_del(&dev_ctrl.cdev);
	device_destroy(dev_ctrl.driver_class, dev_ctrl.device_no);
	class_destroy(dev_ctrl.driver_class);
	unregister_chrdev_region(dev_ctrl.device_no, 1);
}
