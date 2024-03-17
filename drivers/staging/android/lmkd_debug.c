/*
 * Copyright (c) Samsung Technologies Co., Ltd. 2001-2020. All rights reserved.
 *
 * File name: lmkd_debug.c
 * Description: debug for lmkd
 * Author: jiman.kwon@samsung.com
 * Version: 0.1
 * Date:  2020/05/13
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>

#define RET_OK   0
#define RET_ERR  1

static int lmkd_count;
static int lmkd_cricount;

static atomic_t lmkd_debug_init_suc;
static struct proc_dir_entry *lmkd_debug_rootdir;

static ssize_t psi_lmkd_count_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	size_t len;
	char buffer[32];

	len = snprintf(buffer, sizeof(buffer), "%d\n", lmkd_count);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t psi_lmkd_cricount_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	size_t len;
	char buffer[32];

	len = snprintf(buffer, sizeof(buffer), "%d\n", lmkd_cricount);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t psi_lmkd_count_write(struct file *file, const char __user *user_buf,
			    size_t count, loff_t *ppos)
{
	char buffer[32];
	int err;

	memset(buffer, 0, sizeof(buffer));

	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, user_buf, count)) {
		err = -EFAULT;
		return err;
	}

	buffer[count] = '\0';

	err = kstrtoint(strstrip(buffer), 0, &lmkd_count);
	if (err)
		return err;
	if (lmkd_count < 0)
		return -EINVAL;

	return count;
}

static ssize_t psi_lmkd_cricount_write(struct file *file, const char __user *user_buf,
			    size_t count, loff_t *ppos)
{
	char buffer[32];
	int err;

	memset(buffer, 0, sizeof(buffer));

	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, user_buf, count)) {
		err = -EFAULT;
		return err;
	}

	buffer[count] = '\0';

	err = kstrtoint(strstrip(buffer), 0, &lmkd_cricount);
	if (err)
		return err;
	if (lmkd_cricount < 0)
		return -EINVAL;

	return count;
}

static const struct proc_ops psi_lmkd_count_proc_ops = {
	.proc_read           = psi_lmkd_count_read,
	.proc_write          = psi_lmkd_count_write,
	.proc_lseek          = generic_file_llseek,
};

static const struct proc_ops psi_lmkd_cricount_proc_ops = {
	.proc_read           = psi_lmkd_cricount_read,
	.proc_write          = psi_lmkd_cricount_write,
	.proc_lseek          = generic_file_llseek,
};

static int __init klmkd_debug_init(void)
{
	struct proc_dir_entry *lmkd_count_entry = NULL;
	struct proc_dir_entry *lmkd_cricount_entry = NULL;

	lmkd_debug_rootdir = proc_mkdir("lmkd_debug", NULL);
	if (!lmkd_debug_rootdir)
		pr_err("create /proc/lmkd_debug failed\n");
	else {
		lmkd_count_entry = proc_create("lmkd_count", 0644, lmkd_debug_rootdir, &psi_lmkd_count_proc_ops);
		if (!lmkd_count_entry) {
			pr_err("create /proc/lmkd_debug/lmkd_count failed, remove /proc/lmkd_debug dir\n");
			remove_proc_entry("lmkd_debug", NULL);
			lmkd_debug_rootdir = NULL;
		} else {
			lmkd_cricount_entry = proc_create("lmkd_cricount", 0644, lmkd_debug_rootdir, &psi_lmkd_cricount_proc_ops);
			if (!lmkd_cricount_entry) {
				pr_err("create /proc/lmkd_debug/lmkd_cricount failed, remove /proc/lmkd_debug	dir\n");
				remove_proc_entry("lmkd_debug/lmkd_count", NULL);
				remove_proc_entry("lmkd_debug", NULL);
				lmkd_debug_rootdir = NULL;
			}
		}
	}

	atomic_set(&lmkd_debug_init_suc, 1);
	return RET_OK;
}

static void __exit klmkd_debug_exit(void)
{
	if (lmkd_debug_rootdir) {
		remove_proc_entry("lmkd_count", lmkd_debug_rootdir);
		remove_proc_entry("lmkd_cricount", lmkd_debug_rootdir);
		remove_proc_entry("lmkd_debug", NULL);
	}
}

module_init(klmkd_debug_init);
module_exit(klmkd_debug_exit);

MODULE_LICENSE("GPL");
