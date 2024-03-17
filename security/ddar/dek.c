/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *
 * Sensitive Data Protection
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/random.h>
#include <linux/err.h>
#include <ddar/dek_common.h>

#define DEK_LOG_COUNT		100
#define DEK_LOG_BUF_SIZE	1024
#define LOG_ENTRY_BUF_SIZE	512

/* Log buffer */
struct log_struct {
	int len;
	char buf[DEK_LOG_BUF_SIZE];
	struct list_head list;
	spinlock_t list_lock;
};
struct log_struct log_buffer;
static int log_count;

/* Wait queue */
wait_queue_head_t wq;
static int flag;

static struct workqueue_struct *queue_log_workqueue;
typedef struct __log_entry_t {
	int engineId;
	char buffer[LOG_ENTRY_BUF_SIZE];
	struct work_struct work;
} log_entry_t;

#if DEK_DEBUG
void hex_key_dump(const char *tag, uint8_t *data, size_t data_len)
{
	static const char *hex = "0123456789ABCDEF";
	static const char delimiter = ' ';
	int i;
	char *buf;
	size_t buf_len;

	if (tag == NULL || data == NULL || data_len <= 0) {
		return;
	}

	buf_len = data_len * 3;
	buf = (char *)kmalloc(buf_len, GFP_ATOMIC);
	if (buf == NULL) {
		return;
	}
	for (i = 0 ; i < data_len ; i++) {
		buf[i*3 + 0] = hex[(data[i] >> 4) & 0x0F];
		buf[i*3 + 1] = hex[(data[i]) & 0x0F];
		buf[i*3 + 2] = delimiter;
	}
	buf[buf_len - 1] = '\0';
	printk(KERN_ERR
		"[%s] %s(len=%zu) : %s\n", "DEK_DBG", tag, data_len, buf);
	kfree(buf);
}
#endif

static int dek_open_log(struct inode *inode, struct file *file)
{
	DEK_LOGD("dek_open_log\n");
	return 0;
}

static int dek_release_log(struct inode *ignored, struct file *file)
{
	DEK_LOGD("dek_release_log\n");
	return 0;
}

static ssize_t dek_read_log(struct file *file, char __user *buffer, size_t len, loff_t *off)
{
	int ret = 0;
	struct log_struct *tmp = NULL;
	char log_buf[DEK_LOG_BUF_SIZE];
	int log_buf_len;

	if (list_empty(&log_buffer.list)) {
		DEK_LOGD("process %i (%s) going to sleep\n",
				current->pid, current->comm);
		flag = 0;
		wait_event_interruptible(wq, flag != 0);

	}
	flag = 0;

	spin_lock(&log_buffer.list_lock);
	if (!list_empty(&log_buffer.list)) {
		tmp = list_first_entry(&log_buffer.list, struct log_struct, list);
		memcpy(&log_buf, tmp->buf, tmp->len);
		log_buf_len = tmp->len;
		list_del(&tmp->list);
		kfree(tmp);
		log_count--;
		spin_unlock(&log_buffer.list_lock);

		ret = copy_to_user(buffer, log_buf, log_buf_len);
		if (ret) {
			DEK_LOGE("dek_read_log, copy_to_user fail, ret=%d, len=%d\n",
					ret, log_buf_len);
			return -EFAULT;
		}
		len = log_buf_len;
		*off = log_buf_len;
	} else {
		spin_unlock(&log_buffer.list_lock);
		DEK_LOGD("dek_read_log, list empty\n");
		len = 0;
	}

	return len;
}

void queue_log_work(struct work_struct *log_work)
{
	log_entry_t *logStruct = container_of(log_work, log_entry_t, work);
	int engine_id = logStruct->engineId;
	char *buffer = logStruct->buffer;
	struct timespec64 ts;
	struct log_struct *tmp = (struct log_struct *)kmalloc(sizeof(struct log_struct), GFP_KERNEL);

	if (tmp) {
		INIT_LIST_HEAD(&tmp->list);

		ktime_get_real_ts64(&ts);
		tmp->len = sprintf(tmp->buf, "%ld.%.3ld|%d|%s|%d|%s\n",
				(long)ts.tv_sec,
				(long)ts.tv_nsec / 1000000,
				current->pid,
				current->comm,
				engine_id,
				buffer);

		spin_lock(&log_buffer.list_lock);
		list_add_tail(&(tmp->list), &(log_buffer.list));
		log_count++;
		if (log_count > DEK_LOG_COUNT) {
			DEK_LOGD("dek_add_to_log - exceeded DEK_LOG_COUNT\n");
			tmp = list_first_entry(&log_buffer.list, struct log_struct, list);
			list_del(&tmp->list);
			kfree(tmp);
			log_count--;
		}
		spin_unlock(&log_buffer.list_lock);

		DEK_LOGD("process %i (%s) awakening the readers, log_count=%d\n",
				current->pid, current->comm, log_count);
		flag = 1;
		wake_up_interruptible(&wq);
	} else {
		DEK_LOGE("dek_add_to_log - failed to allocate buffer\n");
	}

	kfree(logStruct);
}

void dek_add_to_log(int engine_id, char *buffer)
{
	log_entry_t *temp = (log_entry_t *)kmalloc(sizeof(log_entry_t), GFP_ATOMIC);
	int len;
	if (!temp) {
		DEK_LOGE("failed to allocate memory for log entry\n");
		return;
	}
	temp->engineId = engine_id;
	len = (strlen(buffer) > LOG_ENTRY_BUF_SIZE) ? (LOG_ENTRY_BUF_SIZE - 1) : strlen(buffer);
	memcpy(temp->buffer, buffer, len);
	temp->buffer[len] = '\0';
	INIT_WORK(&temp->work, queue_log_work);
	queue_work(queue_log_workqueue, &temp->work);
}

const struct file_operations dek_fops_log = {
		.owner = THIS_MODULE,
		.open = dek_open_log,
		.release = dek_release_log,
		.read = dek_read_log,
};

static struct miscdevice dek_misc_log = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "dek_log",
		.fops = &dek_fops_log,
};

static int __init dek_init(void)
{
	int ret;

	ret = misc_register(&dek_misc_log);
	if (unlikely(ret)) {
		DEK_LOGE("failed to register misc_log device!\n");
		return ret;
	}

	ret = dek_create_sysfs_key_dump(dek_misc_log.this_device);
	if (unlikely(ret)) {
		DEK_LOGE("failed to create sysfs_key_dump device!\n");
		return ret;
	}

	queue_log_workqueue = alloc_workqueue("queue_log_workqueue", WQ_HIGHPRI, 0);
	if (!queue_log_workqueue) {
		DEK_LOGE("failed to allocate queue_log_workqueue\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&log_buffer.list);
	spin_lock_init(&log_buffer.list_lock);
	init_waitqueue_head(&wq);

	printk("dek: initialized\n");
	dek_add_to_log(000, "Initialized");

#ifdef CONFIG_FSCRYPT_SDP
	fscrypt_sdp_cache_init();
#endif

	return 0;
}

static void __exit dek_exit(void)
{
	printk("dek: unloaded\n");
}

module_init(dek_init)
module_exit(dek_exit)

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SDP DEK");
