/*
 * drivers/staging/android/monitor.c
 *
 *  Copyright (C) 2022 Samsung Electronics
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kobject.h>
#include <linux/syscalls.h>
#include <linux/monitor.h>
#include <linux/delay.h>

struct kobject *monitor_kobj;

/* within 1 second ,if thread's binder times >threhold,will throttle it */
static int threhold = 200;
static int recovery = 50;
static int sleep_time = 5;

/*thread info*/
static int enable_tid = -1;
static int enable_code = 0;

static unsigned long start_jiffy = 0;
static int tran_count = 0;
static int throttle = 0;


int binder_monitor(int from_pid, int from_tid, unsigned int code, int target_pid)
{

	if (enable_tid <= 0)
		return 0;

	if ((enable_tid == from_tid && enable_code == code) || (enable_tid == from_pid && enable_code == -1)) {

		if (tran_count == 0)
			start_jiffy = jiffies;

		tran_count++;

		// If eable_code==-1 ,count the number of binder calls about 5 seconds
		if (enable_code == -1) {

			if (time_after(jiffies, start_jiffy + 5*HZ))
				enable_tid = 0;

			return 0;
		}

		if (throttle) {

			msleep(sleep_time);

			if (tran_count >= recovery) {
				/*
				 * after throttle binder by sleep 5ms, max binder call is 200times one second.
				 * so if lower 50times one second, we consider binder call became normal.
				 */
				if (time_after(jiffies, start_jiffy + HZ)) {
					throttle = 0;
					printk("iaft binder became normal,pid=%d tid=%d\n", from_pid, enable_tid);
				}

				tran_count = 0;
			}

		} else {

			if (tran_count >= threhold) {
				if (time_before(jiffies, start_jiffy + HZ)) {
					throttle = 1;
						printk("iaft binder_throttle ,pid=%d tid=%d\n", from_pid, enable_tid);
					}
					tran_count = 0;
			}

		}

	}
	return 0;
}

static ssize_t sleep_time_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{

	return sprintf(buf, "%d\n", sleep_time);
}

static ssize_t sleep_time_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t n)
{

	int val;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	sleep_time = val;
	return n;
}

binder_monitor_attr(sleep_time);


static ssize_t enable_tid_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%d\n", enable_tid);
}

static ssize_t enable_tid_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t n)
{
	int val;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	enable_tid = val;
	tran_count = throttle = 0;
	printk("iaft enable_tid:%d\n", enable_tid);
	return n;
}

binder_monitor_attr(enable_tid);

static ssize_t enable_code_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	if (tran_count > 0 && enable_code == -1)
		return sprintf(buf, "%d\n", tran_count);
	else
		return sprintf(buf, "%d\n", enable_code);
}

static ssize_t enable_code_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t n)
{
	int val;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	enable_code = val;
	tran_count = throttle = 0;
	printk("iaft enable_code:%d\n", enable_code);
	return n;
}

binder_monitor_attr(enable_code);

static ssize_t debug_threhold_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%d\n", threhold);
}

static ssize_t debug_threhold_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t n)
{
	int val;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	threhold = val;
	printk("iaft threhold:%d\n", threhold);
	return n;
}

binder_monitor_attr(debug_threhold);

static ssize_t debug_recovery_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%d\n", recovery);
}

static ssize_t debug_recovery_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t n)
{
	int val;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	recovery = val;
	printk("iaft recovery:%d\n", recovery);
	return n;
}

binder_monitor_attr(debug_recovery);

static struct attribute *g[] = {
	&sleep_time_attr.attr,
	&enable_tid_attr.attr,
	&enable_code_attr.attr,
	&debug_threhold_attr.attr,
	&debug_recovery_attr.attr,
	NULL,
};

static const struct attribute_group attr_group = {
	.attrs = g,
};

static const struct attribute_group *attr_groups[] = {
	&attr_group,
	NULL,
};


static int __init kmonitor_init(void)
{
	int error;

	monitor_kobj = kobject_create_and_add("iaft", power_kobj);
	if (!monitor_kobj)
		return -ENOMEM;

	error = sysfs_create_groups(monitor_kobj, attr_groups);
	if (error)
		return error;

	tran_count = throttle = 0;
	return 0;
}
static void __exit kmonitor_exit(void)
{
	//
}
module_init(kmonitor_init);
module_exit(kmonitor_exit);

MODULE_LICENSE("GPL");
