/*
 * FIVE-DSMS integration.
 *
 * Copyright (C) 2020 Samsung Electronics, Inc.
 * Yevgen Kopylov, <y.kopylov@samsung.com>
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

#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/crc16.h>
#include "five.h"

#include "five_testing.h"
#ifndef FIVE_KUNIT_ENABLED
#include <linux/dsms.h>
#include "five_dsms.h"
#endif

#define MESSAGE_BUFFER_SIZE    600
#define MESSAGE_FIVE_INIT_SIZE 32
#define DEFERRED_TIME (1000 * 300)
#define MAX_FIV1_NUM 16
#define MAX_FIV2_NUM 96

#define FIV3_FIRST 1
#define FIV3_FEW   20
#define FIV3_LOT   100

struct sign_err_event {
	char comm[TASK_COMM_LEN];
	int result;
	int count;
};

static struct five_dsms_report_context {
	struct delayed_work work;
	char message[MESSAGE_FIVE_INIT_SIZE];
} context;

static DEFINE_SPINLOCK(five_dsms_lock);
static struct sign_err_event sign_err_events[MAX_FIV1_NUM];
static bool fiv3_overflow;
static DECLARE_BITMAP(mask, MAX_FIV2_NUM);
static bool oem_unlocking_state __ro_after_init;

static int __init verifiedboot_state_setup(char *str)
{
	static const char unlocked[] = "orange";

	oem_unlocking_state = !strncmp(str, unlocked, sizeof(unlocked));

	if (oem_unlocking_state)
		pr_err("FIVE: Device is unlocked\n");

	return 0;
}

__setup("androidboot.verifiedbootstate=", verifiedboot_state_setup);

// proxy to call kernel func
u16 __mockable call_crc16(u16 crc, u8 const *buffer, size_t len)
{
	return crc16(crc, buffer, len);
}

/*`noinline` is required by DSMS.
 * Don't rename this function. File_name/function_name
 * is used by DSMS in dsms_whitelist as an access rule.
 */
noinline void __mockable five_dsms_msg(const char *tag, const char *msg)
{
	int ret;

	ret = dsms_send_message(tag, msg, 0);
	if (ret)
		pr_err("FIVE: unable to send dsms message(result:%d)\n", ret);
}

static void five_dsms_init_report(struct work_struct *in_data)
{
	struct five_dsms_report_context *context = container_of(in_data,
			struct five_dsms_report_context, work.work);

	five_dsms_msg("FIV0", context->message);
}

void five_dsms_sign_err(const char *app, int result)
{
	int i, current_count;
	struct sign_err_event *same_event = NULL;
	char dsms_msg[MESSAGE_BUFFER_SIZE];
	bool send_overflow = false;

	spin_lock(&five_dsms_lock);
	for (i = 0; i < MAX_FIV1_NUM; i++) {
		if (sign_err_events[i].count == 0) {
			same_event = &sign_err_events[i];
			current_count = ++same_event->count;
			strlcpy(same_event->comm, app, TASK_COMM_LEN);
			same_event->result = result;
			break;
		} else if (sign_err_events[i].result == result &&
			!strncmp(sign_err_events[i].comm, app, TASK_COMM_LEN)) {
			same_event = &sign_err_events[i];
			current_count = ++same_event->count;
			break;
		}
	}
	if (!same_event && !fiv3_overflow) {
		fiv3_overflow = true;
		send_overflow = true;
	}
	spin_unlock(&five_dsms_lock);

	if (same_event) {
		switch (current_count) {
		case FIV3_FIRST:
		case FIV3_FEW:
		case FIV3_LOT:
			snprintf(dsms_msg, MESSAGE_BUFFER_SIZE,
				"%s res = %d count = %d", same_event->comm,
				same_event->result, current_count);
			five_dsms_msg("FIV3", dsms_msg);
		}
	} else if (unlikely(send_overflow)) {
		five_dsms_msg("FIV3", "data buffer overflow");
	}
}

void five_dsms_reset_integrity(const char *task_name, int result,
					const char *file_name)
{
	char dsms_msg[MESSAGE_BUFFER_SIZE];
	unsigned short crc;
	int msg_size;
	bool sent = true;

	if (oem_unlocking_state)
		return;

	msg_size = snprintf(dsms_msg, MESSAGE_BUFFER_SIZE, "%s|%d|%s",
		task_name, result, file_name ? kbasename(file_name) : "");

	if (unlikely(msg_size < 0)) {
		pr_err("FIVE: unable to create dsms message from task_name: %s, result: %d, file_name: %s\n",
			task_name, result, file_name);
		return;
	}
	if (unlikely(msg_size >= MESSAGE_BUFFER_SIZE)) {
		pr_warn("FIVE: dsms message size: %d exceeds max buffer size: %d. The tail was truncated! Resulting message is: %s\n",
			msg_size, MESSAGE_BUFFER_SIZE, dsms_msg);
		msg_size = MESSAGE_BUFFER_SIZE - 1;
	}
	crc = call_crc16(0, dsms_msg, msg_size) % MAX_FIV2_NUM;

	spin_lock(&five_dsms_lock);
	if (!test_bit(crc, mask)) {
		sent = false;
		set_bit(crc, mask);
	}
	spin_unlock(&five_dsms_lock);

	if (!sent)
		five_dsms_msg("FIV2", dsms_msg);

	return;
}

void five_dsms_init(const char *version, int result)
{
	snprintf(context.message, MESSAGE_FIVE_INIT_SIZE, "%s", version);
	INIT_DELAYED_WORK(&context.work, five_dsms_init_report);
	schedule_delayed_work(&context.work, msecs_to_jiffies(DEFERRED_TIME));
}
