/*
 * Copyright (c) 2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/dsms.h>
#include <linux/errno.h>
#include <linux/llist.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "dsms_init.h"
#include "dsms_kernel_api.h"
#include "dsms_netlink.h"
#include "dsms_preboot_buffer.h"

#define MESSAGE_COUNT_LIMIT (50)

struct dsms_message_node {
	struct dsms_message *message;
	struct llist_node llist;
};

__visible_for_testing atomic_t message_counter = ATOMIC_INIT(0);
__visible_for_testing struct llist_head message_list = LLIST_HEAD_INIT(message_list);
__visible_for_testing struct task_struct *sender_thread;

__visible_for_testing struct dsms_message *create_message(const char *feature_code,
							  const char *detail,
							  int64_t value)
{
	size_t len_detail;
	struct dsms_message *message;

	message = kmalloc(sizeof(struct dsms_message), GFP_KERNEL);
	if (!message) {
		DSMS_LOG_ERROR("Message allocation error.");
		return NULL;
	}

	message->feature_code = kmalloc_array(FEATURE_CODE_LENGTH + 1,
					sizeof(char), GFP_KERNEL);
	if (!message->feature_code) {
		DSMS_LOG_ERROR("Feature code allocation error.");
		kfree(message);
		return NULL;
	}
	strncpy(message->feature_code, feature_code, sizeof(char) *
						     FEATURE_CODE_LENGTH);
	message->feature_code[FEATURE_CODE_LENGTH] = '\0';

	len_detail = strnlen(detail, MAX_ALLOWED_DETAIL_LENGTH) + 1;
	message->detail = kmalloc_array(len_detail, sizeof(char), GFP_KERNEL);
	if (!message->detail) {
		DSMS_LOG_ERROR("Detail allocation error.");
		kfree(message->feature_code);
		kfree(message);
		return NULL;
	}
	strncpy(message->detail, detail, len_detail);
	message->detail[len_detail - 1] = '\0';
	message->value = value;

	return message;
}

__visible_for_testing void destroy_message(struct dsms_message *message)
{
	kfree(message->feature_code);
	kfree(message->detail);
	kfree(message);
}

__visible_for_testing struct dsms_message_node *create_node(struct dsms_message *message)
{
	struct dsms_message_node *node;

	node = kmalloc(sizeof(struct dsms_message_node), GFP_KERNEL);
	if (!node) {
		DSMS_LOG_ERROR("Node allocation error.");
		return NULL;
	}

	node->message = message;
	return node;
}

__visible_for_testing void destroy_node(struct dsms_message_node *node)
{
	kfree(node);
}

int dsms_preboot_buffer_add(const char *feature_code,
			    const char *detail, int64_t value)
{
	struct dsms_message *message;
	struct dsms_message_node *node;

	DSMS_LOG_DEBUG("Storing message to preboot buffer.");

	if (!atomic_add_unless(&message_counter, 1, MESSAGE_COUNT_LIMIT)) {
		DSMS_LOG_ERROR("Preboot buffer has reached its limit.");
		return -EBUSY;
	}

	message = create_message(feature_code, detail, value);
	if (!message) {
		atomic_dec(&message_counter);
		return -ENOMEM;
	}

	node = create_node(message);
	if (!node) {
		destroy_message(message);
		atomic_dec(&message_counter);
		return -ENOMEM;
	}

	llist_add(&node->llist, &message_list);

	return 0;
}

__visible_for_testing struct dsms_message *dsms_preboot_buffer_get(void)
{
	struct llist_node *first;
	struct dsms_message_node *node;
	struct dsms_message *message;

	first = llist_del_first(&message_list);
	if (!first)
		return NULL;

	node = llist_entry(first, struct dsms_message_node, llist);
	message = node->message;
	destroy_node(node);

	return message;
}

__visible_for_testing int preboot_sender(void *unused)
{
	int ret;
	size_t len_detail;
	struct dsms_message *message;

	DSMS_LOG_DEBUG("Preboot sender running.");

	while (1) {
		message = dsms_preboot_buffer_get();
		if (!message) {
			DSMS_LOG_DEBUG("Preboot buffer empty.");
			break;
		}

		len_detail = strnlen(message->detail,
				     MAX_ALLOWED_DETAIL_LENGTH);
		DSMS_LOG_DEBUG("Preboot sender message {'%s', '%s' (%zu bytes), %lld}",
			       message->feature_code, message->detail,
			       len_detail, message->value);
		ret = dsms_send_netlink_message(message->feature_code,
						message->detail,
						message->value);
		if (ret < 0)
			DSMS_LOG_ERROR("Preboot sender failed to send a message");

		destroy_message(message);
	}

	DSMS_LOG_DEBUG("Preboot sender exiting.");
	return 0;
}

void wakeup_preboot_sender(void)
{
	wake_up_process(sender_thread);
}

int __kunit_init dsms_preboot_buffer_init(void)
{
	DSMS_LOG_DEBUG("Preboot buffer init.");

	sender_thread = kthread_create(preboot_sender,
				       NULL, "dsms_sender_kthread");
	if (IS_ERR(sender_thread)) {
		DSMS_LOG_ERROR("Preboot sender thread failed.");
		return -1;
	}

	return 0;
}

void __kunit_exit dsms_preboot_buffer_exit(void)
{
	// TODO: The 'sender_thread' must exit before the module exit function
	// returns. Since the module is built-in, the exit function is never
	// called at the moment. However, if it changes to a loadable module
	// that must be guaranteed to occur. For example, by using a completion
	// structure.

	DSMS_LOG_DEBUG("Preboot buffer exit.");
}
