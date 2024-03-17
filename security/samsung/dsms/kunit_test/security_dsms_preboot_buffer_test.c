/*
 * Copyright (c) 2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/mock.h>
#include <kunit/test.h>
#include <linux/dsms.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "dsms_kernel_api.h"
#include "dsms_preboot_buffer.h"
#include "dsms_test.h"
#include "dsms_test_utils.h"

#define MESSAGE_COUNT_LIMIT (50)

struct dsms_message_node {
	struct dsms_message *message;
	struct llist_node llist;
};

/* ------------------------------------------------------------------------- */
/* Module test functions                                                     */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* File: dsms_preboot_buffer.c                                               */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Function to be tested: create_message                                     */
/* ------------------------------------------------------------------------- */

/*
 * create_message_test()
 * Create a dsms message and check if correct values are set.
 * Expected: Dsms message should be allocated and parameters correctly set.
 */
static void security_dsms_create_message_success_test(struct kunit *test)
{
	struct dsms_message *message;

	message = create_message("KATC", "kunit test", 0);
	KUNIT_EXPECT_PTR_NE(test, message, (struct dsms_message *)NULL);
	if (message != NULL) {
		KUNIT_EXPECT_STREQ(test, message->feature_code, "KATC");
		KUNIT_EXPECT_STREQ(test, message->detail, "kunit test");
		KUNIT_EXPECT_EQ(test, message->value, (long long)0);
		destroy_message(message);
	}
}

/*
 * create_message_memory_error_test()
 * Trigger memory error case when allocating the dsms message struct.
 * Expected: Function should return NULL.
 */
static void security_dsms_create_message_memory_error_test(struct kunit *test)
{
	struct dsms_message *message;

	security_dsms_test_request_kmalloc_fail_at(1);
	message = create_message("KATM", "kunit test", 0);
	security_dsms_test_cancel_kmalloc_fail_requests();
	KUNIT_EXPECT_PTR_EQ(test, message, (struct dsms_message *)NULL);
	if (message != NULL)
		destroy_message(message);
}

/*
 * create_message_feature_code_memory_error_test()
 * Trigger memory error case when allocating the feature code.
 * Expected: Function should return NULL.
 */
static void security_dsms_create_message_feature_code_memory_error_test(
				struct kunit *test)
{
	struct dsms_message *message;

	security_dsms_test_request_kmalloc_fail_at(2);
	message = create_message("KATF", "kunit test", 0);
	security_dsms_test_cancel_kmalloc_fail_requests();
	KUNIT_EXPECT_PTR_EQ(test, message, (struct dsms_message *)NULL);
	if (message != NULL)
		destroy_message(message);
}

/*
 * create_message_detail_memory_error_test()
 * Trigger memory error case when allocating the detail.
 * Expected: Function should return NULL.
 */
static void security_dsms_create_message_detail_memory_error_test(
				struct kunit *test)
{
	struct dsms_message *message;

	security_dsms_test_request_kmalloc_fail_at(3);
	message = create_message("KATD", "kunit test", 0);
	security_dsms_test_cancel_kmalloc_fail_requests();
	KUNIT_EXPECT_PTR_EQ(test, message, (struct dsms_message *)NULL);
	if (message != NULL)
		destroy_message(message);
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: create_node                                        */
/* ------------------------------------------------------------------------- */

/*
 * security_dsms_create_node_success_test()
 * Create a node and check if correct values are set.
 * Expected: node should be allocated and parameters correctly set.
 */
static void security_dsms_create_node_success_test(struct kunit *test)
{
	struct dsms_message *message;
	struct dsms_message_node *node;

	message = create_message("KATC", "kunit test", 0);
	KUNIT_EXPECT_PTR_NE(test, message, (struct dsms_message *)NULL);
	if (message != NULL) {
		node = create_node(message);
		KUNIT_EXPECT_PTR_NE(test, node, (struct dsms_message_node *)NULL);
		if (node != NULL) {
			KUNIT_EXPECT_PTR_EQ(test, node->message, message);
			KUNIT_EXPECT_STREQ(test, node->message->feature_code, "KATC");
			KUNIT_EXPECT_STREQ(test, node->message->detail, "kunit test");
			KUNIT_EXPECT_EQ(test, node->message->value, (long long)0);
			destroy_node(node);
		}
		destroy_message(message);
	}
}

/*
 * security_dsms_create_node_fail_test()
 * Trigger memory error case when allocating the node struct.
 * Expected: Function should return NULL.
 */
static void security_dsms_create_node_fail_test(struct kunit *test)
{
	struct dsms_message *message;
	struct dsms_message_node *node;

	message = create_message("KATC", "kunit test", 0);
	KUNIT_EXPECT_PTR_NE(test, message, (struct dsms_message *)NULL);
	if (message != NULL) {
		security_dsms_test_request_kmalloc_fail_at(1);
		node = create_node(message);
		security_dsms_test_cancel_kmalloc_fail_requests();
		KUNIT_EXPECT_PTR_EQ(test, node, (struct dsms_message_node *)NULL);
		if (node != NULL)
			destroy_node(node);
		destroy_message(message);
	}
}

/* ------------------------------------------------------------------------- */
/* Function to be tested: dsms_preboot_buffer_add                            */
/* ------------------------------------------------------------------------- */

/*
 * security_dsms_preboot_buffer_add_success_test()
 * Add to preboot buffer and check if correct value is returned.
 * Expected: Success should return 0.
 */
static void security_dsms_preboot_buffer_add_success_test(struct kunit *test)
{
	int ret;

	ret = dsms_preboot_buffer_add("KATC", "kunit test", 0);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * security_dsms_preboot_buffer_add_count_error_test()
 * Trigger count during add to preboot buffer.
 * Expected: Count error should return -EBUSY.
 */
static void security_dsms_preboot_buffer_add_count_error_test(struct kunit *test)
{
	int ret;
	int old_message_counter;

	old_message_counter = atomic_read(&message_counter);
	atomic_set(&message_counter, MESSAGE_COUNT_LIMIT);
	ret = dsms_preboot_buffer_add("KATC", "kunit test", 0);
	atomic_set(&message_counter, old_message_counter);
	KUNIT_EXPECT_EQ(test, ret, -EBUSY);
}

/*
 * security_dsms_preboot_buffer_add_message_error_test()
 * Trigger memory error at message allocation during add to preboot buffer.
 * Expected: Error at message allocation should return -ENOMEM.
 */
static void security_dsms_preboot_buffer_add_message_error_test(struct kunit *test)
{
	int ret;

	security_dsms_test_request_kmalloc_fail_at(1);
	ret = dsms_preboot_buffer_add("KATC", "kunit test", 0);
	security_dsms_test_cancel_kmalloc_fail_requests();
	KUNIT_EXPECT_EQ(test, ret, -ENOMEM);
}

/*
 * security_dsms_preboot_buffer_add_node_error_test()
 * Trigger memory error at node allocation during add to preboot buffer.
 * Expected: Error at node allocation should return -ENOMEM.
 */
static void security_dsms_preboot_buffer_add_node_error_test(struct kunit *test)
{
	int ret;

	security_dsms_test_request_kmalloc_fail_at(4);
	ret = dsms_preboot_buffer_add("KATC", "kunit test", 0);
	security_dsms_test_cancel_kmalloc_fail_requests();
	KUNIT_EXPECT_EQ(test, ret, -ENOMEM);
}

/* ------------------------------------------------------------------------- */
/* Module definition                                                         */
/* ------------------------------------------------------------------------- */

static struct kunit_case security_dsms_preboot_buffer_test_cases[] = {
	KUNIT_CASE(security_dsms_create_message_success_test),
	KUNIT_CASE(security_dsms_create_message_memory_error_test),
	KUNIT_CASE(security_dsms_create_message_feature_code_memory_error_test),
	KUNIT_CASE(security_dsms_create_message_detail_memory_error_test),
	KUNIT_CASE(security_dsms_create_node_success_test),
	KUNIT_CASE(security_dsms_create_node_fail_test),
	KUNIT_CASE(security_dsms_preboot_buffer_add_success_test),
	KUNIT_CASE(security_dsms_preboot_buffer_add_count_error_test),
	KUNIT_CASE(security_dsms_preboot_buffer_add_message_error_test),
	KUNIT_CASE(security_dsms_preboot_buffer_add_node_error_test),
	{},
};

static struct kunit_suite security_dsms_preboot_buffer_module = {
	.name = "security-dsms-preboot-buffer",
	.test_cases = security_dsms_preboot_buffer_test_cases,
};
kunit_test_suites(&security_dsms_preboot_buffer_module);
