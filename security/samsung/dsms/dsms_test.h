/*
 * Copyright (c) 2020-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DSMS_TEST_H
#define _DSMS_TEST_H

/* -------------------------------------------------------------------------- */
/* macros to allow testing static functions and initialization code */
/* -------------------------------------------------------------------------- */

#if defined(DSMS_KUNIT_ENABLED)

#define __kunit_init
#define __kunit_exit

#else

#define __visible_for_testing static
#define __kunit_init __init
#define __kunit_exit __init

#endif /* defined(DSMS_KUNIT_ENABLED) */

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* Functions exported for each module (using __visible_for_testing) */
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

#if defined(DSMS_KUNIT_ENABLED)

#include <kunit/mock.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/types.h>

/* -------------------------------------------------------------------------- */
/* kmalloc and kmalloc_array mock */
/* -------------------------------------------------------------------------- */

extern void *security_dsms_test_kmalloc_mock(size_t size, gfp_t flags);
extern void *security_dsms_test_kmalloc_array_mock(size_t n, size_t size, gfp_t flags);

#define kmalloc security_dsms_test_kmalloc_mock
#define kmalloc_array security_dsms_test_kmalloc_array_mock

/* -------------------------------------------------------------------------- */
/* dsms_access_control */
/* -------------------------------------------------------------------------- */

struct dsms_policy_entry;

extern int compare_policy_entries(const void *function_name, const void *entry);
extern struct dsms_policy_entry *find_policy_entry(const char *function_name);

/* -------------------------------------------------------------------------- */
/* dsms_init */
/* -------------------------------------------------------------------------- */

extern int __kunit_init dsms_init(void);
extern void __kunit_exit dsms_exit(void);

/* -------------------------------------------------------------------------- */
/* dsms_netlink */
/* -------------------------------------------------------------------------- */

extern atomic_t daemon_ready;
extern int dsms_send_netlink_message(const char *feature_code,
				     const char *detail,
				     int64_t value);

/* -------------------------------------------------------------------------- */
/* dsms_preboot_buffer */
/* -------------------------------------------------------------------------- */

struct dsms_message;
extern atomic_t message_counter;
extern struct task_struct *sender_thread;
extern struct dsms_message *create_message(const char *feature_code,
					   const char *detail,
					   int64_t value);
extern void destroy_message(struct dsms_message *message);
extern struct dsms_message_node *create_node(struct dsms_message *message);
extern void destroy_node(struct dsms_message_node *node);
extern struct dsms_message *dsms_preboot_buffer_get(void);

/* -------------------------------------------------------------------------- */
/* dsms_rate_limit */
/* -------------------------------------------------------------------------- */

extern int dsms_message_count;
extern u64 dsms_round_start_ms;

extern int dsms_get_max_messages_per_round(void);
extern u64 round_end_ms(u64 round_start_ms);
extern int is_new_round(u64 now_ms, u64 last_round_start_ms);
extern u64 dsms_get_time_ms(void);

#endif /* !defined(DSMS_KUNIT_ENABLED) */
#endif /* _DSMS_TEST_H */
