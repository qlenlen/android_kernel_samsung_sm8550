/*
 * Copyright (c) 2018-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/dsms.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/timekeeping.h>
#include "dsms_kernel_api.h"
#include "dsms_rate_limit.h"
#include "dsms_test.h"

#define ROUND_DURATION_MS ((u64)(1000L))
#define MAX_MESSAGES_PER_ROUND (50)

__visible_for_testing int dsms_message_count;
__visible_for_testing u64 dsms_round_start_ms;

__visible_for_testing int dsms_get_max_messages_per_round(void)
{
	return MAX_MESSAGES_PER_ROUND;
}

__visible_for_testing u64 round_end_ms(u64 round_start_ms)
{
	return round_start_ms + ROUND_DURATION_MS;
}

__visible_for_testing int is_new_round(u64 now_ms, u64 last_round_start_ms)
{
	return now_ms >= round_end_ms(last_round_start_ms);
}

__visible_for_testing u64 dsms_get_time_ms(void)
{
	return div_u64(ktime_get_ns(), NSEC_PER_MSEC);
}

int __kunit_init dsms_rate_limit_init(void)
{
	dsms_message_count = 0;
	dsms_round_start_ms = dsms_get_time_ms();
	DSMS_LOG_DEBUG("[rate limit] INIT dsms_round_start_ms=%llu dsms_message_count=%d",
		dsms_round_start_ms, dsms_message_count);
	return 0;
}

int dsms_check_message_rate_limit(void)
{
	int dropped_messages;
	u64 current_time_ms;

	current_time_ms = dsms_get_time_ms();
	if (current_time_ms < dsms_round_start_ms) {
		DSMS_LOG_DEBUG("[rate limit] RESET current_time_ms=%llu dsms_round_start_ms=%llu dsms_message_count=%d",
			current_time_ms, dsms_round_start_ms, dsms_message_count);
		dsms_round_start_ms = current_time_ms;
		dsms_message_count = 0;
	}

	if (is_new_round(current_time_ms, dsms_round_start_ms)) {
		dropped_messages = dsms_message_count - dsms_get_max_messages_per_round();
		if (dropped_messages > 0)
			DSMS_LOG_ERROR("[rate limit] %d of %d messages dropped", dropped_messages, dsms_message_count);
		dsms_round_start_ms = current_time_ms;
		dsms_message_count = 0;
		return DSMS_SUCCESS;
	}

	if (++dsms_message_count > dsms_get_max_messages_per_round())
		return DSMS_DENY;
	return DSMS_SUCCESS;
}
