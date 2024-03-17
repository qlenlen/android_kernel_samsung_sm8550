/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/dsms.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "dsms_access_control.h"
#include "dsms_init.h"
#include "dsms_kernel_api.h"
#include "dsms_netlink.h"
#include "dsms_preboot_buffer.h"
#include "dsms_rate_limit.h"
#include "dsms_test.h"

noinline int dsms_send_message(const char *feature_code,
		const char *detail,
		int64_t value)
{
	int ret;
	size_t len;
	void *address;

	if (!feature_code) {
		DSMS_LOG_ERROR("Invalid feature code.");
		ret = -EINVAL;
		goto exit_send;
	}

	if (!detail)
		detail = "";

	len = strnlen(detail, MAX_ALLOWED_DETAIL_LENGTH);
	DSMS_LOG_DEBUG("{'%s', '%s' (%zu bytes), %lld}",
		       feature_code, detail, len, value);

	if (!dsms_is_initialized()) {
		DSMS_LOG_ERROR("DSMS not initialized yet.");
		ret = -EACCES;
		goto exit_send;
	}

	ret = dsms_check_message_rate_limit();
	if (ret != DSMS_SUCCESS)
		goto exit_send;

	address = __builtin_return_address(CALLER_FRAME);
	ret = dsms_verify_access(address);
	if (ret != DSMS_SUCCESS)
		goto exit_send;

	if (dsms_daemon_ready()) {
		ret = dsms_send_netlink_message(feature_code, detail, value);
	} else {
		ret = dsms_preboot_buffer_add(feature_code, detail, value);
	}

exit_send:
	return ret;
}
