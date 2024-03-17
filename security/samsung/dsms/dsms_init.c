/*
 * Copyright (c) 2018-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/module.h>
#include "dsms_init.h"
#include "dsms_kernel_api.h"
#include "dsms_netlink.h"
#include "dsms_preboot_buffer.h"
#include "dsms_rate_limit.h"
#include "dsms_test.h"

static int is_dsms_initialized_flag = false;

int dsms_is_initialized(void)
{
	return is_dsms_initialized_flag;
}

__visible_for_testing int __kunit_init dsms_init(void)
{
	int ret = 0;

	DSMS_LOG_DEBUG("Starting.");
	if (is_dsms_initialized_flag) {
		DSMS_LOG_ERROR("Reinitialization attempt ignored.");
		goto exit_ret;
	}
	ret = dsms_rate_limit_init();
	if (ret != 0)
		goto exit_ret;
	ret = dsms_netlink_init();
	if (ret != 0)
		goto exit_rate_limit;
	ret = dsms_preboot_buffer_init();
	if (ret != 0)
		goto exit_netlink;
	is_dsms_initialized_flag = true;
	goto exit_ret;
exit_netlink:
	dsms_netlink_exit();
exit_rate_limit:
	dsms_rate_limit_exit();
exit_ret:
	if (ret == 0)
		DSMS_LOG_INFO("Started.");
	else
		DSMS_LOG_ERROR("Failed to start.");
	return ret;
}

__visible_for_testing void __kunit_exit dsms_exit(void)
{
	DSMS_LOG_DEBUG("Exiting.");
	if (is_dsms_initialized_flag) {
		is_dsms_initialized_flag = false;
		dsms_preboot_buffer_exit();
		dsms_netlink_exit();
		dsms_rate_limit_exit();
	}
	DSMS_LOG_INFO("Exited.");
}

module_init(dsms_init);
module_exit(dsms_exit);
