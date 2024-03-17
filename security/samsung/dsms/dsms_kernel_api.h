/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DSMS_KERNEL_API_H
#define _DSMS_KERNEL_API_H

#define FEATURE_CODE_LENGTH (4)
#define MAX_ALLOWED_DETAIL_LENGTH (1024)

#define DSMS_TAG "[DSMS-KERNEL] "

#define DSMS_LOG_INFO(format, ...) pr_info(DSMS_TAG format, ##__VA_ARGS__)
#define DSMS_LOG_ERROR(format, ...) pr_err(DSMS_TAG format, ##__VA_ARGS__)
#define DSMS_LOG_DEBUG(format, ...) pr_debug(DSMS_TAG format, ##__VA_ARGS__)

struct dsms_message {
	char *feature_code;
	char *detail;
	int64_t value;
};

#endif /* _DSMS_KERNEL_API_H */
