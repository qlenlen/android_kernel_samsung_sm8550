/*
 * Copyright (c) 2020-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DSMS_NETLINK_H
#define _DSMS_NETLINK_H

#include "dsms_test.h"

extern int __kunit_init dsms_netlink_init(void);
extern void __kunit_exit dsms_netlink_exit(void);
extern int dsms_daemon_ready(void);
extern int dsms_send_netlink_message(const char *feature_code,
				     const char *detail,
				     int64_t value);

#endif /* _DSMS_NETLINK_H */
