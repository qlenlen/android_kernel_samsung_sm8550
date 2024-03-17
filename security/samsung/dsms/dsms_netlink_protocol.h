/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DSMS_NETLINK_PROTOCOL_H
#define _DSMS_NETLINK_PROTOCOL_H

#define DSMS_FAMILY "DSMS Family"
#define DSMS_GROUP "DSMS Group"

// Creation of dsms operation for the generic netlink communication
enum dsms_operations {
	DSMS_MSG_CMD,
};

// Creation of dsms attributes ids for the dsms netlink policy
enum dsms_attribute_ids {
	/* Numbering must start from 1 */
	DSMS_VALUE = 1,
	DSMS_FEATURE_CODE,
	DSMS_DETAIL,
	DSMS_DAEMON_READY,
	DSMS_ATTR_COUNT,
#define DSMS_ATTR_MAX (DSMS_ATTR_COUNT - 1)
};

#endif /* _DSMS_NETLINK_PROTOCOL_H */
