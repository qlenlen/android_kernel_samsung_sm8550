/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/dsms.h>
#include "dsms_access_control.h"

// Policy entries *MUST BE* ordered by function_name field, as the find
// function uses binary search to find the function entry in the policy table.

// vvvvv DO NOT CHANGE THESE LINES! vvvvv
struct dsms_policy_entry dsms_policy[] = {
{ "security/samsung/defex_lsm/core/defex_main.c", "defex_report_violation" },
{ "security/samsung/defex_lsm/trusted_map/dtm_log.c", "dtm_report_violation" },
{ "kernel/seccomp.c", "seccomp_notify_dsms" },
}; // dsms_policy
// ^^^^^ DO NOT CHANGE THESE LINES! ^^^^^

size_t dsms_policy_size(void)
{
	return sizeof(dsms_policy)/sizeof(*dsms_policy);
}
