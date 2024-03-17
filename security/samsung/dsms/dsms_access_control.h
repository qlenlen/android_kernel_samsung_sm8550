/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DSMS_ACCESS_CONTROL_H
#define _DSMS_ACCESS_CONTROL_H

#include <linux/types.h>

#define CALLER_FRAME (0)

#ifdef DSMS_ALLOWLIST_IGNORE_NAME_SUFFIXES_ENABLE
#  define ALLOWLIST_IGNORE_SUFFIX (1)
#else
#  define ALLOWLIST_IGNORE_SUFFIX (0)
#endif

static inline char should_ignore_allowlist_suffix(void)
{
	return ALLOWLIST_IGNORE_SUFFIX;
}

struct dsms_policy_entry {
	const char *file_path;
	const char *function_name;
};

extern struct dsms_policy_entry dsms_policy[];

extern size_t dsms_policy_size(void);
extern int dsms_verify_access(const void *address);

#endif /* _DSMS_ACCESS_CONTROL_H */
