/*
 * Copyright (c) 2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DSMS_PREBOOT_BUFFER_H
#define _DSMS_PREBOOT_BUFFER_H

#include "dsms_test.h"

#ifdef DSMS_PREBOOT_BUFFER_ENABLE
extern int dsms_preboot_buffer_add(const char *feature_code,
				   const char *detail, int64_t value);
extern void wakeup_preboot_sender(void);
extern int __kunit_init dsms_preboot_buffer_init(void);
extern void __kunit_exit dsms_preboot_buffer_exit(void);
#else
static inline int dsms_preboot_buffer_add(const char *feature_code,
					  const char *detail, int64_t value)
{
	return -EAGAIN;
}

static inline void wakeup_preboot_sender(void)
{
	return;
}

static inline int dsms_preboot_buffer_init(void)
{
	return 0;
}

static inline void dsms_preboot_buffer_exit(void)
{
	return;
}
#endif

#endif /* _DSMS_PREBOOT_BUFFER_H */
