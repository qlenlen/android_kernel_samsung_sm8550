/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _LINUX_DSMS_H
#define _LINUX_DSMS_H

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/types.h>

#define DSMS_SUCCESS (0)
#define DSMS_DENY (-EPERM)
#define DSMS_NOT_IMPLEMENTED (-ENOSYS)

// DSMS Kernel Interface

#ifdef CONFIG_SECURITY_DSMS

extern int noinline dsms_send_message(const char *feature_code,
				      const char *detail, int64_t value);

#else

static inline int dsms_send_message(const char *feature_code,
				    const char *detail,
				    int64_t value)
{
	/* When SEC_PRODUCT_FEATURE_SECURITY_SUPPORT_DSMS=FALSE 
	 * CONFIG_SECURITY_DSMS is disabled and 
	 * DSMS functionality is not implemented. 
	 */
	return DSMS_NOT_IMPLEMENTED;
}

#endif /* CONFIG_SECURITY_DSMS */

#endif /* _LINUX_DSMS_H */