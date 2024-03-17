/*
 * Copyright (c) 2018-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DSMS_RATE_LIMIT_H
#define _DSMS_RATE_LIMIT_H

#include "dsms_test.h"

extern int __kunit_init dsms_rate_limit_init(void);
static inline void dsms_rate_limit_exit(void) { return; }

extern int dsms_check_message_rate_limit(void);

#endif /* _DSMS_RATE_LIMIT_H */
