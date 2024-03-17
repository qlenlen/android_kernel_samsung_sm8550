/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _SECURITY_DSMS_TEST_UTILS_H
#define _SECURITY_DSMS_TEST_UTILS_H

/* -------------------------------------------------------------------------- */
/* General test functions: kmalloc mock function */
/* -------------------------------------------------------------------------- */

/* Requests that kmalloc fails in the attempt given by argument (1 for next) */
void security_dsms_test_request_kmalloc_fail_at(int attempt_no);

/* Cancels all kmalloc fail requests */
void security_dsms_test_cancel_kmalloc_fail_requests(void);

#endif /* _SECURITY_DSMS_TEST_UTILS_H */
