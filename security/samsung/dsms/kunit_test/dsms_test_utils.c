/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/mock.h>
#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "dsms_test_utils.h"

/* test utils "sees" actual kmalloc and kmalloc_array */
#undef kmalloc
#undef kmalloc_array

/* -------------------------------------------------------------------------- */
/* General test functions: kmalloc and kmalloc_array mock function */
/* -------------------------------------------------------------------------- */

/* each bit indicates if kmalloc or kmalloc_array mock should return fail (NULL) */
static uint64_t dsms_test_kmalloc_fail_requests;

void *security_dsms_test_all_kmalloc_mock(size_t n, size_t size, gfp_t flags, bool is_kmalloc)
{
	bool fail;

	fail = dsms_test_kmalloc_fail_requests & 1ul;
	dsms_test_kmalloc_fail_requests >>= 1;
	if (is_kmalloc)
		return fail ? NULL : kmalloc(size, flags);
	else
		return fail ? NULL : kmalloc_array(n, size, flags);
}

void *security_dsms_test_kmalloc_mock(size_t size, gfp_t flags)
{
	return security_dsms_test_all_kmalloc_mock(0, size, flags, 1);
}

void *security_dsms_test_kmalloc_array_mock(size_t n, size_t size, gfp_t flags)
{
	return security_dsms_test_all_kmalloc_mock(n, size, flags, 0);
}

/* Requests that kmalloc or kmalloc_array fails in the attempt given by argument (1 for next) */
void security_dsms_test_request_kmalloc_fail_at(int attempt_no)
{
	if (attempt_no > 0)
		dsms_test_kmalloc_fail_requests |= (1ul << (attempt_no-1));
}

/* Cancels all kmalloc or kmalloc_array fail requests */
void security_dsms_test_cancel_kmalloc_fail_requests(void)
{
	dsms_test_kmalloc_fail_requests = 0;
}
