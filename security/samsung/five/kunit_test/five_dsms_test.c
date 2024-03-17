/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */
#include <kunit/test.h>
#include <kunit/mock.h>
#include "test_helpers.h"
#include "five.h"

void five_dsms_sign_err(const char *app, int result);
void five_dsms_reset_integrity(const char *task_name, int result,
				const char *file_name);
void five_dsms_init(const char *version, int result);

#define MAX_FIV1_NUM 16
#define FIV3_FIRST 1
#define FIV3_FEW   20
#define FIV3_LOT   100
#define MAX_FIV2_NUM 96

#define MESSAGE_BUFFER_SIZE    600
#define LARGE_FILE_NAME_SIZE (2*MESSAGE_BUFFER_SIZE)
#define LARGE_COMM_SIZE (2*MESSAGE_BUFFER_SIZE)
#define PARAM_COMM_RAND 5
#define PARAM_RESULT_RAND 10
#define PARAM_EVENT_COUNT_RAND 2020
#define CRC_VALUE_NO_MATTER	37	// any uint16
#define FILE_NAME_0 "foo/bar"
#define FILE_NAME_1 "bar/qux"
#define FILE_NAME_2 "foo"

DEFINE_FUNCTION_MOCK_VOID_RETURN(five_dsms_msg, PARAMS(char *, char *))

DEFINE_FUNCTION_MOCK(
	METHOD(call_crc16), RETURNS(u16), PARAMS(u16, u8 const *, size_t));

static char comm[TASK_COMM_LEN];
static int result;
static char dsms_msg[MESSAGE_BUFFER_SIZE];

static struct mock_expectation *setup_expect_call(struct kunit *test,
	char *comm, int result, int event_count, int n_calls)
{
	snprintf(dsms_msg, MESSAGE_BUFFER_SIZE, "%s res = %d count = %d",
		comm, result, event_count);  // generate appropriate gold msg
	return Times(n_calls, KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(
	    streq(test, "FIV3"), streq(test, dsms_msg))), int_return(test, 0)));
}

static void init_param(int comm_offs, int res, char *comm, int *p_result)
{
	int i;
	*p_result = res;  // randomly init result
	for (i = 0; i < TASK_COMM_LEN-1; ++i)  // randomly init char message
		comm[i] = (char)(comm_offs + i);
	comm[TASK_COMM_LEN-1] = '\0';
}

static void five_dsms_sign_err_first0_test(struct kunit *test)
{
	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND, comm, &result);
	setup_expect_call(test, comm, result, FIV3_FIRST, 1);
	five_dsms_sign_err(comm, result);
}

static void five_dsms_sign_err_first1_test(struct kunit *test)
{
	int i;

	setup_expect_call(test, comm, result, PARAM_EVENT_COUNT_RAND, 0);
	for (i = FIV3_FIRST + 1; i < FIV3_FEW; ++i)
		five_dsms_sign_err(comm, result);
}

static void five_dsms_sign_err_few0_test(struct kunit *test)
{
	setup_expect_call(test, comm, result, FIV3_FEW, 1);
	five_dsms_sign_err(comm, result);
}

static void five_dsms_sign_err_few1_test(struct kunit *test)
{
	int i;

	setup_expect_call(test, comm, result, PARAM_EVENT_COUNT_RAND, 0);
	for (i = FIV3_FEW + 1; i < FIV3_LOT; ++i)
		five_dsms_sign_err(comm, result);
}

static void five_dsms_sign_err_lot0_test(struct kunit *test)
{
	setup_expect_call(test, comm, result, FIV3_LOT, 1);
	five_dsms_sign_err(comm, result);
}

static void five_dsms_sign_err_lot1_test(struct kunit *test)
{
	int i;

	setup_expect_call(test, comm, result, PARAM_EVENT_COUNT_RAND, 0);
	for (i = FIV3_LOT + 1; i < 2*FIV3_LOT; ++i)
		five_dsms_sign_err(comm, result);
}

static void five_dsms_sign_err_all_events_test(struct kunit *test)
{
	int i;

	Times(MAX_FIV1_NUM-1, KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(
		streq(test, "FIV3"), any(test))), int_return(test, 0)));
	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND + 1, comm, &result);
	five_dsms_sign_err(comm, result);
	init_param(PARAM_COMM_RAND + 1, PARAM_RESULT_RAND, comm, &result);
	five_dsms_sign_err(comm, result);
	for (i = 2; i < MAX_FIV1_NUM-1; ++i) {
		init_param(PARAM_COMM_RAND + i,
			   PARAM_RESULT_RAND + i, comm, &result);
		five_dsms_sign_err(comm, result);
	}
}

static void five_dsms_sign_err_send_overflow_test(struct kunit *test)
{
	KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(streq(test, "FIV3"),
		streq(test, "data buffer overflow"))), int_return(test, 0));
	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND + MAX_FIV1_NUM, comm,
		&result);
	five_dsms_sign_err(comm, result);
}

static void five_dsms_sign_err_dont_send_overflow_test(struct kunit *test)
{
	Times(0, KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(
		streq(test, "FIV3"), any(test))), int_return(test, 0)));
	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND + MAX_FIV1_NUM, comm,
		&result);
	five_dsms_sign_err(comm, result);
	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND + MAX_FIV1_NUM + 1, comm,
		&result);
	five_dsms_sign_err(comm, result);
}

static void five_dsms_reset_integrity_send_msg0_test(struct kunit *test)
{
	char *file_name = FILE_NAME_0;

	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND, comm, &result);
	snprintf(dsms_msg, MESSAGE_BUFFER_SIZE, "%s|%d|%s", comm, result,
		 file_name ? kbasename(file_name) : "");
	KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(streq(test, "FIV2"),
		streq(test, dsms_msg))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(call_crc16(int_eq(test, 0),
		streq(test, dsms_msg), int_lt(test, MESSAGE_BUFFER_SIZE))),
		u32_return(test, CRC_VALUE_NO_MATTER));
	five_dsms_reset_integrity(comm, result, file_name);
}

static void five_dsms_reset_integrity_send_msg1_test(struct kunit *test)
{
	char *file_name = FILE_NAME_0;

	init_param(PARAM_COMM_RAND + 1, PARAM_RESULT_RAND, comm, &result);
	snprintf(dsms_msg, MESSAGE_BUFFER_SIZE, "%s|%d|%s", comm, result,
		file_name ? kbasename(file_name) : "");
	KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(
	     streq(test, "FIV2"), streq(test, dsms_msg))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(call_crc16(int_eq(test, 0),
		streq(test, dsms_msg), int_lt(test, MESSAGE_BUFFER_SIZE))),
		u32_return(test, CRC_VALUE_NO_MATTER + 1));
	five_dsms_reset_integrity(comm, result, file_name);
}

static void five_dsms_reset_integrity_send_msg2_test(struct kunit *test)
{
	char *file_name = FILE_NAME_0;

	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND + 1, comm, &result);
	snprintf(dsms_msg, MESSAGE_BUFFER_SIZE, "%s|%d|%s", comm, result,
		file_name ? kbasename(file_name) : "");
	KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(
	     streq(test, "FIV2"), streq(test, dsms_msg))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(call_crc16(int_eq(test, 0),
		streq(test, dsms_msg), int_lt(test, MESSAGE_BUFFER_SIZE))),
		u32_return(test, CRC_VALUE_NO_MATTER + 2));
	five_dsms_reset_integrity(comm, result, file_name);
}

static void five_dsms_reset_integrity_two_same_msg_test(struct kunit *test)
{
	char *file_name = FILE_NAME_1;

	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND, comm, &result);
	KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(
		streq(test, "FIV2"), any(test))), int_return(test, 0));
	Times(2, KunitReturns(KUNIT_EXPECT_CALL(call_crc16(
		int_eq(test, 0), any(test), int_lt(test, MESSAGE_BUFFER_SIZE))),
		u32_return(test, CRC_VALUE_NO_MATTER + 3)));
	five_dsms_reset_integrity(comm, result, file_name);
	five_dsms_reset_integrity(comm, result, file_name);
}

static void five_dsms_reset_integrity_large_filename_test(struct kunit *test)
{
	int i;
	char large_file_name[LARGE_FILE_NAME_SIZE];

	// create wrong filename (too large size)
	for (i = 0; i < LARGE_FILE_NAME_SIZE-1; ++i)
		large_file_name[i] = 97;  // init message with randomly chosen chars
	large_file_name[LARGE_FILE_NAME_SIZE-1] = '\0';
	// create correct comm[] and result
	init_param(PARAM_COMM_RAND, PARAM_RESULT_RAND, comm, &result);
	snprintf(dsms_msg, MESSAGE_BUFFER_SIZE, "%s|%d|%s", comm, result,
		kbasename(large_file_name));

	KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(
	     streq(test, "FIV2"), streq(test, dsms_msg))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(call_crc16(int_eq(test, 0),
		streq(test, dsms_msg), int_lt(test, MESSAGE_BUFFER_SIZE))),
		u32_return(test, CRC_VALUE_NO_MATTER + 4));

	five_dsms_reset_integrity(comm, result, large_file_name);
}

static void five_dsms_reset_integrity_large_comm_test(struct kunit *test)
{
	int i;
	char file_name[] = FILE_NAME_2;  // correct filename
	char large_comm[LARGE_COMM_SIZE];

	result = PARAM_RESULT_RAND;  // randomly init result
	// create wrong comm[] (too large size)
	for (i = 0; i < LARGE_COMM_SIZE-1; ++i)
		large_comm[i] = 98; // init char message with randomly chosen symbol
	large_comm[LARGE_COMM_SIZE-1] = '\0';
	snprintf(dsms_msg, MESSAGE_BUFFER_SIZE, "%s|%d|%s", large_comm, result,
		kbasename(file_name));

	KunitReturns(KUNIT_EXPECT_CALL(five_dsms_msg(
	     streq(test, "FIV2"), streq(test, dsms_msg))), int_return(test, 0));
	KunitReturns(KUNIT_EXPECT_CALL(call_crc16(int_eq(test, 0),
		streq(test, dsms_msg), int_lt(test, MESSAGE_BUFFER_SIZE))),
		u32_return(test, CRC_VALUE_NO_MATTER + 5));

	five_dsms_reset_integrity(large_comm, result, file_name);
}

static int five_dsms_test_init(struct kunit *test)
{
	return 0;
}

static void five_dsms_test_exit(struct kunit *test)
{
}

static struct kunit_case five_dsms_test_cases[] = {
	KUNIT_CASE(five_dsms_sign_err_first0_test),
	KUNIT_CASE(five_dsms_sign_err_first1_test),
	KUNIT_CASE(five_dsms_sign_err_few0_test),
	KUNIT_CASE(five_dsms_sign_err_few1_test),
	KUNIT_CASE(five_dsms_sign_err_lot0_test),
	KUNIT_CASE(five_dsms_sign_err_lot1_test),
	KUNIT_CASE(five_dsms_sign_err_all_events_test),
	KUNIT_CASE(five_dsms_sign_err_send_overflow_test),
	KUNIT_CASE(five_dsms_sign_err_dont_send_overflow_test),
	KUNIT_CASE(five_dsms_reset_integrity_send_msg0_test),
	KUNIT_CASE(five_dsms_reset_integrity_send_msg1_test),
	KUNIT_CASE(five_dsms_reset_integrity_send_msg2_test),
	KUNIT_CASE(five_dsms_reset_integrity_two_same_msg_test),
	KUNIT_CASE(five_dsms_reset_integrity_large_filename_test),
	KUNIT_CASE(five_dsms_reset_integrity_large_comm_test),
	{},
};

static struct kunit_suite five_dsms_test_module = {
	.name = "five_dsms_test",
	.init = five_dsms_test_init,
	.exit = five_dsms_test_exit,
	.test_cases = five_dsms_test_cases,
};

kunit_test_suites(&five_dsms_test_module);

MODULE_LICENSE("GPL v2");
