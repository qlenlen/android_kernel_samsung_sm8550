// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit test for parameter list parsing macros.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <kunit/test.h>
#include <kunit/params.h>
#include <kunit/mock.h>

struct mock_macro_dummy_struct {
	int (*one_param)(struct mock_macro_dummy_struct *test_struct);
	int (*two_param)(struct mock_macro_dummy_struct *test_struct, int num);
	int (*non_first_slot_param)(
			int num,
			struct mock_macro_dummy_struct *test_struct);
	void *(*void_ptr_return)(struct mock_macro_dummy_struct *test_struct);
};

DECLARE_STRUCT_CLASS_MOCK_PREREQS(mock_macro_dummy_struct);

DEFINE_STRUCT_CLASS_MOCK(METHOD(one_param), CLASS(mock_macro_dummy_struct),
			 RETURNS(int),
			 PARAMS(struct mock_macro_dummy_struct *));

DEFINE_STRUCT_CLASS_MOCK(METHOD(two_param), CLASS(mock_macro_dummy_struct),
			 RETURNS(int),
			 PARAMS(struct mock_macro_dummy_struct *, int));

DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX(METHOD(non_first_slot_param),
			 CLASS(mock_macro_dummy_struct), HANDLE_INDEX(1),
			 RETURNS(int),
			 PARAMS(int, struct mock_macro_dummy_struct *));

DEFINE_STRUCT_CLASS_MOCK(METHOD(void_ptr_return),
			 CLASS(mock_macro_dummy_struct),
			 RETURNS(void *),
			 PARAMS(struct mock_macro_dummy_struct *));

static int mock_macro_dummy_struct_init(
		struct kunit *test, struct MOCK(mock_macro_dummy_struct) *mock_test_struct)
{
	struct mock_macro_dummy_struct *test_struct =
			mock_get_trgt(mock_test_struct);

	test_struct->one_param = one_param;
	test_struct->two_param = two_param;
	test_struct->non_first_slot_param = non_first_slot_param;
	return 0;
}

DEFINE_STRUCT_CLASS_MOCK_INIT(mock_macro_dummy_struct,
			      mock_macro_dummy_struct_init);
DECLARE_VOID_CLASS_MOCK_HANDLE_INDEX(METHOD(test_void_ptr_func),
				     HANDLE_INDEX(0),
				     RETURNS(int),
				     PARAMS(void*, int));

DEFINE_VOID_CLASS_MOCK_HANDLE_INDEX(METHOD(test_void_ptr_func),
				    HANDLE_INDEX(0),
				    RETURNS(int),
				    PARAMS(void*, int));

DEFINE_FUNCTION_MOCK(add, RETURNS(int), PARAMS(int, int));

struct mock_macro_context {
	struct MOCK(mock_macro_dummy_struct) *mock_test_struct;
	struct MOCK(void) *mock_void_ptr;
};

#define TO_STR_INTERNAL(...) #__VA_ARGS__
#define TO_STR(...) TO_STR_INTERNAL(__VA_ARGS__)

static void mock_macro_is_equal(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "dropped, 1", TO_STR(EQUAL(1, 1)));
	KUNIT_EXPECT_EQ(test, 1, DROP_FIRST_ARG(dropped, 1, 0));
	KUNIT_EXPECT_EQ(test, 0, DROP_FIRST_ARG(1, 0));
	KUNIT_EXPECT_EQ(test, 0, DROP_FIRST_ARG(EQUAL(1, 0), 0));
	KUNIT_EXPECT_EQ(test, 1, IS_EQUAL(1, 1));
	KUNIT_EXPECT_EQ(test, 0, IS_EQUAL(1, 0));
}

static void mock_macro_if(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "body", ""IF(1)("body"));
	KUNIT_EXPECT_STREQ(test, "", ""IF(0)("body"));
	KUNIT_EXPECT_STREQ(test, "body", ""IF(IS_EQUAL(1, 1))("body"));
	KUNIT_EXPECT_STREQ(test, "", ""IF(IS_EQUAL(0, 1))("body"));
}

static void mock_macro_apply_tokens(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "type", TO_STR(APPLY_TOKENS(type, 1, 0)));
	KUNIT_EXPECT_STREQ(test, ", type", TO_STR(APPLY_TOKENS(type, 1, 1)));
	KUNIT_EXPECT_STREQ(test, "", TO_STR(APPLY_TOKENS(type, 0, 1)));
}

#define IDENTITY(context, type, index) type

static void mock_macro_param_list_recurse(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "", TO_STR(PARAM_LIST_RECURSE(0,
							      0,
							      IDENTITY,
							      FILTER_NONE,
							      not_used)));
	KUNIT_EXPECT_STREQ(test,
			  "type",
			  TO_STR(EXPAND(PARAM_LIST_RECURSE(0,
							   1,
							   IDENTITY,
							   FILTER_NONE,
							   not_used,
							   type))));
	KUNIT_EXPECT_STREQ(test,
			  "type0 , type1 , type2 , type3 , type4 , type5 , "
			  "type6 , type7 , type8 , type9 , type10 , type11 , "
			  "type12 , type13 , type14 , type15",
			  TO_STR(EXPAND(PARAM_LIST_RECURSE(0, 16,
							   IDENTITY,
							   FILTER_NONE,
							   not_used,
							   type0, type1, type2,
							   type3, type4, type5,
							   type6, type7, type8,
							   type9, type10,
							   type11, type12,
							   type13, type14,
							   type15))));
}

static void mock_macro_for_each_param(struct kunit *test) {
	KUNIT_EXPECT_STREQ(test,
			  "type0 , type1",
			  TO_STR(FOR_EACH_PARAM(IDENTITY,
						FILTER_NONE,
						not_used,
						type0,
						type1)));
	KUNIT_EXPECT_STREQ(test,
			  "type1",
			  TO_STR(FOR_EACH_PARAM(IDENTITY,
						FILTER_INDEX,
						0,
						type0,
						type1)));
}

static void mock_macro_param_list_from_types_basic(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "", TO_STR(PARAM_LIST_FROM_TYPES()));
	KUNIT_EXPECT_STREQ(test, "int arg0",
			   TO_STR(PARAM_LIST_FROM_TYPES(int)));
	KUNIT_EXPECT_STREQ(test, "struct kunit_struct * arg0 , int arg1",
			  TO_STR(PARAM_LIST_FROM_TYPES(struct kunit_struct *,
						       int)));
	KUNIT_EXPECT_STREQ(test,
			  "type0 arg0 , type1 arg1 , type2 arg2 , type3 arg3 , "
			  "type4 arg4 , type5 arg5 , type6 arg6 , type7 arg7 , "
			  "type8 arg8 , type9 arg9 , type10 arg10 , "
			  "type11 arg11 , type12 arg12 , type13 arg13 , "
			  "type14 arg14 , type15 arg15",
			  TO_STR(PARAM_LIST_FROM_TYPES(type0, type1, type2,
						       type3, type4, type5,
						       type6, type7, type8,
						       type9, type10, type11,
						       type12, type13, type14,
						       type15)));
}

static void mock_macro_arg_names_from_types(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "", TO_STR(ARG_NAMES_FROM_TYPES(0)));
	KUNIT_EXPECT_STREQ(test, "", TO_STR(ARG_NAMES_FROM_TYPES(0, int)));
	KUNIT_EXPECT_STREQ(test,
			  "arg1",
			  TO_STR(ARG_NAMES_FROM_TYPES(0,
						      struct kunit_struct *,
						      int)));
	KUNIT_EXPECT_STREQ(test,
			  "arg0 , arg1 , arg3 , arg4 , arg5 , arg6 , arg7 , "
			  "arg8 , arg9 , arg10 , arg11 , arg12 , arg13 , "
			  "arg14 , arg15",
			  TO_STR(ARG_NAMES_FROM_TYPES(2, type0, type1, type2,
						      type3, type4, type5,
						      type6, type7, type8,
						      type9, type10, type11,
						      type12, type13, type14,
						      type15)));
}

static void mock_macro_test_generated_method_code_works(struct kunit *test)
{
	struct mock_macro_context *ctx = test->priv;
	struct MOCK(mock_macro_dummy_struct) *mock_test_struct =
			ctx->mock_test_struct;
	struct mock_macro_dummy_struct *test_struct =
			mock_get_trgt(mock_test_struct);
	struct mock_expectation *handle;

	handle = KUNIT_EXPECT_CALL(one_param(mock_get_ctrl(mock_test_struct)));
	handle->action = kunit_int_return(test, 0);
	handle = KUNIT_EXPECT_CALL(two_param(mock_get_ctrl(mock_test_struct),
					     kunit_int_eq(test, 5)));
	handle->action = kunit_int_return(test, 1);
	handle = KUNIT_EXPECT_CALL(non_first_slot_param(
			kunit_int_eq(test, 5),
			mock_get_ctrl(mock_test_struct)));
	handle->action = kunit_int_return(test, 1);

	test_struct->one_param(test_struct);
	test_struct->two_param(test_struct, 5);
	test_struct->non_first_slot_param(5, test_struct);
}

static void mock_macro_test_generated_method_void_code_works(struct kunit *test)
{
	struct mock_macro_context *ctx = test->priv;
	struct MOCK(void) *mock_void_ptr = ctx->mock_void_ptr;
	struct mock_expectation *handle;

	handle = KUNIT_EXPECT_CALL(test_void_ptr_func(mock_get_ctrl(mock_void_ptr),
						kunit_int_eq(test, 3)));
	handle->action = kunit_int_return(test, 0);

	test_void_ptr_func(mock_void_ptr, 3);
}

static void mock_macro_test_generated_function_code_works(struct kunit *test)
{
	struct mock_expectation *handle;

	handle = KUNIT_EXPECT_CALL(add(kunit_int_eq(test, 4), kunit_int_eq(test, 3)));
	handle->action = kunit_int_return(test, 7);

	KUNIT_EXPECT_EQ(test, 7, add(4, 3));
}

static int mock_macro_test_init(struct kunit *test)
{
	struct mock_macro_context *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	test->priv = ctx;

	ctx->mock_test_struct = CONSTRUCT_MOCK(mock_macro_dummy_struct, test);
	if (!ctx->mock_test_struct)
		return -EINVAL;

	ctx->mock_void_ptr = CONSTRUCT_MOCK(void, test);
	if (!ctx->mock_void_ptr)
		return -EINVAL;

	return 0;
}

static struct kunit_case mock_macro_test_cases[] = {
	KUNIT_CASE(mock_macro_is_equal),
	KUNIT_CASE(mock_macro_if),
	KUNIT_CASE(mock_macro_apply_tokens),
	KUNIT_CASE(mock_macro_param_list_recurse),
	KUNIT_CASE(mock_macro_for_each_param),
	KUNIT_CASE(mock_macro_param_list_from_types_basic),
	KUNIT_CASE(mock_macro_arg_names_from_types),
	KUNIT_CASE(mock_macro_test_generated_method_code_works),
	KUNIT_CASE(mock_macro_test_generated_method_void_code_works),
	KUNIT_CASE(mock_macro_test_generated_function_code_works),
	{}
};

static struct kunit_suite mock_macro_test_suite = {
	.name = "mock-macro-test",
	.init = mock_macro_test_init,
	.test_cases = mock_macro_test_cases,
};
kunit_test_suite(mock_macro_test_suite);
