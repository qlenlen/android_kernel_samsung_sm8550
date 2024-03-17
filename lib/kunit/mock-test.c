// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit test for mock.h.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <kunit/test.h>
#include <kunit/mock.h>

// A simple class for unit-testing/example purposes.
struct adder {
	int (*add)(struct adder *adder, int x, int y);
};

static int real_add(struct adder *adder, int x, int y)
{
	return x + y;
}

static void adder_real_init(struct adder *adder)
{
	  adder->add = real_add;
}

DECLARE_STRUCT_CLASS_MOCK_PREREQS(adder);
DEFINE_STRUCT_CLASS_MOCK(METHOD(mock_add), CLASS(adder), RETURNS(int),
				     PARAMS(struct adder*, int, int));
DECLARE_STRUCT_CLASS_MOCK_INIT(adder);

// This would normally live in the .c file.
static int adder_mock_init(struct kunit *test, struct MOCK(adder) *mock_adder)
{
	struct adder *real = mock_get_trgt(mock_adder);

	adder_real_init(real);

	real->add = mock_add;
	mock_set_default_action(mock_get_ctrl(mock_adder),
				"mock_add",
				mock_add,
				kunit_int_return(mock_get_test(mock_adder), 0));
	return 0;
}
DEFINE_STRUCT_CLASS_MOCK_INIT(adder, adder_mock_init);


/*
 * Note: we create a new `failing_test` so we can validate that failed mock
 * expectations mark tests as failed.
 * Marking the real `test` as failed is obviously problematic.
 *
 * See mock_test_failed_expect_call_fails_test for an example.
 */
struct mock_test_context {
	struct kunit *failing_test;
	struct mock  *mock;
};

static void mock_test_do_expect_basic(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct mock *mock = ctx->mock;
	int param0 = 5, param1 = -4;
	static const char * const two_param_types[] = {"int", "int"};
	const void *two_params[] = {&param0, &param1};
	struct mock_param_matcher *matchers_any_two[] = {
		kunit_any(test), kunit_any(test)
	};
	struct mock_expectation *expectation;
	const void *ret;

	expectation = mock_add_matcher(mock,
				       "",
				       NULL,
				       matchers_any_two,
				       ARRAY_SIZE(matchers_any_two));
	expectation->action = kunit_int_return(test, 5);
	KUNIT_EXPECT_EQ(test, 0, expectation->times_called);

	ret = mock->do_expect(mock,
			      "",
			      NULL,
			      two_param_types,
			      two_params,
			      ARRAY_SIZE(two_params));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ret);
	KUNIT_EXPECT_EQ(test, 5, *((int *) ret));
	KUNIT_EXPECT_EQ(test, 1, expectation->times_called);
}

static void mock_test_ptr_eq(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;
	void *param0 = ctx, *param1 = failing_test;
	static const char * const two_param_types[] = {"void *", "void *"};
	const void *two_params[] = {&param0, &param1};
	struct mock_param_matcher *matchers_two_ptrs[] = {
		kunit_ptr_eq(test, param0), kunit_ptr_eq(test, param1)
	};
	struct mock_expectation *expectation;
	const void *ret;

	expectation = mock_add_matcher(mock,
				       "",
				       NULL,
				       matchers_two_ptrs,
				       ARRAY_SIZE(matchers_two_ptrs));
	expectation->action = kunit_int_return(test, 0);
	KUNIT_EXPECT_EQ(test, 0, expectation->times_called);

	ret = mock->do_expect(mock,
			      "",
			      NULL,
			      two_param_types,
			      two_params,
			      ARRAY_SIZE(two_params));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ret);
	KUNIT_EXPECT_EQ(test, 1, expectation->times_called);
}

static void mock_test_ptr_eq_not_equal(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	/* Pick some two pointers, but pass in different values. */
	void *param0 = test, *param1 = failing_test;
	static const char * const two_param_types[] = {"void *", "void *"};
	const void *two_params[] = {&param0, &param1};
	struct mock_param_matcher *matchers_two_ptrs[] = {
		kunit_ptr_eq(failing_test, param0),
		kunit_ptr_eq(failing_test, param1 - 1)
	};
	struct mock_expectation *expectation;
	const void *ret;

	expectation = mock_add_matcher(mock,
				       "",
				       NULL,
				       matchers_two_ptrs,
				       ARRAY_SIZE(matchers_two_ptrs));
	expectation->action = kunit_int_return(failing_test, 0);
	KUNIT_EXPECT_EQ(test, 0, expectation->times_called);

	ret = mock->do_expect(mock,
			      "",
			      NULL,
			      two_param_types,
			      two_params,
			      ARRAY_SIZE(two_params));
	KUNIT_EXPECT_FALSE(test, ret);
	KUNIT_EXPECT_EQ(test, 0, expectation->times_called);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

/*
 * In order for us to be able to rely on KUNIT_EXPECT_CALL to validate other
 * behavior, we need to test that unsatisfied KUNIT_EXPECT_CALL causes a test
 * failure.
 *
 * In order to understand what this test is testing we must first understand how
 * KUNIT_EXPECT_CALL() works conceptually. In theory, a test specifies that it
 * expects some function to be called some number of times (can be zero), with
 * some particular arguments. Hence, KUNIT_EXPECT_CALL() must do two things:
 *
 * 1) Determine whether a function call matches the expectation.
 *
 * 2) Fail if there are too many or too few matches.
 */
static void mock_test_failed_expect_call_fails_test(struct kunit *test)
{
       /*
	* We do not want to fail the real `test` object used to run this test.
	* So we use a separate `failing_test` for KUNIT_EXPECT_CALL().
	*/
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	/*
	 * Put an expectation on mock, which we won't satisify.
	 *
	 * NOTE: it does not actually matter what function we expect here.
	 * `mock` does not represent an actual mock on anything; we just need to
	 * create some expectation, that we won't satisfy.
	 */
	KUNIT_EXPECT_CALL(mock_add(mock,
			       kunit_any(failing_test),
			       kunit_any(failing_test)));

	/*
	 * Validate the unsatisfied expectation that we just created. This
	 * should cause `failing_test` to fail.
	 */
	mock_validate_expectations(mock);

	/* Verify that `failing_test` has actually failed. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

static void mock_test_do_expect_default_return(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct mock *mock = ctx->mock;
	int param0 = 5, param1 = -5;
	static const char * const two_param_types[] = {"int", "int"};
	const void *two_params[] = {&param0, &param1};
	struct mock_param_matcher *matchers[] = {
		kunit_int_eq(test, 5),
		kunit_int_eq(test, -4)
	};
	struct mock_expectation *expectation;
	const void *ret;

	expectation = mock_add_matcher(mock,
				       "add",
				       mock_add,
				       matchers,
				       ARRAY_SIZE(matchers));
	expectation->action = kunit_int_return(test, 5);
	KUNIT_EXPECT_EQ(test, 0, expectation->times_called);

	KUNIT_EXPECT_FALSE(test,
			   mock_set_default_action(mock,
						   "add",
						   mock_add,
						   kunit_int_return(test, -4)));

	ret = mock->do_expect(mock,
			      "add",
			      mock_add,
			      two_param_types,
			      two_params,
			      ARRAY_SIZE(two_params));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ret);
	KUNIT_EXPECT_EQ(test, -4, *((int *) ret));
	KUNIT_EXPECT_EQ(test, 0, expectation->times_called);
}

/**
 * DOC: Testing the failure condition of different mock types.
 *
 * The following tests will test the behaviour of expectations under different
 * conditions. For example, what happens when an expectation:
 * - is not satisfied at the end of the test
 * - is fulfilled but the expected function is called again
 * - a function is called without expectations set on it
 *
 * For each of these conditions, there may be variations between the different
 * types of mocks: nice mocks, naggy mocks (the default) and strict mocks.
 *
 * More information about these mocks can be found in the kernel documentation
 * under Documentation/test/api/class-and-function-mocking
 */

/* Method called on strict mock with no expectations will fail */
static void mock_test_strict_no_expectations_will_fail(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;
	int param0 = 5, param1 = -5;
	static const char * const two_param_types[] = {"int", "int"};
	const void *two_params[] = {&param0, &param1};

	mock->type = MOCK_TYPE_STRICT;

	mock_set_default_action(mock,
				"add",
				mock_add,
				kunit_int_return(failing_test, -4));

	mock->do_expect(mock,
			"add",
			mock_add,
			two_param_types,
			two_params,
			ARRAY_SIZE(two_params));
	mock_validate_expectations(mock);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

/*
 * Method called on naggy mock with no expectations will not fail, but will show
 * a warning message
 */
static void mock_test_naggy_no_expectations_no_fail(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_expectation *expectation;
	int param0 = 5, param1 = -5;
	static const char * const two_param_types[] = {"int", "int"};
	const void *two_params[] = {&param0, &param1};

	mock->type = MOCK_TYPE_NAGGY;

	mock_set_default_action(mock,
				"add",
				real_add,
				kunit_int_return(failing_test, -4));

	expectation = Never(KUNIT_EXPECT_CALL(mock_add(mock,
					     kunit_any(failing_test),
					     kunit_any(failing_test))));

	KUNIT_EXPECT_CALL(mock_add(
			mock,
			kunit_any(failing_test),
			kunit_va_format_cmp(failing_test,
					    kunit_str_contains(failing_test,
							       "Method was called with no expectations declared"),
					    kunit_any(failing_test))));

	mock->do_expect(mock,
			"add",
			real_add,
			two_param_types,
			two_params,
			ARRAY_SIZE(two_params));
	mock_validate_expectations(mock);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

/* Method called on nice mock with no expectations will do nothing. */
static void mock_test_nice_no_expectations_do_nothing(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;
	int param0 = 5, param1 = -5;
	static const char * const two_param_types[] = {"int", "int"};
	const void *two_params[] = {&param0, &param1};

	mock->type = MOCK_TYPE_NICE;

	mock->do_expect(mock,
			"add",
			mock_add,
			two_param_types,
			two_params,
			ARRAY_SIZE(two_params));
	mock_validate_expectations(mock);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}

/* Test that method called on a mock (of any type) with no matching expectations
 * will fail test and print all the tried expectations.
 */
static void
run_method_called_but_no_matching_expectation_test(struct kunit *test,
						   enum mock_type mock_type)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;
	int param0 = 5, param1 = -5;
	static const char * const two_param_types[] = {"int", "int"};
	const void *two_params[] = {&param0, &param1};
	struct mock_param_matcher *two_matchers[] = {
		kunit_int_eq(failing_test, 100),
		kunit_int_eq(failing_test, 100)
	};

	mock_add_matcher(mock, "add", mock_add, two_matchers,
			 ARRAY_SIZE(two_matchers));

	mock->type = mock_type;

	mock->do_expect(mock, "add", mock_add, two_param_types, two_params,
			ARRAY_SIZE(two_params));

	/* Even nice mocks should fail if there's an unmet expectation. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

static void mock_test_naggy_no_matching_expectations_fail(struct kunit *test)
{
	run_method_called_but_no_matching_expectation_test(test,
							   MOCK_TYPE_NAGGY);
}

static void mock_test_strict_no_matching_expectations_fail(struct kunit *test)
{
	run_method_called_but_no_matching_expectation_test(test,
							   MOCK_TYPE_STRICT);
}

static void mock_test_nice_no_matching_expectations_fail(struct kunit *test)
{
	run_method_called_but_no_matching_expectation_test(test,
							   MOCK_TYPE_NICE);
}

static void mock_test_mock_validate_expectations(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *matchers[] = {
		kunit_int_eq(failing_test, 5),
		kunit_int_eq(failing_test, -4)
	};
	struct mock_expectation *expectation;


	expectation = mock_add_matcher(mock,
				       "add",
				       mock_add,
				       matchers,
				       ARRAY_SIZE(matchers));
	expectation->times_called = 0;
	expectation->min_calls_expected = 1;
	expectation->max_calls_expected = 1;

	mock_validate_expectations(mock);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

static void mock_test_validate_clears_expectations(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;
	struct mock_param_matcher *matchers[] = {
		kunit_int_eq(failing_test, 5),
		kunit_int_eq(failing_test, -4)
	};
	int param0 = 5, param1 = -4;
	static const char * const two_param_types[] = {"int", "int"};
	const void *two_params[] = {&param0, &param1};

	struct mock_expectation *expectation;

	mock->type = MOCK_TYPE_STRICT;

	expectation = Never(KUNIT_EXPECT_CALL(mock_add(mock,
					     kunit_any(failing_test),
					     kunit_any(failing_test))));

	/* Add an arbitrary matcher for 0 calls */
	expectation = mock_add_matcher(mock, "add", mock_add,
				       matchers, ARRAY_SIZE(matchers));
	expectation->times_called = 0;
	expectation->min_calls_expected = 0;
	expectation->max_calls_expected = 0;

	/* Should have 0 calls and should clear the previous expectation */
	mock_validate_expectations(mock);

	/* Add a new matcher for 1 call */
	expectation = mock_add_matcher(mock, "add", mock_add,
				       matchers, ARRAY_SIZE(matchers));
	expectation->times_called = 0;
	expectation->min_calls_expected = 1;
	expectation->max_calls_expected = 1;

	/* Satisfy previous matcher */
	mock->do_expect(mock, "add", mock_add, two_param_types, two_params,
			ARRAY_SIZE(two_params));

	/*
	 * Validate previous satisfy; if we didn't clear the previous
	 * expectation, it would fail the mock_test.
	 */
	mock_validate_expectations(mock);

	/* If all goes well, shouldn't fail the test. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}


static void mock_stub(int a) { }

/* Common references for InSequence tests */
static int param_len = 1;
static const char * const param_type[] = {"int"};

static const void *a_params[] = { &(int){1} };
static const void *b_params[] = { &(int){2} };
static const void *c_params[] = { &(int){3} };

/* Simple test of InSequence, a -> b -> c */
static void mock_test_in_sequence_simple_pass(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };
	struct mock_param_matcher *c_matchers[] = { kunit_int_eq(failing_test, 3) };

	struct mock_expectation *c = mock_add_matcher(mock, "c", mock_stub,
		c_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);
	struct mock_expectation *a = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);

	InSequence(test, a, b, c);

	Never(KUNIT_EXPECT_CALL(mock_add(mock, kunit_any(failing_test),
					     kunit_any(failing_test))));


	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "c", mock_stub, param_type, c_params, param_len);

	mock_validate_expectations(mock);

	/* If all goes well, shouldn't fail the test. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}

static void mock_test_in_sequence_simple_fail(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };
	struct mock_param_matcher *c_matchers[] = { kunit_int_eq(failing_test, 3) };

	struct mock_expectation *c = mock_add_matcher(mock, "c", mock_stub,
		c_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);
	struct mock_expectation *a = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);

	InSequence(test, a, b, c);

	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "c", mock_stub, param_type, c_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

/* More complex test of InSequence on two chains in v formation:
 *   a -> c
 *   b -> c
 */
static void mock_test_in_sequence_abc_success(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };
	struct mock_param_matcher *c_matchers[] = { kunit_int_eq(failing_test, 3) };

	struct mock_expectation *c = mock_add_matcher(mock, "c", mock_stub,
		c_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);
	struct mock_expectation *a = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);

	InSequence(test, a, c);
	InSequence(test, b, c);

	Never(KUNIT_EXPECT_CALL(mock_add(mock, kunit_any(failing_test),
					     kunit_any(failing_test))));

	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "c", mock_stub, param_type, c_params, param_len);

	/* If all goes well, shouldn't fail the test. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}

static void mock_test_in_sequence_bac_success(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };
	struct mock_param_matcher *c_matchers[] = { kunit_int_eq(failing_test, 3) };

	struct mock_expectation *c = mock_add_matcher(mock, "c", mock_stub,
		c_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);
	struct mock_expectation *a = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);

	InSequence(test, a, c);
	InSequence(test, b, c);

	Never(KUNIT_EXPECT_CALL(mock_add(mock, kunit_any(failing_test),
					     kunit_any(failing_test))));

	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "c", mock_stub, param_type, c_params, param_len);

	/* If all goes well, shouldn't fail the test. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}

static void mock_test_in_sequence_no_a_fail(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };
	struct mock_param_matcher *c_matchers[] = { kunit_int_eq(failing_test, 3) };

	struct mock_expectation *c = mock_add_matcher(mock, "c", mock_stub,
		c_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);
	struct mock_expectation *a = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);

	InSequence(test, a, c);
	InSequence(test, b, c);

	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "c", mock_stub, param_type, c_params, param_len);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

static void mock_test_in_sequence_retire_on_saturation(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };
	struct mock_param_matcher *c_matchers[] = { kunit_int_eq(failing_test, 3) };

	struct mock_expectation *c = mock_add_matcher(mock, "c", mock_stub,
		c_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);
	struct mock_expectation *a_1 = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);
	struct mock_expectation *a_2 = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);

	InSequence(test, a_1, b, a_2, c);

	Never(KUNIT_EXPECT_CALL(mock_add(mock, kunit_any(failing_test),
					     kunit_any(failing_test))));

	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "c", mock_stub, param_type, c_params, param_len);

	mock_validate_expectations(mock);

	/* If all goes well, shouldn't fail the test. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}

static void mock_test_atleast(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };

	struct mock_expectation *a = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);

	AtLeast(2, a);
	AtLeast(1, b);
	Never(KUNIT_EXPECT_CALL(mock_add(mock, kunit_any(failing_test),
					     kunit_any(failing_test))));


	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);

	mock_validate_expectations(mock);

	/* If all goes well, shouldn't fail the test. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}

static void mock_test_atleast_fail(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };

	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);

	AtLeast(2, b);

	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);

	mock_validate_expectations(mock);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

static void mock_test_atmost(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };
	struct mock_param_matcher *c_matchers[] = { kunit_int_eq(failing_test, 3) };

	struct mock_expectation *a = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);
	struct mock_expectation *c = mock_add_matcher(mock, "c", mock_stub,
		c_matchers, param_len);

	AtMost(2, a);
	AtMost(1, b);
	AtMost(2, c);
	Never(KUNIT_EXPECT_CALL(mock_add(mock, kunit_any(failing_test),
					     kunit_any(failing_test))));


	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "c", mock_stub, param_type, c_params, param_len);

	mock_validate_expectations(mock);

	/* If all goes well, shouldn't fail the test. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}

static void mock_test_atmost_fail(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };

	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);

	AtMost(2, b);

	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);

	mock_validate_expectations(mock);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

static void mock_test_between(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };

	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);

	Between(2, 4, b);
	Never(KUNIT_EXPECT_CALL(mock_add(mock, kunit_any(failing_test),
					     kunit_any(failing_test))));

	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);

	mock_validate_expectations(mock);

	/* If all goes well, shouldn't fail the test. */
	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_SUCCESS);
}

static void mock_test_between_fail(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;
	struct kunit *failing_test = ctx->failing_test;
	struct mock *mock = ctx->mock;

	struct mock_param_matcher *a_matchers[] = { kunit_int_eq(failing_test, 1) };
	struct mock_param_matcher *b_matchers[] = { kunit_int_eq(failing_test, 2) };

	struct mock_expectation *a = mock_add_matcher(mock, "a", mock_stub,
		a_matchers, param_len);
	struct mock_expectation *b = mock_add_matcher(mock, "b", mock_stub,
		b_matchers, param_len);

	Between(2, 3, a);
	Between(1, 2, b);

	Times(2, KUNIT_EXPECT_CALL(mock_add(mock,
					kunit_any(failing_test),
					kunit_any(failing_test))));

	mock->do_expect(mock, "a", mock_stub, param_type, a_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);
	mock->do_expect(mock, "b", mock_stub, param_type, b_params, param_len);

	mock_validate_expectations(mock);

	KUNIT_EXPECT_EQ(test, failing_test->status, KUNIT_FAILURE);
}

static int mock_test_init(struct kunit *test)
{
	struct mock_test_context *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	test->priv = ctx;

	ctx->failing_test = kunit_kzalloc(test, sizeof(*ctx->failing_test),
					  GFP_KERNEL);
	if (!ctx->failing_test)
		return -EINVAL;
	kunit_init_test(ctx->failing_test, NULL, NULL);

	ctx->mock = kunit_kzalloc(test, sizeof(*ctx->mock), GFP_KERNEL);
	if (!ctx->mock)
		return -ENOMEM;
	mock_init_ctrl(ctx->failing_test, ctx->mock);

	return 0;
}

static void mock_test_exit(struct kunit *test)
{
	struct mock_test_context *ctx = test->priv;

	kunit_cleanup(ctx->failing_test);
}

static struct kunit_case mock_test_cases[] = {
	KUNIT_CASE(mock_test_do_expect_basic),
	KUNIT_CASE(mock_test_ptr_eq),
	KUNIT_CASE(mock_test_ptr_eq_not_equal),
	KUNIT_CASE(mock_test_failed_expect_call_fails_test),
	KUNIT_CASE(mock_test_do_expect_default_return),
	KUNIT_CASE(mock_test_mock_validate_expectations),
	KUNIT_CASE(mock_test_strict_no_expectations_will_fail),
	KUNIT_CASE(mock_test_naggy_no_expectations_no_fail),
	KUNIT_CASE(mock_test_nice_no_expectations_do_nothing),
	KUNIT_CASE(mock_test_strict_no_matching_expectations_fail),
	KUNIT_CASE(mock_test_naggy_no_matching_expectations_fail),
	KUNIT_CASE(mock_test_nice_no_matching_expectations_fail),
	KUNIT_CASE(mock_test_validate_clears_expectations),
	KUNIT_CASE(mock_test_in_sequence_simple_pass),
	KUNIT_CASE(mock_test_in_sequence_simple_fail),
	KUNIT_CASE(mock_test_in_sequence_abc_success),
	KUNIT_CASE(mock_test_in_sequence_bac_success),
	KUNIT_CASE(mock_test_in_sequence_no_a_fail),
	KUNIT_CASE(mock_test_in_sequence_retire_on_saturation),
	KUNIT_CASE(mock_test_atleast),
	KUNIT_CASE(mock_test_atleast_fail),
	KUNIT_CASE(mock_test_atmost),
	KUNIT_CASE(mock_test_atmost_fail),
	KUNIT_CASE(mock_test_between),
	KUNIT_CASE(mock_test_between_fail),
	{}
};

static struct kunit_suite mock_test_suite = {
	.name = "mock-test",
	.init = mock_test_init,
	.exit = mock_test_exit,
	.test_cases = mock_test_cases,
};

kunit_test_suite(mock_test_suite);
