// SPDX-License-Identifier: GPL-2.0
/*
 * Example KUnit test to show how to use KUnit.
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <kunit/test.h>
#include <kunit/mock.h>

/*
 * This is the most fundamental element of KUnit, the test case. A test case
 * makes a set EXPECTATIONs and ASSERTIONs about the behavior of some code; if
 * any expectations or assertions are not met, the test fails; otherwise, the
 * test passes.
 *
 * In KUnit, a test case is just a function with the signature
 * `void (*)(struct kunit *)`. `struct kunit` is a context object that stores
 * information about the current test.
 */
static void example_simple_test(struct kunit *test)
{
	/*
	 * This is an EXPECTATION; it is how KUnit tests things. When you want
	 * to test a piece of code, you set some expectations about what the
	 * code should do. KUnit then runs the test and verifies that the code's
	 * behavior matched what was expected.
	 */
	KUNIT_EXPECT_EQ(test, 1 + 1, 2);
}

struct example_ops;

struct example {
	struct example_ops *ops;
};

/*
 * A lot of times, we embed "ops structs", which acts an abstraction over
 * hardware, a file system implementation, or some other subsystem that you
 * want to reason about in a generic way.
 */
struct example_ops {
	int (*foo)(struct example *example, int num);
};

static int example_bar(struct example *example, int num)
{
	return example->ops->foo(example, num);
}

/*
 * KUnit allows such a class to be "mocked out" with the following:
 */

/*
 * This macro creates a mock subclass of the specified class.
 */
DECLARE_STRUCT_CLASS_MOCK_PREREQS(example);

/*
 * This macro creates a mock implementation of the specified method of the
 * specified class.
 */
DEFINE_STRUCT_CLASS_MOCK(METHOD(foo), CLASS(example),
			 RETURNS(int),
			 PARAMS(struct example *, int));

/*
 * This tells KUnit how to initialize the parts of the mock that come from the
 * parent. In this example, all we have to do is populate the member functions
 * of the parent class with the mock versions we defined.
 */
static int example_init(struct kunit *test, struct MOCK(example) *mock_example)
{
	/* This is how you get a pointer to the parent class of a mock. */
	struct example *example = mock_get_trgt(mock_example);

	/*
	 * Here we create an ops struct containing our mock method instead.
	 */
	example->ops = kunit_kzalloc(test, sizeof(*example->ops), GFP_KERNEL);
	example->ops->foo = foo;

	return 0;
}

/*
 * This registers our parent init function above, allowing KUnit to create a
 * constructor for the mock.
 */
DEFINE_STRUCT_CLASS_MOCK_INIT(example, example_init);

/*
 * This is a test case where we use our mock.
 */
static void example_mock_test(struct kunit *test)
{
	struct MOCK(example) *mock_example = test->priv;
	struct example *example = mock_get_trgt(mock_example);
	struct mock_expectation *handle;

	/*
	 * Here we make an expectation that our mock method will be called with
	 * a parameter equal to 5 passed in.
	 */
	handle = KUNIT_EXPECT_CALL(foo(mock_get_ctrl(mock_example),
				       kunit_int_eq(test, 5)));
	/*
	 * We specify that when our mock is called in this way, we want it to
	 * return 2.
	 */
	handle->action = kunit_int_return(test, 2);

	KUNIT_EXPECT_EQ(test, 2, example_bar(example, 5));
}

/*
 * This is run once before each test case, see the comment on
 * example_test_suite for more information.
 */
static int example_test_init(struct kunit *test)
{
	kunit_info(test, "initializing\n");

	/*
	 * Here we construct the mock and store it in test's `priv` field; this
	 * field is for KUnit users. You can put whatever you want here, but
	 * most often it is a place that the init function can put stuff to be
	 * used by test cases.
	 */
	test->priv = CONSTRUCT_MOCK(example, test);
	if (!test->priv)
		return -EINVAL;

	return 0;
}

/*
 * This test should always be skipped.
 */
static void example_skip_test(struct kunit *test)
{
	/* This line should run */
	kunit_info(test, "You should not see a line below.");

	/* Skip (and abort) the test */
	kunit_skip(test, "this test should be skipped");

	/* This line should not execute */
	KUNIT_FAIL(test, "You should not see this line.");
}

/*
 * This test should always be marked skipped.
 */
static void example_mark_skipped_test(struct kunit *test)
{
	/* This line should run */
	kunit_info(test, "You should see a line below.");

	/* Skip (but do not abort) the test */
	kunit_mark_skipped(test, "this test should be skipped");

	/* This line should run */
	kunit_info(test, "You should see this line.");
}
/*
 * Here we make a list of all the test cases we want to add to the test suite
 * below.
 */
static struct kunit_case example_test_cases[] = {
	/*
	 * This is a helper to create a test case object from a test case
	 * function; its exact function is not important to understand how to
	 * use KUnit, just know that this is how you associate test cases with a
	 * test suite.
	 */
	KUNIT_CASE(example_simple_test),
	KUNIT_CASE(example_mock_test),
	KUNIT_CASE(example_skip_test),
	KUNIT_CASE(example_mark_skipped_test),
	{}
};

/*
 * This defines a suite or grouping of tests.
 *
 * Test cases are defined as belonging to the suite by adding them to
 * `kunit_cases`.
 *
 * Often it is desirable to run some function which will set up things which
 * will be used by every test; this is accomplished with an `init` function
 * which runs before each test case is invoked. Similarly, an `exit` function
 * may be specified which runs after every test case and can be used to for
 * cleanup. For clarity, running tests in a test suite would behave as follows:
 *
 * suite.init(test);
 * suite.test_case[0](test);
 * suite.exit(test);
 * suite.init(test);
 * suite.test_case[1](test);
 * suite.exit(test);
 * ...;
 */
static struct kunit_suite example_test_suite = {
	.name = "example",
	.init = example_test_init,
	.test_cases = example_test_cases,
};

/*
 * This registers the above test suite telling KUnit that this is a suite of
 * tests that need to be run.
 */
kunit_test_suites(&example_test_suite);

MODULE_LICENSE("GPL v2");
