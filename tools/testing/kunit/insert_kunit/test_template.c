// SPDX-License-Identifier: GPL-2.0
/*
 * TODO: Add test description.
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

#ifdef CONFIG_UML
/* NOTE: UML TC */
static void ${test_prefix}_bar(struct kunit *test)
{
	/* Test cases for UML */
	KUNIT_EXPECT_EQ(test, 1, 1); // Pass
}
#else
/* NOTE: Target running TC must be in the #ifndef CONFIG_UML */
static void ${test_prefix}_foo(struct kunit *test)
{
	/*
	 * This is an EXPECTATION; it is how KUnit tests things. When you want
	 * to test a piece of code, you set some expectations about what the
	 * code should do. KUnit then runs the test and verifies that the code's
	 * behavior matched what was expected.
	 */
	KUNIT_EXPECT_EQ(test, 1, 2); // Obvious failure.
}
#endif

/*
 * This is run once before each test case, see the comment on
 * example_test_module for more information.
 */
static int ${test_prefix}_init(struct kunit *test)
{
	return 0;
}

/*
 * This is run once after each test case, see the comment on example_test_module
 * for more information.
 */
static void ${test_prefix}_exit(struct kunit *test)
{
}

/*
 * Here we make a list of all the test cases we want to add to the test module
 * below.
 */
static struct kunit_case ${test_prefix}_cases[] = {
	/*
	 * This is a helper to create a test case object from a test case
	 * function; its exact function is not important to understand how to
	 * use KUnit, just know that this is how you associate test cases with a
	 * test module.
	 */
#ifdef CONFIG_UML
	/* NOTE: UML TC */
	KUNIT_CASE(${test_prefix}_bar),
#else
	/* NOTE: Target running TC */
	KUNIT_CASE(${test_prefix}_foo),
#endif
	{},
};

/*
 * This defines a suite or grouping of tests.
 *
 * Test cases are defined as belonging to the suite by adding them to
 * `test_cases`.
 *
 * Often it is desirable to run some function which will set up things which
 * will be used by every test; this is accomplished with an `init` function
 * which runs before each test case is invoked. Similarly, an `exit` function
 * may be specified which runs after every test case and can be used to for
 * cleanup. For clarity, running tests in a test module would behave as follows:
 *
 * module.init(test);
 * module.test_case[0](test);
 * module.exit(test);
 * module.init(test);
 * module.test_case[1](test);
 * module.exit(test);
 * ...;
 */
struct kunit_suite ${test_prefix}_module = {
	.name = "${test_prefix}",
	.init = ${test_prefix}_init,
	.exit = ${test_prefix}_exit,
	.test_cases = ${test_prefix}_cases,
};
EXPORT_SYMBOL_KUNIT(${test_prefix}_module);

/*
 * This registers the above test module telling KUnit that this is a suite of
 * tests that need to be run.
 */
kunit_test_suites(&${test_prefix}_module);

MODULE_LICENSE("GPL v2");
