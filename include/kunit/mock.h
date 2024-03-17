/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Mocking API for KUnit.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#ifndef _KUNIT_MOCK_H
#define _KUNIT_MOCK_H

#include <linux/types.h>
#include <linux/tracepoint.h> /* For PARAMS(...) */
#include <kunit/test.h>
#include <kunit/kunit-stream.h>
#include <kunit/params.h>

/**
 * struct mock_param_matcher - represents a matcher used in a *call expectation*
 * @match: the function that performs the matching
 *
 * The matching function takes a couple of parameters:
 *
 * - ``this``: refers to the parent struct
 * - ``stream``: a &kunit_stream to which a detailed message should be added as
 *   to why the parameter matches or not
 * - ``param``: a pointer to the parameter to check for a match
 *
 * The matching function should return whether or not the passed parameter
 * matches.
 */
struct mock_param_matcher {
	bool (*match)(struct mock_param_matcher *this,
		      struct kunit_stream *stream,
		      const void *param);
};

#define MOCK_MAX_PARAMS 255

struct mock_matcher {
	struct mock_param_matcher *matchers[MOCK_MAX_PARAMS];
	int num;
};

/**
 * struct mock_action - Represents an action that a mock performs when
 *                      expectation is matched
 * @do_action: the action to perform
 *
 * The action function is given some parameters:
 *
 * - ``this``: refers to the parent struct
 * - ``params``: an array of pointers to the params passed into the mocked
 *   method or function. **The class argument is excluded for a mocked class
 *   method.**
 * - ``len``: size of ``params``
 *
 * The action function returns a pointer to the value that the mocked method
 * or function should be returning.
 */
struct mock_action {
	void *(*do_action)(struct mock_action *this,
			   const void **params,
			   int len);
};

/**
 * struct mock_expectation - represents a *call expectation* on a function.
 * @action: A &struct mock_action to perform when the function is called.
 * @max_calls_expected: maximum number of times an expectation may be called.
 * @min_calls_expected: minimum number of times an expectation may be called.
 * @retire_on_saturation: no longer match once ``max_calls_expected`` is
 *			  reached.
 *
 * Represents a *call expectation* on a function created with
 * KUNIT_EXPECT_CALL().
 */
struct mock_expectation {
	struct mock_action *action;
	int max_calls_expected;
	int min_calls_expected;
	bool retire_on_saturation;
	/* private: internal use only. */
	const char *expectation_name;
	struct list_head node;
	struct mock_matcher *matcher;
	int times_called;
	/* internal list of prerequisites */
	struct list_head prerequisites;
};

struct mock_expectation_prereq_entry {
	struct mock_expectation *expectation;
	struct list_head node;
};

struct mock_method {
	struct list_head node;
	const char *method_name;
	const void *method_ptr;
	struct mock_action *default_action;
	struct list_head expectations;
};

enum mock_type {
	MOCK_TYPE_NICE,
	MOCK_TYPE_NAGGY,
	MOCK_TYPE_STRICT
};

struct mock {
	struct kunit_post_condition parent;
	struct kunit *test;
	struct list_head methods;
	enum mock_type type;
	/* TODO(brendanhiggins@google.com): add locking to do_expect. */
	const void *(*do_expect)(struct mock *mock,
				 const char *method_name,
				 const void *method_ptr,
				 const char * const *param_types,
				 const void **params,
				 int len);
};

#define DEFAULT_MOCK_TYPE MOCK_TYPE_NAGGY

void mock_init_ctrl(struct kunit *test, struct mock *mock);

void mock_validate_expectations(struct mock *mock);

int mock_set_default_action(struct mock *mock,
			    const char *method_name,
			    const void *method_ptr,
			    struct mock_action *action);

struct mock_expectation *mock_add_matcher(struct mock *mock,
					  const char *method_name,
					  const void *method_ptr,
					  struct mock_param_matcher *matchers[],
					  int len);

struct mock_param_formatter {
	struct list_head node;
	const char *type_name;
	void (*format)(struct mock_param_formatter *formatter,
		       struct kunit_stream *stream,
		       const void *param);
};

void mock_register_formatter(struct mock_param_formatter *formatter);

void mock_unregister_formatter(struct mock_param_formatter *formatter);

#define MOCK(name) name##_mock

struct mock *mock_get_global_mock(void);

/**
 * STRICT_MOCK() - sets the mock to be strict and returns the mock
 * @mock: the mock
 *
 * For an example, see ``The Nice, the Strict, and the Naggy`` under
 * ``Using KUnit``.
 */
#define STRICT_MOCK(mock) \
({ \
	mock_get_ctrl(mock)->type = MOCK_TYPE_STRICT; \
	mock; \
})

static inline bool is_strict_mock(struct mock *mock)
{
	return mock->type == MOCK_TYPE_STRICT;
}

/**
 * NICE_MOCK() - sets the mock to be nice and returns the mock
 * @mock: the mock
 *
 * For an example, see ``The Nice, the Strict, and the Naggy`` under
 * ``Using KUnit``.
 */
#define NICE_MOCK(mock) \
({ \
	mock_get_ctrl(mock)->type = MOCK_TYPE_NICE; \
	mock; \
})

static inline bool is_nice_mock(struct mock *mock)
{
	return mock->type == MOCK_TYPE_NICE;
}

/**
 * NAGGY_MOCK() - sets the mock to be naggy and returns the mock
 * @mock: the mock
 *
 * For an example, see ``The Nice, the Strict, and the Naggy`` under
 * ``Using KUnit``.
 */
#define NAGGY_MOCK(mock) \
({ \
	mock_get_ctrl(mock)->type = MOCK_TYPE_NAGGY; \
	mock; \
})

static inline bool is_naggy_mock(struct mock *mock)
{
	return mock->type == MOCK_TYPE_NAGGY;
}

/**
 * KUNIT_EXPECT_CALL() - Declares a *call expectation* on a mock function.
 * @expectation_call: a mocked method or function with parameters replaced with
 *                    matchers.
 *
 * Example:
 *
 * .. code-block:: c
 *
 *	// Class to mock.
 *	struct example {
 *		int (*foo)(struct example *, int);
 *	};
 *
 *	// Define the mock.
 *	DECLARE_STRUCT_CLASS_MOCK_PREREQS(example);
 *
 *	DEFINE_STRUCT_CLASS_MOCK(METHOD(foo), CLASS(example),
 *				 RETURNS(int),
 *				 PARAMS(struct example *, int));
 *
 *	static int example_init(struct MOCK(example) *mock_example)
 *	{
 *		struct example *example = mock_get_trgt(mock_example);
 *
 *		example->foo = foo;
 *		return 0;
 *	}
 *
 *	DEFINE_STRUCT_CLASS_MOCK_INIT(example, example_init);
 *
 *	static void foo_example_test_success(struct kunit *test)
 *	{
 *		struct MOCK(example) *mock_example;
 *		struct example *example = mock_get_trgt(mock_example);
 *		struct mock_expectation *handle;
 *
 *		mock_example = CONSTRUCT_MOCK(example, test);
 *
 *		handle = KUNIT_EXPECT_CALL(foo(mock_get_ctrl(mock_example),
 *					       kunit_int_eq(test, 5)));
 *		handle->action = int_return(test, 2);
 *
 *		KUNIT_EXPECT_EQ(test, 2, example_bar(example, 5));
 *	}
 *
 * Return:
 * A &struct mock_expectation representing the call expectation.
 * allowing additional conditions and actions to be specified.
 */
#define KUNIT_EXPECT_CALL(expectation_call) mock_master_##expectation_call

/**
 * Times() - sets the number of times a method is expected be called with the
 *	matching parameters
 * @times: the number of times expected
 * @expectation: the expectation to set
 *
 * Return:
 * the same &struct mock_expectation passed in
 */
static inline struct mock_expectation *Times(
	int times,
	struct mock_expectation *expectation)
{
	expectation->min_calls_expected = times;
	expectation->max_calls_expected = times;
	return expectation;
}

/**
 * AtLeast() - sets the minimum number of times a method is expected to be
 *	called with matching parameters
 * @times: the minimum number of times expected
 * @expectation: the expectation to set
 *
 * Return:
 * the same &struct mock_expectation passed in
 */
static inline struct mock_expectation *AtLeast(
	int times,
	struct mock_expectation *expectation)
{
	expectation->min_calls_expected = times;
	expectation->max_calls_expected = INT_MAX;
	return expectation;
}

/**
 * AtMost() - sets the maximum number of times a method is expected to be
 *	called with matching parameters
 * @times: the maximum number of times expected
 * @expectation: the expectation to set
 *
 * Return:
 * the same &struct mock_expectation passed in
 */
static inline struct mock_expectation *AtMost(
	int times,
	struct mock_expectation *expectation)
{
	expectation->min_calls_expected = 0;
	expectation->max_calls_expected = times;
	return expectation;
}

/**
 * Between() - sets the minimum and maximum number of times a method is
 *	expected to be called with matching parameters
 * @min_times: the minimum number of times expected
 * @max_times: the maximum number of times expected
 * @expectation: the expectation to set
 *
 * Return:
 * the same &struct mock_expectation passed in
 */
static inline struct mock_expectation *Between(
	int min_times,
	int max_times,
	struct mock_expectation *expectation)
{
	expectation->min_calls_expected = min_times;
	expectation->max_calls_expected = max_times;
	return expectation;
}

/**
 * Never() - alias for Times(0)
 * @expectation: the expectation to set
 *
 * Return:
 * the same &struct mock_expectation passed in
 */
static inline struct mock_expectation *Never(
	struct mock_expectation *expectation)
{
	return Times(0, expectation);
}

/**
 * RetireOnSaturation() - sets the expectation to retire on saturation
 * @expectation: the expectation to set
 *
 * Return:
 * the same &struct mock_expectation passed in
 */
static inline struct mock_expectation *RetireOnSaturation(
	struct mock_expectation *expectation)
{
	expectation->retire_on_saturation = true;
	return expectation;
}

/**
 * ActionOnMatch() - sets a action of the expectation when matched
 * @expectation: the expectation to set the action of
 * @action: action to perform when expectation matches
 *
 * Example:
 *
 * .. code-block:: c
 *
 *	ActionOnMatch(EXPECT_CALL(...), INVOKE_REAL(test, ...));
 *
 * Return:
 * the same &struct mock_expectation passed in
 */
static inline struct mock_expectation *ActionOnMatch(
	struct mock_expectation *expectation,
	struct mock_action *action)
{
	expectation->action = action;
	return expectation;
}

/**
 * InSequence() - defines an order for expectations to be matched
 * @test: the test, used for internal resource allocations
 * @first: the first &struct mock_expectation in the sequence
 * @...: the rest of the expectations in order following
 *
 * Example:
 *
 * .. code-block:: c
 *
 *	struct mock_expectation *a = EXPECT_CALL(...);
 *	struct mock_expectation *b = EXPECT_CALL(...);
 *	struct mock_expectation *c = EXPECT_CALL(...);
 *
 *	InSequence(test, a, b, c);
 *
 * Return:
 * 0 if everything was successful, otherwise a memory allocation error
 */
#define InSequence(test, first, ...) \
	mock_in_sequence((struct kunit *)test, first, __VA_ARGS__, 0)

int mock_in_sequence(struct kunit *test, struct mock_expectation *first, ...);

#define mock_get_ctrl_internal(mock_object) (&(mock_object)->ctrl)
#define mock_get_ctrl(mock_object) mock_get_ctrl_internal(mock_object)

#define mock_get_trgt_internal(mock_object) (&(mock_object)->trgt)
#define mock_get_trgt(mock_object) mock_get_trgt_internal(mock_object)

#define mock_get_test(mock_object) (mock_get_ctrl(mock_object)->test)

#define CLASS(struct_name) struct_name
#define HANDLE_INDEX(index) index
#define METHOD(method_name) method_name
#define RETURNS(return_type) return_type
/* #define PARAMS(...) __VA_ARGS__ included by linux/tracepoint.h */

#define MOCK_INIT_ID(struct_name) struct_name##mock_init
#define REAL_ID(func_name) __real__##func_name
#define INVOKE_ID(func_name) __invoke__##func_name

#define DECLARE_MOCK_CLIENT(name, return_type, param_types...)		       \
		return_type name(PARAM_LIST_FROM_TYPES(param_types))

#define DECLARE_MOCK_MASTER(name, ctrl_index, param_types...)		       \
		struct mock_expectation *mock_master_##name(		       \
				MATCHER_PARAM_LIST_FROM_TYPES(ctrl_index,      \
							      param_types))

#define DECLARE_MOCK_COMMON(name, handle_index, return_type, param_types...)   \
		DECLARE_MOCK_CLIENT(name, return_type, param_types);	       \
		DECLARE_MOCK_MASTER(name, handle_index, param_types)

#define DECLARE_REDIRECT_MOCKABLE(name, return_type, param_types...)	       \
		return_type REAL_ID(name)(param_types);			       \
		return_type name(param_types);				       \
		void *INVOKE_ID(name)(struct kunit *test,		       \
				      const void *params[],		       \
				      int len)

#define DECLARE_MOCK_FUNC_CLIENT(name, return_type, param_types...) \
		DECLARE_MOCK_CLIENT(name, return_type, param_types)

#define DECLARE_MOCK_FUNC_MASTER(name, param_types...) \
		DECLARE_MOCK_MASTER(name, MOCK_MAX_PARAMS, param_types)

#define DECLARE_STRUCT_CLASS_MOCK_STRUCT(struct_name)			       \
		struct MOCK(struct_name) {				       \
			struct mock		ctrl;			       \
			struct struct_name	trgt;			       \
		}

#define DECLARE_STRUCT_CLASS_MOCK_CONVERTER(struct_name)		       \
		static inline struct mock *from_##struct_name##_to_mock(       \
				const struct struct_name *trgt)		       \
		{							       \
			return mock_get_ctrl(				       \
					container_of(trgt,		       \
						     struct MOCK(struct_name), \
						     trgt));		       \
		}

/**
 * DECLARE_STRUCT_CLASS_MOCK_PREREQS() - Create a mock child class
 * @struct_name: name of the class/struct to be mocked
 *
 * Creates a mock child class of ``struct_name`` named
 * ``struct MOCK(struct_name)`` along with supporting internally used methods.
 *
 * See KUNIT_EXPECT_CALL() for example usages.
 */
#define DECLARE_STRUCT_CLASS_MOCK_PREREQS(struct_name)			       \
		DECLARE_STRUCT_CLASS_MOCK_STRUCT(struct_name);		       \
		DECLARE_STRUCT_CLASS_MOCK_CONVERTER(struct_name)

#define DECLARE_STRUCT_CLASS_MOCK_HANDLE_INDEX_INTERNAL(name,		       \
							struct_name,	       \
							handle_index,	       \
							return_type,	       \
							param_types...)	       \
		DECLARE_MOCK_COMMON(name,				       \
				    handle_index,			       \
				    return_type,			       \
				    param_types)

#define DECLARE_STRUCT_CLASS_MOCK_HANDLE_INDEX(name,			       \
					       struct_name,		       \
					       handle_index,		       \
					       return_type,		       \
					       param_types...)		       \
		DECLARE_STRUCT_CLASS_MOCK_HANDLE_INDEX_INTERNAL(name,	       \
								struct_name,   \
								handle_index,  \
								return_type,   \
								param_types)

/**
 * DECLARE_STRUCT_CLASS_MOCK()
 * @name: method name
 * @struct_name: name of the class/struct
 * @return_type: return type of the method
 * @param_types: parameters of the method
 *
 * Same as DEFINE_STRUCT_CLASS_MOCK(), but only makes header compatible
 * declarations.
 */
#define DECLARE_STRUCT_CLASS_MOCK(name,					       \
				  struct_name,				       \
				  return_type,				       \
				  param_types...)			       \
		DECLARE_STRUCT_CLASS_MOCK_HANDLE_INDEX(name,		       \
						       struct_name,	       \
						       0,		       \
						       return_type,	       \
						       param_types)

/**
 * DECLARE_STRUCT_CLASS_MOCK_VOID_RETURN()
 * @name: method name
 * @struct_name: name of the class/struct
 * @param_types: parameters of the method
 *
 * Same as DEFINE_STRUCT_CLASS_MOCK_VOID_RETURN(), but only makes header
 * compatible declarations.
 */
#define DECLARE_STRUCT_CLASS_MOCK_VOID_RETURN(name,			       \
					      struct_name,		       \
					      param_types...)		       \
		DECLARE_STRUCT_CLASS_MOCK_HANDLE_INDEX(name,		       \
						       struct_name,	       \
						       0,		       \
						       void,		       \
						       param_types)

/**
 * DECLARE_STRUCT_CLASS_MOCK_INIT()
 * @struct_name: name of the class/struct
 *
 * Same as DEFINE_STRUCT_CLASS_MOCK_INIT(), but only makes header compatible
 * declarations.
 */
#define DECLARE_STRUCT_CLASS_MOCK_INIT(struct_name)			       \
		struct MOCK(struct_name) *MOCK_INIT_ID(struct_name)(	       \
				struct kunit *test)

#define DECLARE_VOID_CLASS_MOCK_HANDLE_INDEX_INTERNAL(name,		       \
						      handle_index,	       \
						      return_type,	       \
						      param_types...)	       \
		DECLARE_MOCK_COMMON(name,				       \
				    handle_index,			       \
				    return_type,			       \
				    param_types)

#define DECLARE_VOID_CLASS_MOCK_HANDLE_INDEX(name,			       \
					     handle_index,		       \
					     return_type,		       \
					     param_types...)		       \
		DECLARE_VOID_CLASS_MOCK_HANDLE_INDEX_INTERNAL(name,	       \
							      handle_index,    \
							      return_type,     \
							      param_types)

/**
 * CONSTRUCT_MOCK()
 * @struct_name: name of the class
 * @test: associated test
 *
 * Constructs and allocates a test managed ``struct MOCK(struct_name)`` given
 * the name of the class for which the mock is defined and a test object.
 *
 * See KUNIT_EXPECT_CALL() for example usage.
 */
#define CONSTRUCT_MOCK(struct_name, test) MOCK_INIT_ID(struct_name)((struct kunit *)test)

#define DECLARE_FUNCTION_MOCK_INTERNAL(name, return_type, param_types...)      \
		DECLARE_MOCK_FUNC_CLIENT(name, return_type, param_types);      \
		DECLARE_MOCK_FUNC_MASTER(name, param_types);

#define DECLARE_FUNCTION_MOCK(name, return_type, param_types...) \
		DECLARE_FUNCTION_MOCK_INTERNAL(name, return_type, param_types)

#define DECLARE_FUNCTION_MOCK_VOID_RETURN(name, param_types...) \
		DECLARE_FUNCTION_MOCK(name, void, param_types)

#define DEFINE_MOCK_CLIENT_COMMON(name,					       \
				  handle_index,				       \
				  MOCK_SOURCE,				       \
				  mock_source_ctx,			       \
				  return_type,				       \
				  RETURN,				       \
				  param_types...)			       \
		return_type name(PARAM_LIST_FROM_TYPES(param_types))	       \
		{							       \
			struct mock *mock = MOCK_SOURCE(mock_source_ctx,       \
							handle_index);	       \
			static const char * const param_type_names[] = {       \
				TYPE_NAMES_FROM_TYPES(handle_index,	       \
						      param_types)	       \
			};						       \
			const void *params[] = {			       \
				PTR_TO_ARG_FROM_TYPES(handle_index,	       \
						      param_types)	       \
			};						       \
			const void *retval;				       \
									       \
			retval = mock->do_expect(mock,			       \
						 #name,			       \
						 name,			       \
						 param_type_names,	       \
						 params,		       \
						 ARRAY_SIZE(params));	       \
			KUNIT_ASSERT_NOT_ERR_OR_NULL(mock->test, retval);      \
			if (!retval) {					       \
				kunit_info(mock->test,			       \
					   "no action installed for "#name"\n");\
				BUG();					       \
			}						       \
			RETURN(return_type, retval);			       \
		}

#if IS_ENABLED(CONFIG_KUNIT)
#define DEFINE_INVOKABLE(name, return_type, RETURN_ASSIGN, param_types...)     \
		void *INVOKE_ID(name)(struct kunit *test,		       \
				      const void *params[],		       \
				      int len) {			       \
			return_type *retval;				       \
									       \
			KUNIT_ASSERT_EQ(test, NUM_VA_ARGS(param_types), len);  \
			retval = kunit_kzalloc(test,			       \
					      sizeof(*retval),		       \
					      GFP_KERNEL);		       \
			KUNIT_ASSERT_NOT_ERR_OR_NULL(test, retval);	       \
			RETURN_ASSIGN() REAL_ID(name)(			       \
					ARRAY_ACCESSORS_FROM_TYPES(	       \
							param_types));	       \
			return retval;					       \
		}
#else
#define DEFINE_INVOKABLE(name, return_type, RETURN_ASSIGN, param_types...)
#endif

#define DEFINE_REDIRECT_MOCKABLE_COMMON(name,				       \
					return_type,			       \
					RETURN_ASSIGN,			       \
					param_types...)			       \
		return_type REAL_ID(name)(param_types);			       \
		return_type name(param_types) __mockable_alias(REAL_ID(name)); \
		DEFINE_INVOKABLE(name, return_type, RETURN_ASSIGN, param_types);

#define ASSIGN() *retval =

/**
 * DEFINE_REDIRECT_MOCKABLE()
 * @name: name of the function
 * @return_type: return type of the function
 * @param_types: parameter types of the function
 *
 * Used to define a function which is *redirect-mockable*, which allows the
 * function to be mocked and refer to the original definition via
 * INVOKE_REAL().
 *
 * Example:
 *
 * .. code-block:: c
 *
 *	DEFINE_REDIRECT_MOCKABLE(i2c_add_adapter,
 *				 RETURNS(int), PARAMS(struct i2c_adapter *));
 *	int REAL_ID(i2c_add_adapter)(struct i2c_adapter *adapter)
 *	{
 *		...
 *	}
 *
 *	static int aspeed_i2c_test_init(struct kunit *test)
 *	{
 *		struct mock_param_capturer *adap_capturer;
 *		struct mock_expectation *handle;
 *		struct aspeed_i2c_test *ctx;
 *		int ret;
 *
 *		ctx = test_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
 *		if (!ctx)
 *			return -ENOMEM;
 *		test->priv = ctx;
 *
 *		handle = EXPECT_CALL(
 *				i2c_add_adapter(capturer_to_matcher(
 *						adap_capturer)));
 *		handle->action = INVOKE_REAL(test, i2c_add_adapter);
 *		ret = of_fake_probe_platform_by_name(test,
 *						     "aspeed-i2c-bus",
 *						     "test-i2c-bus");
 *		if (ret < 0)
 *			return ret;
 *
 *		ASSERT_PARAM_CAPTURED(test, adap_capturer);
 *		ctx->adap = mock_capturer_get(adap_capturer,
 *					      struct i2c_adapter *);
 *
 *		return 0;
 *	}
 */
#define DEFINE_REDIRECT_MOCKABLE(name, return_type, param_types...)	       \
		DEFINE_REDIRECT_MOCKABLE_COMMON(name,			       \
						return_type,		       \
						ASSIGN,			       \
						param_types)

#define NO_ASSIGN()
#define DEFINE_REDIRECT_MOCKABLE_VOID_RETURN(name, param_types)		       \
		DEFINE_REDIRECT_MOCKABLE_COMMON(name,			       \
						void,			       \
						NO_ASSIGN,		       \
						param_types)

#define CLASS_MOCK_CLIENT_SOURCE(ctx, handle_index) ctx(arg##handle_index)
#define DEFINE_MOCK_METHOD_CLIENT_COMMON(name,				       \
					 handle_index,			       \
					 mock_converter,		       \
					 return_type,			       \
					 RETURN,			       \
					 param_types...)		       \
		DEFINE_MOCK_CLIENT_COMMON(name,				       \
					  handle_index,			       \
					  CLASS_MOCK_CLIENT_SOURCE,	       \
					  mock_converter,		       \
					  return_type,			       \
					  RETURN,			       \
					  param_types)

#define CAST_AND_RETURN(return_type, retval) return *((return_type *) retval)
#define NO_RETURN(return_type, retval)

#define DEFINE_MOCK_METHOD_CLIENT(name,					       \
				  handle_index,				       \
				  mock_converter,			       \
				  return_type,				       \
				  param_types...)			       \
		DEFINE_MOCK_METHOD_CLIENT_COMMON(name,			       \
						 handle_index,		       \
						 mock_converter,	       \
						 return_type,		       \
						 CAST_AND_RETURN,	       \
						 param_types)

#define DEFINE_MOCK_METHOD_CLIENT_VOID_RETURN(name,			       \
					      handle_index,		       \
					      mock_converter,		       \
					      param_types...)		       \
		DEFINE_MOCK_METHOD_CLIENT_COMMON(name,			       \
						 handle_index,		       \
						 mock_converter,	       \
						 void,			       \
						 NO_RETURN,		       \
						 param_types)

#define FUNC_MOCK_SOURCE(ctx, handle_index) mock_get_global_mock()
#define DEFINE_MOCK_FUNC_CLIENT_COMMON(name,				       \
				       return_type,			       \
				       RETURN,				       \
				       param_types...)			       \
		DEFINE_MOCK_CLIENT_COMMON(name,				       \
					  MOCK_MAX_PARAMS,		       \
					  FUNC_MOCK_SOURCE,		       \
					  name,				       \
					  return_type,			       \
					  RETURN,			       \
					  param_types)

#define DEFINE_MOCK_FUNC_CLIENT(name, return_type, param_types...)	       \
		DEFINE_MOCK_FUNC_CLIENT_COMMON(name,			       \
					       return_type,		       \
					       CAST_AND_RETURN,		       \
					       param_types)

#define DEFINE_MOCK_FUNC_CLIENT_VOID_RETURN(name, param_types...)	       \
		DEFINE_MOCK_FUNC_CLIENT_COMMON(name,			       \
					       void,			       \
					       NO_RETURN,		       \
					       param_types)

#define DEFINE_MOCK_MASTER_COMMON_INTERNAL(name,			       \
					   ctrl_index,			       \
					   MOCK_SOURCE,			       \
					   param_types...)		       \
		struct mock_expectation *mock_master_##name(		       \
				MATCHER_PARAM_LIST_FROM_TYPES(ctrl_index,      \
							      param_types))    \
		{ \
			struct mock_param_matcher *matchers[] = {	       \
				ARG_NAMES_FROM_TYPES(ctrl_index, param_types)  \
			};						       \
									       \
			return mock_add_matcher(MOCK_SOURCE(ctrl_index),       \
						#name,			       \
						(const void *) name,	       \
						matchers,		       \
						ARRAY_SIZE(matchers));	       \
		}
#define DEFINE_MOCK_MASTER_COMMON(name,					       \
				  ctrl_index,				       \
				  MOCK_SOURCE,				       \
				  param_types...)			       \
		DEFINE_MOCK_MASTER_COMMON_INTERNAL(name,		       \
						   ctrl_index,		       \
						   MOCK_SOURCE,		       \
						   param_types)

#define CLASS_MOCK_MASTER_SOURCE(ctrl_index) arg##ctrl_index
#define DEFINE_MOCK_METHOD_MASTER(name, ctrl_index, param_types...)	       \
		DEFINE_MOCK_MASTER_COMMON(name,				       \
					  ctrl_index,			       \
					  CLASS_MOCK_MASTER_SOURCE,	       \
					  param_types)

#define FUNC_MOCK_CLIENT_SOURCE(ctrl_index) mock_get_global_mock()
#define DEFINE_MOCK_FUNC_MASTER(name, param_types...)			       \
		DEFINE_MOCK_MASTER_COMMON(name,				       \
					  MOCK_MAX_PARAMS,		       \
					  FUNC_MOCK_CLIENT_SOURCE,	       \
					  param_types)

#define DEFINE_MOCK_COMMON(name,					       \
			   handle_index,				       \
			   mock_converter,				       \
			   return_type,					       \
			   param_types...)				       \
		DEFINE_MOCK_METHOD_CLIENT(name,				       \
					  handle_index,			       \
					  mock_converter,		       \
					  return_type,			       \
					  param_types);			       \
		DEFINE_MOCK_METHOD_MASTER(name, handle_index, param_types)

#define DEFINE_MOCK_COMMON_VOID_RETURN(name,				       \
				       handle_index,			       \
				       mock_converter,			       \
				       param_types...)			       \
		DEFINE_MOCK_METHOD_CLIENT_VOID_RETURN(name,		       \
						      handle_index,	       \
						      mock_converter,	       \
						      param_types);	       \
		DEFINE_MOCK_METHOD_MASTER(name, handle_index, param_types)

#define DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX_INTERNAL(name,		       \
						       struct_name,	       \
						       handle_index,	       \
						       return_type,	       \
						       param_types...)	       \
		DEFINE_MOCK_COMMON(name,				       \
				   handle_index,			       \
				   from_##struct_name##_to_mock,	       \
				   return_type, param_types)
#define DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX(name,			       \
					      struct_name,		       \
					      handle_index,		       \
					      return_type,		       \
					      param_types...)		       \
		DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX_INTERNAL(name,	       \
							       struct_name,    \
							       handle_index,   \
							       return_type,    \
							       param_types)

#define DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX_VOID_RETURN_INTERNAL(	       \
		name,							       \
		struct_name,						       \
		handle_index,						       \
		param_types...)						       \
		DEFINE_MOCK_COMMON_VOID_RETURN(name,			       \
					       handle_index,		       \
					       from_##struct_name##_to_mock,   \
					       param_types)
#define DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX_VOID_RETURN(name,		       \
							  struct_name,	       \
							  handle_index,	       \
							  param_types...)      \
		DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX_VOID_RETURN_INTERNAL(    \
				name,					       \
				struct_name,				       \
				handle_index,				       \
				param_types)

/**
 * DEFINE_STRUCT_CLASS_MOCK()
 * @name: name of the method
 * @struct_name: name of the class of which the method belongs
 * @return_type: return type of the method to be created. **Must not be void.**
 * @param_types: parameters to method to be created.
 *
 * See KUNIT_EXPECT_CALL() for example usage.
 */
#define DEFINE_STRUCT_CLASS_MOCK(name,					       \
				 struct_name,				       \
				 return_type,				       \
				 param_types...)			       \
		DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX(name,		       \
						      struct_name,	       \
						      0,		       \
						      return_type,	       \
						      param_types)

/**
 * DEFINE_STRUCT_CLASS_MOCK_VOID_RETURN()
 * @name: name of the method
 * @struct_name: name of the class of which the method belongs
 * @param_types: parameters to method to be created.
 *
 * Same as DEFINE_STRUCT_CLASS_MOCK() except the method has a ``void`` return
 * type.
 */
#define DEFINE_STRUCT_CLASS_MOCK_VOID_RETURN(name, struct_name, param_types...)\
		DEFINE_STRUCT_CLASS_MOCK_HANDLE_INDEX_VOID_RETURN(name,	       \
								  struct_name, \
								  0,	       \
								  param_types)

/**
 * DEFINE_STRUCT_CLASS_MOCK_INIT()
 * @struct_name: name of the class
 * @init_func: a function of type ``int (*)(struct kunit *, struct MOCK(struct_name) *)``.
 *             The function is passed a pointer to an allocated, *but not
 *             initialized*, ``struct MOCK(struct_name)``. The job of this user
 *             provided function is to perform remaining initialization. Usually
 *             this entails assigning mock methods to the function pointers in
 *             the parent struct.
 *
 * See KUNIT_EXPECT_CALL() for example usage.
 */
#define DEFINE_STRUCT_CLASS_MOCK_INIT(struct_name, init_func)		       \
		struct MOCK(struct_name) *MOCK_INIT_ID(struct_name)(	       \
				struct kunit *test)			       \
		{							       \
			struct MOCK(struct_name) *mock_obj;		       \
									       \
			mock_obj = kunit_kzalloc(test,			       \
						sizeof(*mock_obj),	       \
						GFP_KERNEL);		       \
			if (!mock_obj)					       \
				return NULL;				       \
									       \
			mock_init_ctrl(test, mock_get_ctrl(mock_obj));	       \
									       \
			if (init_func(test, mock_obj))			       \
				return NULL;				       \
									       \
			return mock_obj;				       \
		}

struct MOCK(void) {
	struct mock	ctrl;
	void		*trgt;
};

static inline struct mock *from_void_ptr_to_mock(const void *ptr)
{
	struct MOCK(void) *mock_void_ptr = (void *)ptr;

	return mock_get_ctrl(mock_void_ptr);
}

#define DEFINE_VOID_CLASS_MOCK_HANDLE_INDEX_INTERNAL(name,		       \
						     handle_index,	       \
						     return_type,	       \
						     param_types...)	       \
		DEFINE_MOCK_COMMON(name,				       \
				   handle_index,			       \
				   from_void_ptr_to_mock,		       \
				   return_type,				       \
				   param_types)
#define DEFINE_VOID_CLASS_MOCK_HANDLE_INDEX(name,			       \
					    handle_index,		       \
					    return_type,		       \
					    param_types...)		       \
		DEFINE_VOID_CLASS_MOCK_HANDLE_INDEX_INTERNAL(name,	       \
							     handle_index,     \
							     return_type,      \
							     param_types)

DECLARE_STRUCT_CLASS_MOCK_INIT(void);

#define DEFINE_FUNCTION_MOCK_INTERNAL(name, return_type, param_types...)       \
		DEFINE_MOCK_FUNC_CLIENT(name, return_type, param_types);       \
		DEFINE_MOCK_FUNC_MASTER(name, param_types)

/**
 * DEFINE_FUNCTION_MOCK()
 * @name: name of the function
 * @return_type: return type of the function
 * @...: parameter types of the function
 *
 * Same as DEFINE_STRUCT_CLASS_MOCK() except can be used to mock any function
 * declared %__mockable or DEFINE_REDIRECT_MOCKABLE()
 */
#define DEFINE_FUNCTION_MOCK(name, return_type, param_types...) \
		DEFINE_FUNCTION_MOCK_INTERNAL(name, return_type, param_types)

#define DEFINE_FUNCTION_MOCK_VOID_RETURN_INTERNAL(name, param_types...)	       \
		DEFINE_MOCK_FUNC_CLIENT_VOID_RETURN(name, param_types);	       \
		DEFINE_MOCK_FUNC_MASTER(name, param_types)

/**
 * DEFINE_FUNCTION_MOCK_VOID_RETURN()
 * @name: name of the function
 * @...: parameter types of the function
 *
 * Same as DEFINE_FUNCTION_MOCK() except the method has a ``void`` return
 * type.
 */
#define DEFINE_FUNCTION_MOCK_VOID_RETURN(name, param_types...) \
		DEFINE_FUNCTION_MOCK_VOID_RETURN_INTERNAL(name, param_types)

#if IS_ENABLED(CONFIG_KUNIT)

/**
 * __mockable - A function decorator that allows the function to be mocked.
 *
 * Example:
 *
 * .. code-block:: c
 *
 *	int __mockable example(int arg) { ... }
 */
#define __mockable __weak
#define __mockable_alias(id) __weak __alias(id)

/**
 * __visible_for_testing - Makes a static function visible when testing.
 *
 * A macro that replaces the `static` specifier on functions and global
 * variables that is static when compiled normally and visible when compiled for
 * tests.
 */
#define __visible_for_testing
#else
#define __mockable
#define __mockable_alias(id) __alias(id)
#define __visible_for_testing static
#endif

#define CONVERT_TO_ACTUAL_TYPE(type, ptr) (*((type *) ptr))

/**
 * DOC: Built In Matchers
 *
 * These are the matchers that can be used when matching arguments in
 * :c:func:`KUNIT_EXPECT_CALL` (more can be defined manually).
 *
 * For example, there's a matcher that matches any arguments:
 *
 * .. code-block:: c
 *
 *    struct mock_param_matcher *any(struct kunit *test);
 *
 * There are matchers for integers based on the binary condition:
 *
 * * eq: equals to
 * * ne: not equal to
 * * lt: less than
 * * le: less than or equal to
 * * gt: greater than
 * * ge: greater than or equal to
 *
 * .. code-block:: c
 *
 *    struct mock_param_matcher *kunit_int_eq(struct kunit *test, int expected);
 *    struct mock_param_matcher *kunit_int_ne(struct kunit *test, int expected);
 *    struct mock_param_matcher *kunit_int_lt(struct kunit *test, int expected);
 *    struct mock_param_matcher *kunit_int_le(struct kunit *test, int expected);
 *    struct mock_param_matcher *kunit_int_gt(struct kunit *test, int expected);
 *    struct mock_param_matcher *kunit_int_ge(struct kunit *test, int expected);
 *
 * For a detailed list, please see
 * ``include/linux/mock.h``.
 */

/* Matches any argument */
struct mock_param_matcher *kunit_any(struct kunit *test);

/*
 * Matches different types of integers, the argument is compared to the
 * `expected` field, based on the comparison defined.
 */
struct mock_param_matcher *kunit_u8_eq(struct kunit *test, u8 expected);
struct mock_param_matcher *kunit_u8_ne(struct kunit *test, u8 expected);
struct mock_param_matcher *kunit_u8_le(struct kunit *test, u8 expected);
struct mock_param_matcher *kunit_u8_lt(struct kunit *test, u8 expected);
struct mock_param_matcher *kunit_u8_ge(struct kunit *test, u8 expected);
struct mock_param_matcher *kunit_u8_gt(struct kunit *test, u8 expected);

struct mock_param_matcher *kunit_u16_eq(struct kunit *test, u16 expected);
struct mock_param_matcher *kunit_u16_ne(struct kunit *test, u16 expected);
struct mock_param_matcher *kunit_u16_le(struct kunit *test, u16 expected);
struct mock_param_matcher *kunit_u16_lt(struct kunit *test, u16 expected);
struct mock_param_matcher *kunit_u16_ge(struct kunit *test, u16 expected);
struct mock_param_matcher *kunit_u16_gt(struct kunit *test, u16 expected);

struct mock_param_matcher *kunit_u32_eq(struct kunit *test, u32 expected);
struct mock_param_matcher *kunit_u32_ne(struct kunit *test, u32 expected);
struct mock_param_matcher *kunit_u32_le(struct kunit *test, u32 expected);
struct mock_param_matcher *kunit_u32_lt(struct kunit *test, u32 expected);
struct mock_param_matcher *kunit_u32_ge(struct kunit *test, u32 expected);
struct mock_param_matcher *kunit_u32_gt(struct kunit *test, u32 expected);

struct mock_param_matcher *kunit_u64_eq(struct kunit *test, u64 expected);
struct mock_param_matcher *kunit_u64_ne(struct kunit *test, u64 expected);
struct mock_param_matcher *kunit_u64_le(struct kunit *test, u64 expected);
struct mock_param_matcher *kunit_u64_lt(struct kunit *test, u64 expected);
struct mock_param_matcher *kunit_u64_ge(struct kunit *test, u64 expected);
struct mock_param_matcher *kunit_u64_gt(struct kunit *test, u64 expected);

struct mock_param_matcher *kunit_char_eq(struct kunit *test, char expected);
struct mock_param_matcher *kunit_char_ne(struct kunit *test, char expected);
struct mock_param_matcher *kunit_char_le(struct kunit *test, char expected);
struct mock_param_matcher *kunit_char_lt(struct kunit *test, char expected);
struct mock_param_matcher *kunit_char_ge(struct kunit *test, char expected);
struct mock_param_matcher *kunit_char_gt(struct kunit *test, char expected);

struct mock_param_matcher *kunit_uchar_eq(struct kunit *test,
					 unsigned char expected);
struct mock_param_matcher *kunit_uchar_ne(struct kunit *test,
					 unsigned char expected);
struct mock_param_matcher *kunit_uchar_le(struct kunit *test,
					 unsigned char expected);
struct mock_param_matcher *kunit_uchar_lt(struct kunit *test,
					 unsigned char expected);
struct mock_param_matcher *kunit_uchar_ge(struct kunit *test,
					 unsigned char expected);
struct mock_param_matcher *kunit_uchar_gt(struct kunit *test,
					 unsigned char expected);

struct mock_param_matcher *kunit_schar_eq(struct kunit *test,
					 signed char expected);
struct mock_param_matcher *kunit_schar_ne(struct kunit *test,
					 signed char expected);
struct mock_param_matcher *kunit_schar_le(struct kunit *test,
					 signed char expected);
struct mock_param_matcher *kunit_schar_lt(struct kunit *test,
					 signed char expected);
struct mock_param_matcher *kunit_schar_ge(struct kunit *test,
					 signed char expected);
struct mock_param_matcher *kunit_schar_gt(struct kunit *test,
					 signed char expected);

struct mock_param_matcher *kunit_short_eq(struct kunit *test, short expected);
struct mock_param_matcher *kunit_short_ne(struct kunit *test, short expected);
struct mock_param_matcher *kunit_short_le(struct kunit *test, short expected);
struct mock_param_matcher *kunit_short_lt(struct kunit *test, short expected);
struct mock_param_matcher *kunit_short_ge(struct kunit *test, short expected);
struct mock_param_matcher *kunit_short_gt(struct kunit *test, short expected);

struct mock_param_matcher *kunit_ushort_eq(struct kunit *test,
					  unsigned short expected);
struct mock_param_matcher *kunit_ushort_ne(struct kunit *test,
					  unsigned short expected);
struct mock_param_matcher *kunit_ushort_le(struct kunit *test,
					  unsigned short expected);
struct mock_param_matcher *kunit_ushort_lt(struct kunit *test,
					  unsigned short expected);
struct mock_param_matcher *kunit_ushort_ge(struct kunit *test,
					  unsigned short expected);
struct mock_param_matcher *kunit_ushort_gt(struct kunit *test,
					  unsigned short expected);

struct mock_param_matcher *kunit_int_eq(struct kunit *test, int expected);
struct mock_param_matcher *kunit_int_ne(struct kunit *test, int expected);
struct mock_param_matcher *kunit_int_lt(struct kunit *test, int expected);
struct mock_param_matcher *kunit_int_le(struct kunit *test, int expected);
struct mock_param_matcher *kunit_int_gt(struct kunit *test, int expected);
struct mock_param_matcher *kunit_int_ge(struct kunit *test, int expected);

struct mock_param_matcher *kunit_uint_eq(struct kunit *test,
					unsigned int expected);
struct mock_param_matcher *kunit_uint_ne(struct kunit *test,
					unsigned int expected);
struct mock_param_matcher *kunit_uint_lt(struct kunit *test,
					unsigned int expected);
struct mock_param_matcher *kunit_uint_le(struct kunit *test,
					unsigned int expected);
struct mock_param_matcher *kunit_uint_gt(struct kunit *test,
					unsigned int expected);
struct mock_param_matcher *kunit_uint_ge(struct kunit *test,
					unsigned int expected);

struct mock_param_matcher *kunit_long_eq(struct kunit *test, long expected);
struct mock_param_matcher *kunit_long_ne(struct kunit *test, long expected);
struct mock_param_matcher *kunit_long_le(struct kunit *test, long expected);
struct mock_param_matcher *kunit_long_lt(struct kunit *test, long expected);
struct mock_param_matcher *kunit_long_ge(struct kunit *test, long expected);
struct mock_param_matcher *kunit_long_gt(struct kunit *test, long expected);

struct mock_param_matcher *kunit_ulong_eq(struct kunit *test,
					 unsigned long expected);
struct mock_param_matcher *kunit_ulong_ne(struct kunit *test,
					 unsigned long expected);
struct mock_param_matcher *kunit_ulong_le(struct kunit *test,
					 unsigned long expected);
struct mock_param_matcher *kunit_ulong_lt(struct kunit *test,
					 unsigned long expected);
struct mock_param_matcher *kunit_ulong_ge(struct kunit *test,
					 unsigned long expected);
struct mock_param_matcher *kunit_ulong_gt(struct kunit *test,
					 unsigned long expected);

struct mock_param_matcher *kunit_longlong_eq(struct kunit *test,
					    long long expected);
struct mock_param_matcher *kunit_longlong_ne(struct kunit *test,
					    long long expected);
struct mock_param_matcher *kunit_longlong_le(struct kunit *test,
					    long long expected);
struct mock_param_matcher *kunit_longlong_lt(struct kunit *test,
					    long long expected);
struct mock_param_matcher *kunit_longlong_ge(struct kunit *test,
					    long long expected);
struct mock_param_matcher *kunit_longlong_gt(struct kunit *test,
					    long long expected);

struct mock_param_matcher *kunit_ulonglong_eq(struct kunit *test,
					     unsigned long long expected);
struct mock_param_matcher *kunit_ulonglong_ne(struct kunit *test,
					     unsigned long long expected);
struct mock_param_matcher *kunit_ulonglong_le(struct kunit *test,
					     unsigned long long expected);
struct mock_param_matcher *kunit_ulonglong_lt(struct kunit *test,
					     unsigned long long expected);
struct mock_param_matcher *kunit_ulonglong_ge(struct kunit *test,
					     unsigned long long expected);
struct mock_param_matcher *kunit_ulonglong_gt(struct kunit *test,
					     unsigned long long expected);

/* Matches pointers. */
struct mock_param_matcher *kunit_ptr_eq(struct kunit *test, void *expected);
struct mock_param_matcher *kunit_ptr_ne(struct kunit *test, void *expected);
struct mock_param_matcher *kunit_ptr_lt(struct kunit *test, void *expected);
struct mock_param_matcher *kunit_ptr_le(struct kunit *test, void *expected);
struct mock_param_matcher *kunit_ptr_gt(struct kunit *test, void *expected);
struct mock_param_matcher *kunit_ptr_ge(struct kunit *test, void *expected);

/* Matches memory sections and strings. */
struct mock_param_matcher *kunit_memeq(struct kunit *test,
				      const void *buf,
				      size_t size);

struct mock_param_matcher *kunit_streq(struct kunit *test, const char *str);

struct mock_param_matcher *kunit_str_contains(struct kunit *test,
					      const char *needle);

/* Matches var-arg arguments. */
struct mock_param_matcher *kunit_va_format_cmp(
		struct kunit *test,
		struct mock_param_matcher *fmt_matcher,
		struct mock_param_matcher *va_matcher);

struct mock_action *kunit_bool_return(struct kunit *test, bool ret);
struct mock_action *kunit_u8_return(struct kunit *test, u8 ret);
struct mock_action *kunit_u16_return(struct kunit *test, u16 ret);
struct mock_action *kunit_u32_return(struct kunit *test, u32 ret);
struct mock_action *kunit_u64_return(struct kunit *test, u64 ret);
struct mock_action *kunit_char_return(struct kunit *test, char ret);
struct mock_action *kunit_uchar_return(struct kunit *test, unsigned char ret);
struct mock_action *kunit_schar_return(struct kunit *test, signed char ret);
struct mock_action *kunit_short_return(struct kunit *test, short ret);
struct mock_action *kunit_ushort_return(struct kunit *test, unsigned short ret);
struct mock_action *kunit_int_return(struct kunit *test, int ret);
struct mock_action *kunit_uint_return(struct kunit *test, unsigned int ret);
struct mock_action *kunit_long_return(struct kunit *test, long ret);
struct mock_action *kunit_ulong_return(struct kunit *test, unsigned long ret);
struct mock_action *kunit_longlong_return(struct kunit *test, long long ret);
struct mock_action *kunit_ulonglong_return(struct kunit *test,
					  unsigned long long ret);
struct mock_action *kunit_ptr_return(struct kunit *test, void *ret);
/**
 * struct mock_struct_matcher_entry - composed with other &struct
 *                                    mock_struct_matcher_entry to make a
 *                                    &struct struct_matcher
 * @member_offset: offset of this member
 * @matcher: matcher for this particular member
 *
 * This is used for struct_cmp() matchers.
 */
struct mock_struct_matcher_entry {
	size_t member_offset;
	struct mock_param_matcher *matcher;
};

static inline void init_mock_struct_matcher_entry_internal(
		struct mock_struct_matcher_entry *entry,
		size_t offset,
		struct mock_param_matcher *matcher)
{
	entry->member_offset = offset;
	entry->matcher = matcher;
}

/**
 * INIT_MOCK_STRUCT_MATCHER_ENTRY()
 * @entry: the &struct mock_struct_matcher_entry to initialize
 * @type: the struct being matched
 * @member: the member of the struct being matched, used to calculate the offset
 * @matcher: matcher to match that member
 *
 * Initializes ``entry`` to match ``type->member`` with ``matcher``.
 */
#define INIT_MOCK_STRUCT_MATCHER_ENTRY(entry, type, member, matcher)	       \
		init_mock_struct_matcher_entry_internal(entry,		       \
							offsetof(type, member),\
							matcher)

static inline void INIT_MOCK_STRUCT_MATCHER_ENTRY_LAST(
		struct mock_struct_matcher_entry *entry)
{
	entry->matcher = NULL;
}

struct mock_param_matcher *kunit_struct_cmp(
		struct kunit *test,
		const char *struct_name,
		struct mock_struct_matcher_entry *entries);

/**
 * struct mock_param_capturer - used to capture parameter when matching
 *
 * Use the associated helper macros to access relevant fields.
 * Example:
 *
 * .. code-block::c
 *
 *	static int some_test(struct kunit *test)
 *	{
 *		// imagine a mocked function: int add(int a, int b)
 *		struct mock_param_capturer *capturer =
 *			mock_int_capturer_create(test, any(test));
 *		EXPECT_CALL(add(any(test), capturer_to_matcher(capturer)));
 *		ASSERT_PARAM_CAPTURED(test, capturer);
 *
 *		int captured_value = mock_capturer_get(capturer, int);
 *	}
 */
struct mock_param_capturer {
	/* private: internal use only. */
	struct mock_param_matcher matcher;
	struct mock_param_matcher *child_matcher;
	void *(*capture_param)(struct kunit *test, const void *param);
	void *captured_param;
};

struct mock_param_capturer *mock_param_capturer_create(
		struct kunit *test,
		struct mock_param_matcher *child_matcher,
		void *(*capture_param)(struct kunit *, const void *));

/**
 * mock_int_capturer_create() - creates a int parameter capturer
 * @test: associated test
 * @child_matcher: matcher used to match the integer
 *
 * The capturer will capture the value if the matcher is satisfied.
 */
struct mock_param_capturer *mock_int_capturer_create(
		struct kunit *test, struct mock_param_matcher *child_matcher);

/**
 * mock_int_capturer_create() - creates a generic pointer parameter capturer
 * @test: associated test
 * @child_matcher: matcher used to match the pointer
 *
 * The capturer will capture the value if the matcher is satisfied
 */
struct mock_param_capturer *mock_ptr_capturer_create(
		struct kunit *test, struct mock_param_matcher *child_matcher);

/**
 * capturer_to_matcher()
 * @capturer: the param capturer
 *
 * Use this function when passing a capturer into an EXPECT_CALL() where a
 * matcher would be expected. See the example for &struct mock_param_capturer.
 */
#define capturer_to_matcher(capturer) (&(capturer)->matcher)

/**
 * ASSERT_PARAM_CAPTURED(): Asserts that the capturer has captured a parameter.
 * @test: the associated test
 * @capturer: the param capturer
 *
 * See &struct mock_param_capturer for an example.
 */
#define ASSERT_PARAM_CAPTURED(test, capturer)				       \
		ASSERT((struct kunit *)test,				       \
		       !IS_ERR_OR_NULL((capturer)->captured_param),	       \
		       "Asserted " #capturer " captured param, but did not.")

/**
 * mock_capturer_get(): Returns the value captured by ``capturer``
 * @capturer: the param capturer
 * @type: the type of the value
 *
 * See &struct mock_param_capturer for an example.
 */
#define mock_capturer_get(capturer, type) \
		CONVERT_TO_ACTUAL_TYPE(type, (capturer)->captured_param)

struct mock_action *invoke(struct kunit *test,
			   void *(*invokable)(struct kunit *,
					      const void *params[],
					      int len));

/**
 * INVOKE_REAL()
 * @test: associated test
 * @func_name: name of the function
 *
 * See DEFINE_REDIRECT_MOCKABLE() for an example.
 *
 * Return: &struct mock_action that makes the associated mock method or function
 *         call the original function definition of a redirect-mockable
 *         function.
 */
#define INVOKE_REAL(test, func_name) invoke((struct kunit *)test, INVOKE_ID(func_name))

struct mock_struct_formatter_entry {
	size_t member_offset;
	struct mock_param_formatter *formatter;
};

static inline void init_mock_struct_formatter_entry_internal(
		struct mock_struct_formatter_entry *entry,
		size_t offset,
		struct mock_param_formatter *formatter)
{
	entry->member_offset = offset;
	entry->formatter = formatter;
}

#define INIT_MOCK_STRUCT_FORMATTER_ENTRY(entry, type, member, formatter)       \
		init_mock_struct_formatter_entry_internal(entry,	       \
							  offsetof(type,       \
								   member),    \
								   formatter)

static inline void INIT_MOCK_STRUCT_FORMATTER_ENTRY_LAST(
		struct mock_struct_formatter_entry *entry)
{
	entry->formatter = NULL;
}

#define EXPECT_CALL(expectation_call) KUNIT_EXPECT_CALL(expectation_call)

#define any(test) kunit_any((struct kunit *)test)

/*
 * Matches different types of integers, the argument is compared to the
 * `expected` field, based on the comparison defined.
 */
#define u8_eq(test, ...) kunit_u8_eq((struct kunit *)test, ##__VA_ARGS__)
#define u8_ne(test, ...) kunit_u8_ne((struct kunit *)test, ##__VA_ARGS__)
#define u8_le(test, ...) kunit_u8_le((struct kunit *)test, ##__VA_ARGS__)
#define u8_lt(test, ...) kunit_u8_lt((struct kunit *)test, ##__VA_ARGS__)
#define u8_ge(test, ...) kunit_u8_ge((struct kunit *)test, ##__VA_ARGS__)
#define u8_gt(test, ...) kunit_u8_gt((struct kunit *)test, ##__VA_ARGS__)

#define u16_eq(test, ...) kunit_u16_eq((struct kunit *)test, ##__VA_ARGS__)
#define u16_ne(test, ...) kunit_u16_ne((struct kunit *)test, ##__VA_ARGS__)
#define u16_le(test, ...) kunit_u16_le((struct kunit *)test, ##__VA_ARGS__)
#define u16_lt(test, ...) kunit_u16_lt((struct kunit *)test, ##__VA_ARGS__)
#define u16_ge(test, ...) kunit_u16_ge((struct kunit *)test, ##__VA_ARGS__)
#define u16_gt(test, ...) kunit_u16_gt((struct kunit *)test, ##__VA_ARGS__)

#define u32_eq(test, ...) kunit_u32_eq((struct kunit *)test, ##__VA_ARGS__)
#define u32_ne(test, ...) kunit_u32_ne((struct kunit *)test, ##__VA_ARGS__)
#define u32_le(test, ...) kunit_u32_le((struct kunit *)test, ##__VA_ARGS__)
#define u32_lt(test, ...) kunit_u32_lt((struct kunit *)test, ##__VA_ARGS__)
#define u32_ge(test, ...) kunit_u32_ge((struct kunit *)test, ##__VA_ARGS__)
#define u32_gt(test, ...) kunit_u32_gt((struct kunit *)test, ##__VA_ARGS__)

#define u64_eq(test, ...) kunit_u64_eq((struct kunit *)test, ##__VA_ARGS__)
#define u64_ne(test, ...) kunit_u64_ne((struct kunit *)test, ##__VA_ARGS__)
#define u64_le(test, ...) kunit_u64_le((struct kunit *)test, ##__VA_ARGS__)
#define u64_lt(test, ...) kunit_u64_lt((struct kunit *)test, ##__VA_ARGS__)
#define u64_ge(test, ...) kunit_u64_ge((struct kunit *)test, ##__VA_ARGS__)
#define u64_gt(test, ...) kunit_u64_gt((struct kunit *)test, ##__VA_ARGS__)

#define char_eq(test, ...) kunit_char_eq((struct kunit *)test, ##__VA_ARGS__)
#define char_ne(test, ...) kunit_char_ne((struct kunit *)test, ##__VA_ARGS__)
#define char_le(test, ...) kunit_char_le((struct kunit *)test, ##__VA_ARGS__)
#define char_lt(test, ...) kunit_char_lt((struct kunit *)test, ##__VA_ARGS__)
#define char_ge(test, ...) kunit_char_ge((struct kunit *)test, ##__VA_ARGS__)
#define char_gt(test, ...) kunit_char_gt((struct kunit *)test, ##__VA_ARGS__)

#define uchar_eq(test, ...) kunit_uchar_eq((struct kunit *)test, ##__VA_ARGS__)
#define uchar_ne(test, ...) kunit_uchar_ne((struct kunit *)test, ##__VA_ARGS__)
#define uchar_le(test, ...) kunit_uchar_le((struct kunit *)test, ##__VA_ARGS__)
#define uchar_lt(test, ...) kunit_uchar_lt((struct kunit *)test, ##__VA_ARGS__)
#define uchar_ge(test, ...) kunit_uchar_ge((struct kunit *)test, ##__VA_ARGS__)
#define uchar_gt(test, ...) kunit_uchar_gt((struct kunit *)test, ##__VA_ARGS__)

#define schar_eq(test, ...) kunit_schar_eq((struct kunit *)test, ##__VA_ARGS__)
#define schar_ne(test, ...) kunit_schar_ne((struct kunit *)test, ##__VA_ARGS__)
#define schar_le(test, ...) kunit_schar_le((struct kunit *)test, ##__VA_ARGS__)
#define schar_lt(test, ...) kunit_schar_lt((struct kunit *)test, ##__VA_ARGS__)
#define schar_ge(test, ...) kunit_schar_ge((struct kunit *)test, ##__VA_ARGS__)
#define schar_gt(test, ...) kunit_schar_gt((struct kunit *)test, ##__VA_ARGS__)

#define short_eq(test, ...) kunit_short_eq((struct kunit *)test, ##__VA_ARGS__)
#define short_ne(test, ...) kunit_short_ne((struct kunit *)test, ##__VA_ARGS__)
#define short_le(test, ...) kunit_short_le((struct kunit *)test, ##__VA_ARGS__)
#define short_lt(test, ...) kunit_short_lt((struct kunit *)test, ##__VA_ARGS__)
#define short_ge(test, ...) kunit_short_ge((struct kunit *)test, ##__VA_ARGS__)
#define short_gt(test, ...) kunit_short_gt((struct kunit *)test, ##__VA_ARGS__)

#define ushort_eq(test, ...) kunit_ushort_eq((struct kunit *)test, ##__VA_ARGS__)
#define ushort_ne(test, ...) kunit_ushort_ne((struct kunit *)test, ##__VA_ARGS__)
#define ushort_le(test, ...) kunit_ushort_le((struct kunit *)test, ##__VA_ARGS__)
#define ushort_lt(test, ...) kunit_ushort_lt((struct kunit *)test, ##__VA_ARGS__)
#define ushort_ge(test, ...) kunit_ushort_ge((struct kunit *)test, ##__VA_ARGS__)
#define ushort_gt(test, ...) kunit_ushort_gt((struct kunit *)test, ##__VA_ARGS__)

#define int_eq(test, ...) kunit_int_eq((struct kunit *)test, ##__VA_ARGS__)
#define int_ne(test, ...) kunit_int_ne((struct kunit *)test, ##__VA_ARGS__)
#define int_lt(test, ...) kunit_int_lt((struct kunit *)test, ##__VA_ARGS__)
#define int_le(test, ...) kunit_int_le((struct kunit *)test, ##__VA_ARGS__)
#define int_gt(test, ...) kunit_int_gt((struct kunit *)test, ##__VA_ARGS__)
#define int_ge(test, ...) kunit_int_ge((struct kunit *)test, ##__VA_ARGS__)

#define uint_eq(test, ...) kunit_uint_eq((struct kunit *)test, ##__VA_ARGS__)
#define uint_ne(test, ...) kunit_uint_ne((struct kunit *)test, ##__VA_ARGS__)
#define uint_lt(test, ...) kunit_uint_lt((struct kunit *)test, ##__VA_ARGS__)
#define uint_le(test, ...) kunit_uint_le((struct kunit *)test, ##__VA_ARGS__)
#define uint_gt(test, ...) kunit_uint_gt((struct kunit *)test, ##__VA_ARGS__)
#define uint_ge(test, ...) kunit_uint_ge((struct kunit *)test, ##__VA_ARGS__)

#define long_eq(test, ...) kunit_long_eq((struct kunit *)test, ##__VA_ARGS__)
#define long_ne(test, ...) kunit_long_ne((struct kunit *)test, ##__VA_ARGS__)
#define long_le(test, ...) kunit_long_le((struct kunit *)test, ##__VA_ARGS__)
#define long_lt(test, ...) kunit_long_lt((struct kunit *)test, ##__VA_ARGS__)
#define long_ge(test, ...) kunit_long_ge((struct kunit *)test, ##__VA_ARGS__)
#define long_gt(test, ...) kunit_long_gt((struct kunit *)test, ##__VA_ARGS__)

#define ulong_eq(test, ...) kunit_ulong_eq((struct kunit *)test, ##__VA_ARGS__)
#define ulong_ne(test, ...) kunit_ulong_ne((struct kunit *)test, ##__VA_ARGS__)
#define ulong_le(test, ...) kunit_ulong_le((struct kunit *)test, ##__VA_ARGS__)
#define ulong_lt(test, ...) kunit_ulong_lt((struct kunit *)test, ##__VA_ARGS__)
#define ulong_ge(test, ...) kunit_ulong_ge((struct kunit *)test, ##__VA_ARGS__)
#define ulong_gt(test, ...) kunit_ulong_gt((struct kunit *)test, ##__VA_ARGS__)

#define longlong_eq(test, ...) kunit_longlong_eq((struct kunit *)test, ##__VA_ARGS__)
#define longlong_ne(test, ...) kunit_longlong_ne((struct kunit *)test, ##__VA_ARGS__)
#define longlong_le(test, ...) kunit_longlong_le((struct kunit *)test, ##__VA_ARGS__)
#define longlong_lt(test, ...) kunit_longlong_lt((struct kunit *)test, ##__VA_ARGS__)
#define longlong_ge(test, ...) kunit_longlong_ge((struct kunit *)test, ##__VA_ARGS__)
#define longlong_gt(test, ...) kunit_longlong_gt((struct kunit *)test, ##__VA_ARGS__)

#define ulonglong_eq(test, ...) kunit_ulonglong_eq((struct kunit *)test, ##__VA_ARGS__)
#define ulonglong_ne(test, ...) kunit_ulonglong_ne((struct kunit *)test, ##__VA_ARGS__)
#define ulonglong_le(test, ...) kunit_ulonglong_le((struct kunit *)test, ##__VA_ARGS__)
#define ulonglong_lt(test, ...) kunit_ulonglong_lt((struct kunit *)test, ##__VA_ARGS__)
#define ulonglong_ge(test, ...) kunit_ulonglong_ge((struct kunit *)test, ##__VA_ARGS__)
#define ulonglong_gt(test, ...) kunit_ulonglong_gt((struct kunit *)test, ##__VA_ARGS__)

/* matches booleans. */
#define bool_eq(test, ...) do {} while (0)
#define bool_ne(test, ...) do {} while (0)

/* Matches pointers. */
#define ptr_eq(test, ...) kunit_ptr_eq((struct kunit *)test, ##__VA_ARGS__)
#define ptr_ne(test, ...) kunit_ptr_ne((struct kunit *)test, ##__VA_ARGS__)
#define ptr_lt(test, ...) kunit_ptr_lt((struct kunit *)test, ##__VA_ARGS__)
#define ptr_le(test, ...) kunit_ptr_le((struct kunit *)test, ##__VA_ARGS__)
#define ptr_gt(test, ...) kunit_ptr_gt((struct kunit *)test, ##__VA_ARGS__)
#define ptr_ge(test, ...) kunit_ptr_ge((struct kunit *)test, ##__VA_ARGS__)

/* Matches memory sections and strings. */
#define memeq(test, ...) kunit_memeq((struct kunit *)test, ##__VA_ARGS__)
#define streq(test, ...) kunit_streq((struct kunit *)test, ##__VA_ARGS__)

#define str_contains(test, ...) kunit_str_contains((struct kunit *)test, ##__VA_ARGS__)

/* Matches var-arg arguments. */
#define va_format_cmp(test, ...) kunit_va_format_cmp((struct kunit *)test, ##__VA_ARGS__)

/* Compound matchers */
#define and(test, ...) do {} while (0)
#define or(test, ...) do {} while (0)
#define not(test, ...) do {} while (0)

#define bool_return(test, ...) kunit_bool_return((struct kunit *)test, ##__VA_ARGS__)
#define u8_return(test, ...) kunit_u8_return((struct kunit *)test, ##__VA_ARGS__)
#define u16_return(test, ...) kunit_u16_return((struct kunit *)test, ##__VA_ARGS__)
#define u32_return(test, ...) kunit_u32_return((struct kunit *)test, ##__VA_ARGS__)
#define u64_return(test, ...) kunit_u64_return((struct kunit *)test, ##__VA_ARGS__)
#define char_return(test, ...) kunit_char_return((struct kunit *)test, ##__VA_ARGS__)
#define uchar_return(test, ...) kunit_uchar_return((struct kunit *)test, ##__VA_ARGS__)
#define schar_return(test, ...) kunit_schar_return((struct kunit *)test, ##__VA_ARGS__)
#define short_return(test, ...) kunit_short_return((struct kunit *)test, ##__VA_ARGS__)
#define ushort_return(test, ...) kunit_ushort_return((struct kunit *)test, ##__VA_ARGS__)
#define int_return(test, ...) kunit_int_return((struct kunit *)test, ##__VA_ARGS__)
#define uint_return(test, ...) kunit_uint_return((struct kunit *)test, ##__VA_ARGS__)
#define long_return(test, ...) kunit_long_return((struct kunit *)test, ##__VA_ARGS__)
#define ulong_return(test, ...) kunit_ulong_return((struct kunit *)test, ##__VA_ARGS__)
#define longlong_return(test, ...) kunit_longlong_return((struct kunit *)test, ##__VA_ARGS__)
#define ulonglong_return(test, ...) kunit_ulonglong_return((struct kunit *)test, ##__VA_ARGS__)
#define ptr_return(test, ...) kunit_ptr_return((struct kunit *)test, ##__VA_ARGS__)

#endif /* _KUNIT_MOCK_H */
