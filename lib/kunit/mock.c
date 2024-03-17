// SPDX-License-Identifier: GPL-2.0
/*
 * Mocking API for KUnit.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <kunit/mock.h>

static int mock_void_ptr_init(struct kunit *test, struct MOCK(void) *mock_void_ptr)
{
	mock_void_ptr->trgt = mock_void_ptr;

	return 0;
}

DEFINE_STRUCT_CLASS_MOCK_INIT(void, mock_void_ptr_init);

static bool mock_match_params(struct mock_matcher *matcher,
			      struct kunit_stream *stream,
			      const void **params,
			      int len)
{
	struct mock_param_matcher *param_matcher;
	bool ret = true, tmp;
	int i;

	BUG_ON(matcher->num != len);

	for (i = 0; i < matcher->num; i++) {
		param_matcher = matcher->matchers[i];
		kunit_stream_add(stream, "\t");
		tmp = param_matcher->match(param_matcher, stream, params[i]);
		ret = ret && tmp;
		kunit_stream_add(stream, "\n");
	}

	return ret;
}

static const void *mock_do_expect(struct mock *mock,
				  const char *method_name,
				  const void *method_ptr,
				  const char * const *type_names,
				  const void **params,
				  int len);

static void fail_and_flush(struct kunit *test, struct kunit_stream *stream)
{
	kunit_set_failure(test);
	kunit_stream_commit(stream);
}

void mock_validate_expectations(struct mock *mock)
{
	struct mock_expectation *expectation, *expectation_safe;
	struct kunit_stream *stream;
	struct mock_method *method;
	int times_called;

	stream = alloc_kunit_stream(mock->test, GFP_KERNEL);
	list_for_each_entry(method, &mock->methods, node) {
		list_for_each_entry_safe(expectation, expectation_safe,
					 &method->expectations, node) {
			times_called = expectation->times_called;
			if (!(expectation->min_calls_expected <= times_called &&
			      times_called <= expectation->max_calls_expected)
			    ) {
				kunit_stream_add(stream,
						 "Expectation was not called the specified number of times:\n\t");
				kunit_stream_add(stream,
						 "Function: %s, min calls: %d, max calls: %d, actual calls: %d\n",
						 method->method_name,
						 expectation->min_calls_expected,
						 expectation->max_calls_expected,
						 times_called);
				fail_and_flush(mock->test, stream);
			}
			list_del(&expectation->node);
		}
	}
}

static void mock_validate_wrapper(struct kunit_post_condition *condition)
{
	struct mock *mock = container_of(condition, struct mock, parent);

	mock_validate_expectations(mock);
}

void mock_init_ctrl(struct kunit *test, struct mock *mock)
{
	mock->test = test;
	INIT_LIST_HEAD(&mock->methods);
	mock->do_expect = mock_do_expect;
	mock->type = DEFAULT_MOCK_TYPE;
	mock->parent.validate = mock_validate_wrapper;
	list_add_tail(&mock->parent.node, &test->post_conditions);
}

struct global_mock {
	struct mock ctrl;
	bool is_initialized;
};

static struct global_mock global_mock = {
	.is_initialized = false,
};

static int mock_init_global_mock(struct test_initcall *initcall,
				 struct kunit *test)
{
	BUG_ON(global_mock.is_initialized);

	mock_init_ctrl(test, &global_mock.ctrl);
	global_mock.is_initialized = true;

	return 0;
}

static void mock_exit_global_mock(struct test_initcall *initcall)
{
	BUG_ON(!global_mock.is_initialized);

	global_mock.ctrl.test = NULL;
	global_mock.is_initialized = false;
}

static struct test_initcall global_mock_initcall = {
	.init = mock_init_global_mock,
	.exit = mock_exit_global_mock,
};
test_register_initcall(global_mock_initcall);

struct mock *mock_get_global_mock(void)
{
	BUG_ON(!global_mock.is_initialized);

	return &global_mock.ctrl;
}

static struct mock_method *mock_lookup_method(struct mock *mock,
					      const void *method_ptr)
{
	struct mock_method *ret;

	list_for_each_entry(ret, &mock->methods, node) {
		if (ret->method_ptr == method_ptr)
			return ret;
	}

	return NULL;
}

static struct mock_method *mock_add_method(struct mock *mock,
					   const char *method_name,
					   const void *method_ptr)
{
	struct mock_method *method;

	method = kunit_kzalloc(mock->test, sizeof(*method), GFP_KERNEL);
	if (!method)
		return NULL;

	INIT_LIST_HEAD(&method->expectations);
	method->method_name = method_name;
	method->method_ptr = method_ptr;
	list_add_tail(&method->node, &mock->methods);

	return method;
}

static int mock_add_expectation(struct mock *mock,
				const char *method_name,
				const void *method_ptr,
				struct mock_expectation *expectation)
{
	struct mock_method *method;

	method = mock_lookup_method(mock, method_ptr);
	if (!method) {
		method = mock_add_method(mock, method_name, method_ptr);
		if (!method)
			return -ENOMEM;
	}

	list_add_tail(&expectation->node, &method->expectations);

	return 0;
}

struct mock_expectation *mock_add_matcher(struct mock *mock,
					  const char *method_name,
					  const void *method_ptr,
					  struct mock_param_matcher *matchers[],
					  int len)
{
	struct mock_expectation *expectation;
	struct mock_matcher *matcher;
	int ret;

	expectation = kunit_kzalloc(mock->test,
				   sizeof(*expectation),
				   GFP_KERNEL);
	if (!expectation)
		return NULL;

	matcher = kunit_kmalloc(mock->test, sizeof(*matcher), GFP_KERNEL);
	if (!matcher)
		return NULL;

	memcpy(&matcher->matchers, matchers, sizeof(*matchers) * len);
	matcher->num = len;

	expectation->matcher = matcher;
	expectation->max_calls_expected = 1;
	expectation->min_calls_expected = 1;

	INIT_LIST_HEAD(&expectation->prerequisites);
	ret = mock_add_expectation(mock, method_name, method_ptr, expectation);
	if (ret < 0)
		return NULL;

	return expectation;
}

int mock_set_default_action(struct mock *mock,
			    const char *method_name,
			    const void *method_ptr,
			    struct mock_action *action)
{
	struct mock_method *method;

	method = mock_lookup_method(mock, method_ptr);
	if (!method) {
		method = mock_add_method(mock, method_name, method_ptr);
		if (!method)
			return -ENOMEM;
	}

	method->default_action = action;

	return 0;
}

static void mock_format_param(struct kunit_stream *stream,
			      const char *type_name,
			      const void *param)
{
	/*
	 * Cannot find formatter, so just print the pointer of the
	 * symbol.
	 */
	kunit_stream_add(stream, "<%pS>", param);
}

static void mock_add_method_declaration_to_stream(
		struct kunit_stream *stream,
		const char *function_name,
		const char * const *type_names,
		const void **params,
		int len)
{
	int i;

	kunit_stream_add(stream, "%s(", function_name);
	for (i = 0; i < len; i++) {
		mock_format_param(stream, type_names[i], params[i]);
		if (i < len - 1)
			kunit_stream_add(stream, ", ");
	}
	kunit_stream_add(stream, ")\n");
}

static struct kunit_stream *mock_initialize_failure_message(
		struct kunit *test,
		const char *function_name,
		const char * const *type_names,
		const void **params,
		int len)
{
	struct kunit_stream *stream;

	stream = alloc_kunit_stream(test, GFP_KERNEL);
	if (!stream)
		return NULL;

	kunit_stream_add(stream,
			 "EXPECTATION FAILED: no expectation for call: ");
	mock_add_method_declaration_to_stream(stream,
					      function_name,
					      type_names,
					      params,
					      len);
	return stream;
}

static bool mock_is_expectation_retired(struct mock_expectation *expectation)
{
	return expectation->retire_on_saturation &&
			expectation->times_called ==
			expectation->max_calls_expected;
}

static void mock_add_method_expectation_error(struct kunit *test,
					      struct kunit_stream *stream,
					      char *message,
					      struct mock *mock,
					      struct mock_method *method,
					      const char * const *type_names,
					      const void **params,
					      int len)
{
	kunit_stream_clear(stream);
	kunit_stream_add(stream, message);
	mock_add_method_declaration_to_stream(stream,
		method->method_name, type_names, params, len);
}

static bool mock_are_prereqs_satisfied(struct mock_expectation *expectation,
				       struct kunit_stream *stream)
{
	struct mock_expectation_prereq_entry *entry, *entry_safe;
	int times_called;

	list_for_each_entry_safe(entry, entry_safe,
				 &expectation->prerequisites, node) {
		times_called = entry->expectation->times_called;
		if (!(entry->expectation->min_calls_expected <= times_called &&
		      times_called <= entry->expectation->max_calls_expected)) {
			kunit_stream_add(stream,
				    "Expectation %s matched but prerequisite expectation was not satisfied:\n",
				    expectation->expectation_name);
			kunit_stream_add(stream,
				    "Expectation: \n\tmin calls: %d, max calls: %d, actual calls: %d",
				    entry->expectation->min_calls_expected,
				    entry->expectation->max_calls_expected,
				    entry->expectation->times_called);
			return false;
		}
		/* Don't need to check satisfied prereq again. */
		list_del(&entry->node);
	}
	return true;
}

/* Assumes that the var args are null terminated. */
int mock_in_sequence(struct kunit *test, struct mock_expectation *first, ...)
{
	struct mock_expectation *prereq = first;
	struct mock_expectation *curr = NULL;
	struct mock_expectation_prereq_entry *entry;
	va_list args;

	va_start(args, first);

	RetireOnSaturation(first);

	while ((curr = va_arg(args, struct mock_expectation*))) {
		RetireOnSaturation(curr);
		entry = kunit_kzalloc(test, sizeof(*entry), GFP_KERNEL);
		if (!entry) {
			va_end(args);
			return -ENOMEM;
		}
		entry->expectation = prereq;
		list_add_tail(&entry->node, &curr->prerequisites);
		prereq = curr;
	}
	va_end(args);
	return 0;
}

static inline bool does_mock_expectation_match_call(
	struct mock_expectation *expectation,
	struct kunit_stream *stream,
	const void **params,
	int len)
{
	return mock_match_params(expectation->matcher, stream, params, len) &&
	       mock_are_prereqs_satisfied(expectation, stream);
}

static struct mock_expectation *mock_apply_expectations(
		struct mock *mock,
		struct mock_method *method,
		const char * const *type_names,
		const void **params,
		int len)
{
	struct kunit_stream *attempted_matching_stream;
	bool expectations_all_saturated = true;
	struct kunit *test = mock->test;
	struct kunit_stream *stream = alloc_kunit_stream(test, GFP_KERNEL);
	struct mock_expectation *ret;

	if (list_empty(&method->expectations)) {
		mock_add_method_expectation_error(test, stream,
			"Method was called with no expectations declared: ",
			mock, method, type_names, params, len);
		if (is_strict_mock(mock))
			fail_and_flush(test, stream);
		else if (is_naggy_mock(mock))
			kunit_stream_commit(stream);
		else
			kunit_stream_clear(stream);
		return NULL;
	}

	attempted_matching_stream = mock_initialize_failure_message(
			test,
			method->method_name,
			type_names,
			params,
			len);

	list_for_each_entry(ret, &method->expectations, node) {
		if (mock_is_expectation_retired(ret))
			continue;
		expectations_all_saturated = false;

		kunit_stream_add(attempted_matching_stream,
				 "Tried expectation: %s, but\n",
				 ret->expectation_name);
		if (does_mock_expectation_match_call(ret,
			attempted_matching_stream, params, len)) {
			/*
			 * Matcher was found; we won't print, so clean up the
			 * log.
			 */
			kunit_stream_clear(attempted_matching_stream);
			return ret;
		}
	}

	if (expectations_all_saturated && !is_nice_mock(mock)) {
		mock_add_method_expectation_error(test, stream,
			"Method was called with fully saturated expectations: ",
			mock, method, type_names, params, len);
	} else {
		mock_add_method_expectation_error(test, stream,
			"Method called that did not match any expectations: ",
			mock, method, type_names, params, len);
		kunit_stream_append(stream, attempted_matching_stream);
	}
	fail_and_flush(test, stream);
	kunit_stream_clear(attempted_matching_stream);
	return NULL;
}

static const void *mock_do_expect(struct mock *mock,
				  const char *method_name,
				  const void *method_ptr,
				  const char * const *param_types,
				  const void **params,
				  int len)
{
	struct mock_expectation *expectation;
	struct mock_method *method;
	struct mock_action *action;

	method = mock_lookup_method(mock, method_ptr);
	if (!method)
		return NULL;

	expectation = mock_apply_expectations(mock,
					      method,
					      param_types,
					      params,
					      len);
	if (!expectation) {
		action = method->default_action;
	} else {
		expectation->times_called++;
		if (expectation->action)
			action = expectation->action;
		else
			action = method->default_action;
	}
	if (!action)
		return NULL;

	return action->do_action(action, params, len);
}
