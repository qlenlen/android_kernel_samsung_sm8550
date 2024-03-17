// SPDX-License-Identifier: GPL-2.0
/*
 * Common KUnit mock call arg matchers and formatters.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <linux/kernel.h>
#include <kunit/mock.h>

static bool match_any(struct mock_param_matcher *pmatcher,
		      struct kunit_stream *stream,
		      const void *actual)
{
	kunit_stream_add(stream, "don't care");
	return true;
}

static struct mock_param_matcher any_matcher = {
	.match = match_any,
};

struct mock_param_matcher *kunit_any(struct kunit *test)
{
	return &any_matcher;
}

#define DEFINE_MATCHER_STRUCT(type_name, type)				       \
		struct mock_##type_name##_matcher {			       \
			struct mock_param_matcher matcher;		       \
			type expected;					       \
		}

#define DEFINE_TO_MATCHER_STRUCT(type_name)				       \
		struct mock_##type_name##_matcher *			       \
		to_mock_##type_name##_matcher(				       \
				struct mock_param_matcher *matcher)	       \
		{							       \
			return container_of(matcher,			       \
					    struct mock_##type_name##_matcher, \
					    matcher);			       \
		}

#define TYPE_FRMT(type_name) FORMAT_##type_name
#define FORMAT_u8 "%hu"
#define FORMAT_u16 "%hu"
#define FORMAT_u32 "%u"
#define FORMAT_u64 "%llu"
#define FORMAT_char "%c"
#define FORMAT_uchar "%c"
#define FORMAT_schar "%c"
#define FORMAT_short "%hd"
#define FORMAT_ushort "%hu"
#define FORMAT_int "%d"
#define FORMAT_uint "%u"
#define FORMAT_long "%ld"
#define FORMAT_ulong "%lu"
#define FORMAT_longlong "%lld"
#define FORMAT_ulonglong "%llu"
#define FORMAT_ptr "%pK"

#define CMP_FORMAT(type_name, msg, op)                                        \
	       TYPE_FRMT(type_name) msg " " #op " " TYPE_FRMT(type_name)

#define DEFINE_MATCH_FUNC(type_name, type, op_name, op)			       \
		static bool match_##type_name##_##op_name(		       \
				struct mock_param_matcher *pmatcher,	       \
				struct kunit_stream *stream,		       \
				const void *pactual)			       \
		{							       \
			struct mock_##type_name##_matcher *matcher =	       \
				to_mock_##type_name##_matcher(pmatcher);       \
			type actual = *((type *) pactual);		       \
			bool matches = actual op matcher->expected;	       \
									       \
			if (matches)					       \
				kunit_stream_add(stream,		       \
						 CMP_FORMAT(type_name, "", op),\
						 actual,		       \
						 matcher->expected);	       \
			else						       \
				kunit_stream_add(stream,		       \
						 CMP_FORMAT(type_name, " not", op), \
						 actual,		       \
						 matcher->expected);	       \
									       \
			return matches;					       \
		}

#define DEFINE_MATCH_FACTORY(type_name, type, op_name)			       \
		struct mock_param_matcher *kunit_##type_name##_##op_name(      \
				struct kunit *test, type expected)	       \
		{							       \
			struct mock_##type_name##_matcher *matcher;	       \
									       \
			matcher = kunit_kmalloc(test,			       \
					       sizeof(*matcher),	       \
					       GFP_KERNEL);		       \
			if (!matcher)					       \
				return NULL;				       \
									       \
			matcher->matcher.match = match_##type_name##_##op_name;\
			matcher->expected = expected;			       \
			return &matcher->matcher;			       \
		}

#define DEFINE_MATCHER_WITH_TYPENAME(type_name, type)			       \
		DEFINE_MATCHER_STRUCT(type_name, type);			       \
		DEFINE_TO_MATCHER_STRUCT(type_name)			       \
		DEFINE_MATCH_FUNC(type_name, type, eq, ==)		       \
		DEFINE_MATCH_FACTORY(type_name, type, eq)		       \
		DEFINE_MATCH_FUNC(type_name, type, ne, !=)		       \
		DEFINE_MATCH_FACTORY(type_name, type, ne)		       \
		DEFINE_MATCH_FUNC(type_name, type, le, <=)		       \
		DEFINE_MATCH_FACTORY(type_name, type, le)		       \
		DEFINE_MATCH_FUNC(type_name, type, lt, <)		       \
		DEFINE_MATCH_FACTORY(type_name, type, lt)		       \
		DEFINE_MATCH_FUNC(type_name, type, ge, >=)		       \
		DEFINE_MATCH_FACTORY(type_name, type, ge)		       \
		DEFINE_MATCH_FUNC(type_name, type, gt, >)		       \
		DEFINE_MATCH_FACTORY(type_name, type, gt)

#define DEFINE_MATCHER(type) DEFINE_MATCHER_WITH_TYPENAME(type, type)

DEFINE_MATCHER(u8);
DEFINE_MATCHER(u16);
DEFINE_MATCHER(u32);
DEFINE_MATCHER(u64);
DEFINE_MATCHER(char);
DEFINE_MATCHER_WITH_TYPENAME(uchar, unsigned char);
DEFINE_MATCHER_WITH_TYPENAME(schar, signed char);
DEFINE_MATCHER(short);
DEFINE_MATCHER_WITH_TYPENAME(ushort, unsigned short);
DEFINE_MATCHER(int);
DEFINE_MATCHER_WITH_TYPENAME(uint, unsigned int);
DEFINE_MATCHER(long);
DEFINE_MATCHER_WITH_TYPENAME(ulong, unsigned long);
DEFINE_MATCHER_WITH_TYPENAME(longlong, long long);
DEFINE_MATCHER_WITH_TYPENAME(ulonglong, unsigned long long);

DEFINE_MATCHER_WITH_TYPENAME(ptr, void *);

struct mock_memeq_matcher {
	struct mock_param_matcher matcher;
	const void *expected;
	size_t size;
};

static bool match_memeq(struct mock_param_matcher *pmatcher,
			struct kunit_stream *stream,
			const void *pactual)
{
	struct mock_memeq_matcher *matcher =
			container_of(pmatcher,
				     struct mock_memeq_matcher,
				     matcher);
	const void *actual = CONVERT_TO_ACTUAL_TYPE(const void *, pactual);
	bool matches = !memcmp(actual, matcher->expected, matcher->size);
	int i;

	for (i = 0; i < matcher->size; i++)
		kunit_stream_add(stream, "%02x, ", ((const char *) actual)[i]);
	if (matches)
		kunit_stream_add(stream, "== ");
	else
		kunit_stream_add(stream, "!= ");
	for (i = 0; i < matcher->size; i++)
		kunit_stream_add(stream,
			    "%02x, ",
			    ((const char *) matcher->expected)[i]);

	return matches;
}

struct mock_param_matcher *kunit_memeq(struct kunit *test,
				      const void *buf,
				      size_t size)
{
	struct mock_memeq_matcher *matcher;

	matcher = kunit_kzalloc(test, sizeof(*matcher), GFP_KERNEL);
	if (!matcher)
		return NULL;

	matcher->matcher.match = match_memeq;
	matcher->expected = buf;
	matcher->size = size;

	return &matcher->matcher;
}

struct mock_streq_matcher {
	struct mock_param_matcher matcher;
	const char *expected;
};

static bool match_streq(struct mock_param_matcher *pmatcher,
			struct kunit_stream *stream,
			const void *pactual)
{
	struct mock_streq_matcher *matcher =
			container_of(pmatcher,
				     struct mock_streq_matcher,
				     matcher);
	const char *actual = CONVERT_TO_ACTUAL_TYPE(const char *, pactual);
	bool matches = !strcmp(actual, matcher->expected);

	if (matches)
		kunit_stream_add(stream, "%s == %s", actual, matcher->expected);
	else
		kunit_stream_add(stream, "%s != %s", actual, matcher->expected);

	return matches;
}

struct mock_param_matcher *kunit_streq(struct kunit *test, const char *str)
{
	struct mock_streq_matcher *matcher;

	matcher = kunit_kzalloc(test, sizeof(*matcher), GFP_KERNEL);
	if (!matcher)
		return NULL;

	matcher->matcher.match = match_streq;
	matcher->expected = str;

	return &matcher->matcher;
}

struct mock_str_contains_matcher {
	struct mock_param_matcher matcher;
	const char *needle;
};

static bool match_str_contains(struct mock_param_matcher *pmatcher,
			       struct kunit_stream *stream,
			       const void *phaystack)
{
	struct mock_str_contains_matcher *matcher =
		container_of(pmatcher,
			     struct mock_str_contains_matcher,
			     matcher);
	const char *haystack = CONVERT_TO_ACTUAL_TYPE(const char *, phaystack);
	bool matches = strstr(haystack, matcher->needle);

	if (matches)
		kunit_stream_add(stream,
				 "'%s' found in '%s'",
				 matcher->needle,
				 haystack);
	else
		kunit_stream_add(stream,
				 "'%s' not found in '%s'",
				 matcher->needle,
				 haystack);
	return matches;
}

struct mock_param_matcher *kunit_str_contains(struct kunit *test,
					      const char *str)
{
	struct mock_str_contains_matcher *matcher;

	matcher = kunit_kzalloc(test, sizeof(*matcher), GFP_KERNEL);
	if (!matcher)
		return NULL;

	matcher->matcher.match = match_str_contains;
	matcher->needle = str;

	return &matcher->matcher;
}

struct mock_param_matcher *kunit_va_format_cmp(
		struct kunit *test,
		struct mock_param_matcher *fmt_matcher,
		struct mock_param_matcher *va_matcher)
{
	struct mock_struct_matcher_entry *entries;

	entries = kunit_kzalloc(test, sizeof(*entries) * 3, GFP_KERNEL);
	if (!entries)
		return NULL;

	INIT_MOCK_STRUCT_MATCHER_ENTRY(&entries[0],
				       struct va_format,
				       fmt,
				       fmt_matcher);
	INIT_MOCK_STRUCT_MATCHER_ENTRY(&entries[1],
				       struct va_format,
				       va,
				       va_matcher);
	INIT_MOCK_STRUCT_MATCHER_ENTRY_LAST(&entries[2]);

	return kunit_struct_cmp(test, "va_format", entries);
}

struct mock_struct_matcher {
	struct mock_param_matcher matcher;
	const char *struct_name;
	struct mock_struct_matcher_entry *entries;
};

static bool match_struct(struct mock_param_matcher *pmatcher,
			 struct kunit_stream *stream,
			 const void *pactual)
{
	struct mock_struct_matcher *matcher =
			container_of(pmatcher,
				     struct mock_struct_matcher,
				     matcher);
	struct mock_struct_matcher_entry *entry;
	const char *actual = CONVERT_TO_ACTUAL_TYPE(const char *, pactual);
	const char *member_ptr;
	bool matches = true, tmp;

	kunit_stream_add(stream, "struct %s {", matcher->struct_name);
	for (entry = matcher->entries; entry->matcher; entry++) {
		member_ptr = actual + entry->member_offset;
		tmp = entry->matcher->match(entry->matcher, stream, member_ptr);
		matches = matches && tmp;
		kunit_stream_add(stream, ", ");
	}
	kunit_stream_add(stream, "}");

	return matches;
}

struct mock_param_matcher *kunit_struct_cmp(
		struct kunit *test,
		const char *struct_name,
		struct mock_struct_matcher_entry *entries)
{
	struct mock_struct_matcher *matcher;

	matcher = kunit_kzalloc(test, sizeof(*matcher), GFP_KERNEL);
	if (!matcher)
		return NULL;

	matcher->matcher.match = match_struct;
	matcher->struct_name = struct_name;
	matcher->entries = entries;

	return &matcher->matcher;
}

static bool match_and_capture_param(struct mock_param_matcher *pmatcher,
				    struct kunit_stream *stream,
				    const void *param)
{
	struct mock_param_capturer *capturer =
			container_of(pmatcher,
				     struct mock_param_capturer,
				     matcher);
	struct mock_param_matcher *child_matcher = capturer->child_matcher;
	bool matches;

	matches = child_matcher->match(child_matcher, stream, param);
	if (matches)
		capturer->captured_param = capturer->capture_param(stream->test,
								   param);

	return matches;
}

struct mock_param_capturer *mock_param_capturer_create(
		struct kunit *test,
		struct mock_param_matcher *child_matcher,
		void *(*capture_param)(struct kunit *, const void *))
{
	struct mock_param_capturer *capturer;

	capturer = kunit_kzalloc(test, sizeof(*capturer), GFP_KERNEL);
	if (!capturer)
		return NULL;

	capturer->matcher.match = match_and_capture_param;
	capturer->child_matcher = child_matcher;
	capturer->capture_param = capture_param;
	capturer->captured_param = NULL;

	return capturer;
}

static void *mock_capture_int(struct kunit *test, const void *param)
{
	int value = CONVERT_TO_ACTUAL_TYPE(int, param);
	int *pvalue;

	pvalue = kunit_kzalloc(test, sizeof(*pvalue), GFP_KERNEL);
	if (!pvalue)
		return NULL;
	*pvalue = value;

	return pvalue;
}

struct mock_param_capturer *mock_int_capturer_create(
		struct kunit *test, struct mock_param_matcher *child_matcher)
{
	return mock_param_capturer_create(test,
					  child_matcher,
					  mock_capture_int);
}

static void *mock_capture_ptr(struct kunit *test, const void *param)
{
	void *ptr = CONVERT_TO_ACTUAL_TYPE(void *, param);
	void **pptr;

	pptr = kunit_kzalloc(test, sizeof(*pptr), GFP_KERNEL);
	*pptr = ptr;

	return pptr;
}

struct mock_param_capturer *mock_ptr_capturer_create(
		struct kunit *test, struct mock_param_matcher *child_matcher)
{
	return mock_param_capturer_create(test,
					  child_matcher,
					  mock_capture_ptr);
}

#define DEFINE_RETURN_ACTION_STRUCT(type_name, type)			       \
		struct mock_##type_name##_action {			       \
			struct mock_action action;			       \
			type ret;					       \
		}

#define DEFINE_RETURN_ACTION_FUNC(type_name, type)			       \
		void *do_##type_name##_return(struct mock_action *paction,     \
					      const void **params,	       \
					      int len)			       \
		{							       \
			struct mock_##type_name##_action *action =	       \
					container_of(paction,		       \
						     struct mock_##type_name##_action,\
						     action);		       \
									       \
			return (void *) &action->ret;			       \
		}

#define DEFINE_RETURN_ACTION_FACTORY(type_name, type)			       \
		struct mock_action *kunit_##type_name##_return(		       \
				struct kunit *test,			       \
				type ret)				       \
		{							       \
			struct mock_##type_name##_action *action;	       \
									       \
			action = kunit_kmalloc(test,			       \
					      sizeof(*action),		       \
					      GFP_KERNEL);		       \
			if (!action)					       \
				return NULL;				       \
									       \
			action->action.do_action = do_##type_name##_return;    \
			action->ret = ret;				       \
									       \
			return &action->action;				       \
		}

#define DEFINE_RETURN_ACTION_WITH_TYPENAME(type_name, type)		       \
		DEFINE_RETURN_ACTION_STRUCT(type_name, type);		       \
		DEFINE_RETURN_ACTION_FUNC(type_name, type);		       \
		DEFINE_RETURN_ACTION_FACTORY(type_name, type)

#define DEFINE_RETURN_ACTION(type) \
		DEFINE_RETURN_ACTION_WITH_TYPENAME(type, type)

DEFINE_RETURN_ACTION(bool);
DEFINE_RETURN_ACTION(u8);
DEFINE_RETURN_ACTION(u16);
DEFINE_RETURN_ACTION(u32);
DEFINE_RETURN_ACTION(u64);
DEFINE_RETURN_ACTION(char);
DEFINE_RETURN_ACTION_WITH_TYPENAME(uchar, unsigned char);
DEFINE_RETURN_ACTION_WITH_TYPENAME(schar, signed char);
DEFINE_RETURN_ACTION(short);
DEFINE_RETURN_ACTION_WITH_TYPENAME(ushort, unsigned short);
DEFINE_RETURN_ACTION(int);
DEFINE_RETURN_ACTION_WITH_TYPENAME(uint, unsigned int);
DEFINE_RETURN_ACTION(long);
DEFINE_RETURN_ACTION_WITH_TYPENAME(ulong, unsigned long);
DEFINE_RETURN_ACTION_WITH_TYPENAME(longlong, long long);
DEFINE_RETURN_ACTION_WITH_TYPENAME(ulonglong, unsigned long long);
DEFINE_RETURN_ACTION_WITH_TYPENAME(ptr, void *);

struct mock_invoke_action {
	struct mock_action action;
	struct kunit *test;
	void *(*invokable)(struct kunit *test, const void *params[], int len);
};

static void *do_invoke(struct mock_action *paction,
		       const void *params[],
		       int len)
{
	struct mock_invoke_action *action =
			container_of(paction,
				     struct mock_invoke_action,
				     action);

	return action->invokable(action->test, params, len);
}

struct mock_action *invoke(struct kunit *test,
			   void *(*invokable)(struct kunit *,
					      const void *params[],
					      int len))
{
	struct mock_invoke_action *action;

	action = kunit_kmalloc(test, sizeof(*action), GFP_KERNEL);
	if (!action)
		return NULL;

	action->action.do_action = do_invoke;
	action->test = test;
	action->invokable = invokable;

	return &action->action;
}

struct mock_struct_formatter {
	struct mock_param_formatter formatter;
	const char *type_name;
	struct mock_struct_formatter_entry *entries;
};

static void mock_format_struct(struct mock_param_formatter *pformatter,
			       struct kunit_stream *stream,
			       const void *pparam)
{
	struct mock_struct_formatter *formatter =
			container_of(pformatter,
				     struct mock_struct_formatter,
				     formatter);
	struct mock_struct_formatter_entry *entry;
	const char *param = CONVERT_TO_ACTUAL_TYPE(const char *, pparam);
	const char *member_ptr;

	kunit_stream_add(stream, "%s {", formatter->type_name);
	for (entry = formatter->entries; entry->formatter; entry++) {
		member_ptr = param + entry->member_offset;
		entry->formatter->format(entry->formatter, stream, member_ptr);
		kunit_stream_add(stream, ", ");
	}
	kunit_stream_add(stream, "}");
}

struct mock_param_formatter *mock_struct_formatter(
		struct kunit *test,
		const char *type_name,
		struct mock_struct_formatter_entry *entries)
{
	struct mock_struct_formatter *formatter;

	formatter = kunit_kzalloc(test, sizeof(*formatter), GFP_KERNEL);
	if (!formatter)
		return NULL;

	formatter->formatter.type_name = type_name;
	formatter->formatter.format = mock_format_struct;
	formatter->type_name = type_name;
	formatter->entries = entries;

	return &formatter->formatter;
}


