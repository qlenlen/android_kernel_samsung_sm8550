// SPDX-License-Identifier: GPL-2.0
/*
 * C++ stream style string formatter and printer used in KUnit for outputting
 * KUnit messages.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <kunit/test.h>
#include <kunit/kunit-stream.h>
#include <kunit/string-stream.h>

void kunit_stream_add(struct kunit_stream *kstream, const char *fmt, ...)
{
	va_list args;
	struct string_stream *stream = kstream->internal_stream;

	va_start(args, fmt);

	if (string_stream_vadd(stream, fmt, args))
		kunit_err(kstream->test,
			  "Failed to allocate fragment: %s\n",
			  fmt);

	va_end(args);
}
EXPORT_SYMBOL_GPL(kunit_stream_add);

void kunit_stream_append(struct kunit_stream *kstream,
			 struct kunit_stream *other)
{
	int ret;

	ret = string_stream_append(kstream->internal_stream,
				   other->internal_stream);

	if (ret)
		kunit_err(kstream->test,
			  "Failed to append other stream: %d\n", ret);
}

void kunit_stream_clear(struct kunit_stream *kstream)
{
	string_stream_clear(kstream->internal_stream);
}
EXPORT_SYMBOL_GPL(kunit_stream_clear);

void kunit_stream_commit(struct kunit_stream *kstream)
{
	struct string_stream *stream = kstream->internal_stream;
	struct string_stream_fragment *fragment;
	struct kunit *test = kstream->test;
	char *buf;

	buf = string_stream_get_string(stream);
	if (!buf) {
		kunit_err(test,
			  "Could not allocate buffer, dumping stream:\n");
		list_for_each_entry(fragment, &stream->fragments, node) {
			kunit_err(test, "%s", fragment->fragment);
		}
		kunit_err(test, "\n");
	} else {
		kunit_err(test, "%s", buf);
	}

	kunit_stream_clear(kstream);
}
EXPORT_SYMBOL_GPL(kunit_stream_commit);

struct kunit_stream_alloc_context {
	struct kunit *test;
	gfp_t gfp;
};

static int kunit_stream_init(struct kunit_resource *res, void *context)
{
	struct kunit_stream_alloc_context *ctx = context;
	struct kunit_stream *stream;

	stream = kunit_kzalloc(ctx->test, sizeof(*stream), ctx->gfp);
	if (!stream)
		return -ENOMEM;

	stream->test = ctx->test;
	stream->internal_stream = alloc_string_stream(ctx->test, ctx->gfp);
	if (!stream->internal_stream)
		return -ENOMEM;

	res->data = stream;
	return 0;
}

static void kunit_stream_free(struct kunit_resource *res)
{
	/* Do nothing because cleanup is handled by KUnit managed resources */
}

struct kunit_stream *alloc_kunit_stream(struct kunit *test,
					gfp_t gfp)
{
	struct kunit_stream_alloc_context ctx = {
		.test = test,
		.gfp = gfp
	};

	return kunit_alloc_resource(test,
				    kunit_stream_init,
				    kunit_stream_free,
				    gfp,
				    &ctx);
}
EXPORT_SYMBOL_GPL(alloc_kunit_stream);
