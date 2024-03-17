/* SPDX-License-Identifier: GPL-2.0 */
/*
 * C++ stream style string formatter and printer used in KUnit for outputting
 * KUnit messages.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#ifndef _KUNIT_KUNIT_STREAM_H
#define _KUNIT_KUNIT_STREAM_H

#include <linux/types.h>
#include <kunit/string-stream.h>

struct kunit;

/**
 * struct kunit_stream - a std::stream style string builder.
 *
 * A std::stream style string builder. Allows messages to be built up and
 * printed all at once. Note that the intention is to only use
 * &struct kunit_stream to communicate with a user of KUnit, most often to
 * communicate something about an expectation or an assertion to the user. If
 * you want a similar interface, but aren't sure if this is the right class for
 * you to use, you probably want to use the related string_stream class, which
 * is allowed for generic string construction in a similar manner. This class is
 * really only for the KUnit library to communicate certain kinds of information
 * to KUnit users and should not be used by anyone else.
 *
 * A note on &struct kunit_stream's usage: a kunit_stream will generally
 * accompany *one* expectation or assertion. Multiple expectations/assertions
 * may be validated concurrently at any given time, even within a single test
 * case, so sharing a kunit_stream between expectations/assertions may result in
 * unintended consequences.
 */
struct kunit_stream {
	/* private: internal use only. */
	struct kunit *test;
	struct string_stream *internal_stream;
};

/**
 * alloc_kunit_stream() - constructs a new &struct kunit_stream.
 * @test: The test context object.
 * @gfp: The GFP flags to use for internal allocations.
 *
 * Constructs a new test managed &struct kunit_stream.
 */
struct kunit_stream *alloc_kunit_stream(struct kunit *test,
					gfp_t gfp);

/**
 * kunit_stream_add(): adds the formatted input to the internal buffer.
 * @kstream: the stream being operated on.
 * @fmt: printf style format string to append to stream.
 *
 * Appends the formatted string, @fmt, to the internal buffer.
 */
void __printf(2, 3) kunit_stream_add(struct kunit_stream *kstream,
				     const char *fmt, ...);

/**
 * kunit_stream_append(): appends the contents of @other to @kstream.
 * @kstream: the stream to which @other is appended.
 * @other: the stream whose contents are appended to @kstream.
 *
 * Appends the contents of @other to @kstream.
 */
void kunit_stream_append(struct kunit_stream *kstream,
			 struct kunit_stream *other);

/**
 * kunit_stream_commit(): prints out the internal buffer to the user.
 * @kstream: the stream being operated on.
 *
 * Outputs the contents of the internal buffer as a kunit_printk formatted
 * output. KUNIT_STREAM ONLY OUTPUTS ITS BUFFER TO THE USER IF COMMIT IS
 * CALLED!!! The reason for this is that it allows us to construct a message
 * before we know whether we want to print it out; this can be extremely handy
 * if there is information you might need for a failure message that is easiest
 * to collect in the steps leading up to the actual check.
 */
void kunit_stream_commit(struct kunit_stream *kstream);

/**
 * kunit_stream_clear(): clears the internal buffer.
 * @kstream: the stream being operated on.
 *
 * Clears the contents of the internal buffer.
 */
void kunit_stream_clear(struct kunit_stream *kstream);

#endif /* _KUNIT_KUNIT_STREAM_H */
