/*
 * Copyright (c) 2020-2022 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>

#include "include/dtm.h"
#include "include/dtm_log.h"
#include "include/dtm_utils.h"

#define DTM_MAX_LOG_SIZE	(1024)
#define DTM_MAX_DETAIL_SIZE	(1024)

#ifdef DEFEX_DSMS_ENABLE
#include <linux/dsms.h>
#else
#define DSMS_SUCCESS (0)
#define dsms_send_message(feature_code, message, value) (DSMS_SUCCESS)
#endif

static inline bool should_send_dsms_event(void)
{
#ifdef DEFEX_DSMS_ENABLE
	return IS_ENABLED(CONFIG_SECURITY_DSMS);
#else
	return false;
#endif
}

__visible_for_testing void dtm_append_argv(char *message, size_t size,
					   char separator,
					   int argc, const char **argv)
{
	const char *from;
	char *to;
	size_t len;
	int arg, available;

	if (!message || size <= 0 || !separator)
		return;
	if (argc <= 0 || !argv || !argv[0])
		return;

	arg = 0;
	len = strnlen(message, size);
	available = size - len - 1;
	to = message + len;
	while (arg < argc && available > 0) {
		from = argv[arg++];
		if (!from)
			from = "(null)";
		len = strnlen(from, available);
		strncpy(to, from, len);
		to += len;
		available -= len;
		if (available-- > 0)
			*to++ = separator;
	}
	*to = 0;
}

__visible_for_testing void dtm_prepare_message(char *message, size_t size,
					       const char *where, const char *sep,
					       struct dtm_context *context)
{
	int total_argc, max_argc, arg;

	/* load all arguments to update attributes and fill arg values */
	total_argc = context->callee_argc;
	max_argc = min_t(int, total_argc, ARRAY_SIZE(context->callee_argv));
	if (context->callee_copied_argc != max_argc)
		for (arg = 0; arg < max_argc; arg++)
			if (!context->callee_argv[arg])
				dtm_get_callee_arg(context, arg);

	snprintf(message, size, "%s%s%d:%d:%ld:%ld:%s:%s:%s:", where, sep,
		 context->callee_copied_argc, total_argc,
		 context->callee_copied_args_len, context->callee_total_args_len,
		 dtm_get_caller_path(context), dtm_get_callee_path(context),
		 dtm_get_stdin_mode(context));
	dtm_append_argv(message, size, ':', max_argc, context->callee_argv);
}

#ifdef DEFEX_DEBUG_ENABLE
void dtm_debug_call(const char *where, struct dtm_context *context)
{
	char message[DTM_MAX_LOG_SIZE];

	dtm_prepare_message(message, sizeof(message), where, ": ", context);
	DTM_LOG_DEBUG("%s", message);
}
#endif

noinline void dtm_report_violation(const char *feature_code,
				   struct dtm_context *context)
{
	char message[DTM_MAX_DETAIL_SIZE + 1];
	int ret;

	dtm_prepare_message(message, sizeof(message), "", "", context);
	DTM_DEBUG(VIOLATIONS, "[%s]%s", feature_code, message);
	if (should_send_dsms_event()) {
		ret = dsms_send_message(feature_code, message, 0);
		if (unlikely(ret != DSMS_SUCCESS))
			DTM_LOG_ERROR("Error %d while sending DSMS report", ret);
	}
}
