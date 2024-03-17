/*
 * Copyright (c) 2020-2022 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _INCLUDE_DTM_LOG_H
#define _INCLUDE_DTM_LOG_H

#define DTM_TAG "[DTM] "
#define DTM_LOG_INFO(format, ...) pr_info(DTM_TAG format, ##__VA_ARGS__)
#define DTM_LOG_ERROR(format, ...) pr_err(DTM_TAG format, ##__VA_ARGS__)
#define DTM_LOG_DEBUG(format, ...) pr_debug(DTM_TAG format, ##__VA_ARGS__)

struct dtm_context;

extern noinline void dtm_report_violation(const char *feature_code,
					  struct dtm_context *context);

#ifdef DEFEX_DEBUG_ENABLE

#define DTM_DEBUG(mode, format, ...)					\
	do {								\
		if (defex_tm_mode_enabled(DEFEX_TM_DEBUG_##mode))	\
			DTM_LOG_DEBUG(format, ##__VA_ARGS__);		\
	} while (0)

#define DTM_DEBUG_CALL(message, context)				\
	do {								\
		if (defex_tm_mode_enabled(DEFEX_TM_DEBUG_CALLS))	\
			dtm_debug_call("dtm_enforce", context);		\
	} while (0)

extern void dtm_debug_call(const char *where, struct dtm_context *context);

#else
#define DTM_DEBUG(mode, format, ...) (0)
#define DTM_DEBUG_CALL(message, context) (0)
#endif /* DEFEX_DEBUG_ENABLE */

#endif /* _INCLUDE_DTM_LOG_H */
