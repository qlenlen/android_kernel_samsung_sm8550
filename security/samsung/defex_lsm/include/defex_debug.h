/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
*/

#ifndef __DEFEX_DEBUG_H
#define __DEFEX_DEBUG_H

#define DBG_SETUID		0
#define DBG_SET_FSUID		1
#define DBG_SETGID		2

#define DBG_SET_PE_STATUS	3
#define DBG_SET_IM_STATUS	4
#define DBG_SET_SP_STATUS	5
#define DBG_SET_INT_STATUS	6
#define DBG_GET_LOG		7

#define MAX_DATA_LEN		300

#define DEFEX_LOG_TAG			"[DEFEX] "
#define DEFEX_LOG_BUF_SIZE		(PAGE_SIZE << 0)
#define DEFEX_LOG_BUF_MASK		(DEFEX_LOG_BUF_SIZE - 1)
#define DEFEX_LOG_LEVEL_MASK	(MSG_CRIT | MSG_ERR | MSG_WARN | MSG_INFO | MSG_DEBUG | MSG_TIMEOFF | MSG_BLOB)

enum defex_log_level {
	MSG_CRIT = 1,
	MSG_ERR = 2,
	MSG_WARN = 4,
	MSG_INFO = 8,
	MSG_DEBUG = 16,
	MSG_TIMEOFF = 32,
	MSG_BLOB = 64
};

int defex_create_debug(struct kset *defex_kset);

void blob(const char *title, const char *buffer, const size_t bufLen, const int lineSize);

#ifdef DEFEX_DEBUG_ENABLE
#define defex_log_crit(fmt, ...)       defex_print_msg(MSG_CRIT, fmt, ##__VA_ARGS__)
#define defex_log_err(fmt, ...)        defex_print_msg(MSG_ERR, fmt, ##__VA_ARGS__)
#define defex_log_warn(fmt, ...)       defex_print_msg(MSG_WARN, fmt, ##__VA_ARGS__)
#define defex_log_info(fmt, ...)       defex_print_msg(MSG_INFO, fmt, ##__VA_ARGS__)
#define defex_log_debug(fmt, ...)      defex_print_msg(MSG_DEBUG, fmt, ##__VA_ARGS__)
#define defex_log_timeoff(fmt, ...)    defex_print_msg(MSG_TIMEOFF, fmt, ##__VA_ARGS__)
#define defex_log_blob(fmt, ...)       defex_print_msg(MSG_BLOB, fmt, ##__VA_ARGS__)
void defex_print_msg(const enum defex_log_level msg_type, const char *format, ...);
#else
#define defex_log_crit(fmt, ...)       pr_crit(DEFEX_LOG_TAG fmt "\n", ##__VA_ARGS__)
#define defex_log_err(fmt, ...)        pr_err(DEFEX_LOG_TAG fmt "\n", ##__VA_ARGS__)
#define defex_log_warn(fmt, ...)       pr_warn(DEFEX_LOG_TAG fmt "\n", ##__VA_ARGS__)
#define defex_log_info(fmt, ...)       pr_info(DEFEX_LOG_TAG fmt "\n", ##__VA_ARGS__)
#define defex_log_debug(fmt, ...)      pr_debug(DEFEX_LOG_TAG fmt "\n", ##__VA_ARGS__)
#define defex_log_timeoff(fmt, ...)    pr_info(DEFEX_LOG_TAG fmt "\n", ##__VA_ARGS__)
#define defex_log_blob(fmt, ...)       pr_crit(fmt "\n", ##__VA_ARGS__)
#endif /* DEFEX_DEBUG_ENABLE */

#ifdef DEFEX_LOG_BUFFER_ENABLE
void log_buffer_flush(void);
#endif /* DEFEX_LOG_BUFFER_ENABLE */

#ifdef DEFEX_SHOW_RULES_ENABLE
int defex_show_structure(void *packed_rules, int rules_size);
#endif /* DEFEX_SHOW_RULES_ENABLE */

#endif /* __DEFEX_DEBUG_H */
