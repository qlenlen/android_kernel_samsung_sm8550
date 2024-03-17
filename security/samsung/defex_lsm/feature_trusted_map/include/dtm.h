/*
 * Copyright (c) 2020-2022 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _INCLUDE_DTM_H
#define _INCLUDE_DTM_H

#include <linux/binfmts.h>
#include <linux/compiler.h>
#include <linux/defex.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "dtm_utils.h"
#include "include/defex_internal.h"

// DTM Kernel Interface

#define DTM_CALLER_VIOLATION "DTM1"
#define DTM_PROGRAM_VIOLATION "DTM2"
#define DTM_STDIN_VIOLATION "DTM3"
#define DTM_ARGUMENTS_VIOLATION "DTM4"

enum dtm_result_code {
	DTM_ALLOW	= DEFEX_ALLOW,
	DTM_DENY	= -DEFEX_DENY,
};

enum dtm_constants {
	DTM_MAX_ARGC		= 5,	// max args checked (incl. program name)
	DTM_MAX_ARG_STRLEN	= 100,  // max arg len checked (including '\0')
};

struct dtm_context {
	struct defex_context *defex_context;
	void *callee_argv_ref;
	const char *callee_argv[DTM_MAX_ARGC];
	int callee_argc;
	int callee_copied_argc;
	long callee_copied_args_len;
	long callee_total_args_len;
	const char *program_name;
	const char *stdin_mode;
	int stdin_mode_bit;
};

/* Verifies if a dtm_context was properly initialized */
static inline bool is_dtm_context_valid(struct dtm_context *context)
{
	return !ZERO_OR_NULL_PTR(context)
		&& !ZERO_OR_NULL_PTR(context->defex_context)
		&& !ZERO_OR_NULL_PTR(context->defex_context->task)
		&& !ZERO_OR_NULL_PTR(context->callee_argv_ref);
}

/* Gets caller path for current call */
static inline const char *dtm_get_caller_path(struct dtm_context *context)
{
	return get_dc_process_name(context->defex_context);
}

/* Gets callee path for current call */
static inline const char *dtm_get_callee_path(struct dtm_context *context)
{
	return get_dc_target_name(context->defex_context);
}

/* Gets program name for current call */
const char *dtm_get_program_name(struct dtm_context *context);
/* Gets stdin mode bit for current call */
int dtm_get_stdin_mode_bit(struct dtm_context *context);
/* Gets stdin mode for current call */
const char *dtm_get_stdin_mode(struct dtm_context *context);
/* Gets call argument value, copying from user if needed */
const char *dtm_get_callee_arg(struct dtm_context *context, int arg_index);

#endif /* _INCLUDE_DTM_H */
