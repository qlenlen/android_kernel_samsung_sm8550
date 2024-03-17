/*
 * Copyright (c) 2020-2022 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _INCLUDE_DTM_ENGINE_H
#define _INCLUDE_DTM_ENGINE_H

#include "dtm.h"

/* Enforces DTM policy for an exec system call */
extern int dtm_enforce(struct dtm_context *context);
#ifdef DEFEX_KUNIT_ENABLED
/* Replaces DTM policy (use NULL to return to normal) */
extern void dtm_engine_override_data(const unsigned char *);
#endif

#endif /* _INCLUDE_DTM_ENGINE_H */
