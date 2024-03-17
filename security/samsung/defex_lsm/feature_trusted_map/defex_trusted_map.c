/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include "include/defex_internal.h"

unsigned char global_trusted_map_status = DEFEX_TM_ENFORCING_MODE
#ifdef DEFEX_PERMISSIVE_TM
	| DEFEX_TM_PERMISSIVE_MODE
#endif
	| DEFEX_TM_DEBUG_VIOLATIONS
	;
