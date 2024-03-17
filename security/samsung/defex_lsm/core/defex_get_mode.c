/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/defex.h>
#include "include/defex_internal.h"

int defex_get_features(void)
{
	int features = 0;
#ifdef DEFEX_PED_ENABLE
#if !defined(DEFEX_PERMISSIVE_PED)
	features |= GLOBAL_PED_STATUS;
#else
	if (global_privesc_status != 0)
		features |= FEATURE_CHECK_CREDS;
	if (global_privesc_status == 2)
		features |= FEATURE_CHECK_CREDS_SOFT;
#endif /* DEFEX_PERMISSIVE_PED */
#endif /* DEFEX_PED_ENABLE */

#ifdef DEFEX_INTEGRITY_ENABLE
#if !defined(DEFEX_PERMISSIVE_INT)
	features |= GLOBAL_INTEGRITY_STATUS;
#else
	if (global_integrity_status != 0)
		features |= FEATURE_INTEGRITY;
	if (global_integrity_status == 2)
		features |= FEATURE_INTEGRITY_SOFT;
#endif /* DEFEX_PERMISSIVE_INT */
#endif /* DEFEX_INTEGRITY_ENABLE */

#ifdef DEFEX_SAFEPLACE_ENABLE
#if !defined(DEFEX_PERMISSIVE_SP)
	features |= GLOBAL_SAFEPLACE_STATUS;
#else
	if (global_safeplace_status != 0)
		features |= FEATURE_SAFEPLACE;
	if (global_safeplace_status == 2)
		features |= FEATURE_SAFEPLACE_SOFT;
#endif /* DEFEX_PERMISSIVE_SP */
#endif /* DEFEX_SAFEPLACE_ENABLE */

#ifdef DEFEX_TRUSTED_MAP_ENABLE
#if !defined(DEFEX_PERMISSIVE_TM)
	features |= GLOBAL_TRUSTED_MAP_STATUS;
#else
	if (global_trusted_map_status != 0)
		features |= FEATURE_TRUSTED_MAP;
	if (global_trusted_map_status & DEFEX_TM_PERMISSIVE_MODE)
		features |= FEATURE_TRUSTED_MAP_SOFT;
#endif /* DEFEX_PERMISSIVE_TM */
#endif /* DEFEX_TRUSTED_MAP_ENABLE */

#ifdef DEFEX_IMMUTABLE_ENABLE
#if !defined(DEFEX_PERMISSIVE_IM)
	features |= GLOBAL_IMMUTABLE_STATUS;
#else
	if (global_immutable_status != 0)
		features |= FEATURE_IMMUTABLE;
	if (global_immutable_status == 2)
		features |= FEATURE_IMMUTABLE_SOFT;
#endif /* DEFEX_PERMISSIVE_IM */
#endif /* DEFEX_IMMUTABLE_ENABLE */
	return features;
}
