/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/bsearch.h>
#include <linux/dsms.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include "dsms_access_control.h"
#include "dsms_kernel_api.h"
#include "dsms_test.h"

typedef int (*cmp_fn_t)(const void *key, const void *element);

/*
 * compare_to_policy_entry_key - compare a function name with the function
 * name of a policy entry
 * @function_name: function name
 * @entry: pointer to the policy entry
 *
 * Returns lexicographic order of the two compared function names
 */
__visible_for_testing int compare_policy_entries(const void *function_name, const void *entry)
{
	return strncmp((const char *)function_name,
		       ((const struct dsms_policy_entry *)entry)->function_name, KSYM_NAME_LEN);
}

/*
 * find_policy_entry - find policy entry
 * @function_name: function name to find
 *
 * Returns a pointer to the policy entry for the given function,
 * or NULL if not found.
 */
__visible_for_testing struct dsms_policy_entry *find_policy_entry(const char *function_name)
{
	void *entry;

	// see: https://github.com/torvalds/linux/blob/master/lib/bsearch.c
	entry = bsearch(function_name,
			dsms_policy,
			dsms_policy_size(),
			sizeof(*dsms_policy),
			(cmp_fn_t) compare_policy_entries);

	return (struct dsms_policy_entry *)entry;
}

int dsms_verify_access(const void *address)
{
	const char *symname;
	unsigned long symsize;
	unsigned long offset;
	char *modname;
	char function_name[KSYM_NAME_LEN+1];
	int index;

	DSMS_LOG_DEBUG("%s: Caller function is %pS (%pF)", __func__,
		       address, address);

	if (!address) {
		DSMS_LOG_ERROR("DENY: invalid caller address.");
		return DSMS_DENY;
	}

	symname = kallsyms_lookup((unsigned long)address,
				  &symsize, &offset, &modname, function_name);
	if (!symname) {
		DSMS_LOG_ERROR("DENY: caller address not in kallsyms.");
		return DSMS_DENY;
	}

	function_name[KSYM_NAME_LEN] = 0;
	DSMS_LOG_DEBUG("%s: kallsyms caller modname = %s, function_name = '%s', offset = 0x%lx",
		       __func__, modname, function_name, offset);

	if (modname != NULL) {
		DSMS_LOG_ERROR("DENY: function '%s' is not a kernel symbol",
			       function_name);
		return DSMS_DENY; // not a kernel symbol
	}

	if (should_ignore_allowlist_suffix()) {
		for (index = 0; index < KSYM_NAME_LEN; index++)
			if ((function_name[index] == '.') || (function_name[index] == 0))
				break;
		function_name[index] = 0;
	}

	if (find_policy_entry(function_name) == NULL) {
		DSMS_LOG_ERROR("DENY: function '%s': is not allowed by policy",
			       function_name);
		return DSMS_DENY;
	}

	return DSMS_SUCCESS;
}
