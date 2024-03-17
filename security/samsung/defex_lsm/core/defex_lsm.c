/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
*/

#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include "include/defex_caches.h"
#include "include/defex_catch_list.h"
#include "include/defex_debug.h"
#include "include/defex_internal.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#include <linux/bootconfig.h>
#endif

MODULE_DESCRIPTION("Defex Linux Security Module");

bool boot_state_recovery __ro_after_init;

#ifdef DEFEX_DEPENDING_ON_OEMUNLOCK
bool boot_state_unlocked __ro_after_init;
int warranty_bit __ro_after_init;
#endif /* DEFEX_DEPENDING_ON_OEMUNLOCK */

asmlinkage int defex_syscall_enter(long int syscallno, struct pt_regs *regs);
asmlinkage int (* const defex_syscall_catch_enter)(long int syscallno, struct pt_regs *regs) = defex_syscall_enter;
static int defex_init_done __initdata;

asmlinkage int defex_syscall_enter(long int syscallno, struct pt_regs *regs)
{
	long err;
	const struct local_syscall_struct *item;

	if (!current)
		return 0;

#if !defined(__arm__) && defined(CONFIG_COMPAT)
	if (regs->pstate & PSR_MODE32_BIT)
		item = get_local_syscall_compat(syscallno);
	else
#endif /* __arm__ && CONFIG_COMPAT */
		item = get_local_syscall(syscallno);

	if (!item)
		return 0;

	err = item->err_code;
	if (err) {
		if (task_defex_enforce(current, NULL, item->local_syscall))
			return err;
	}
	return 0;
}


#ifdef DEFEX_DEPENDING_ON_OEMUNLOCK
__visible_for_testing int __init verifiedboot_state_setup(char *str)
{
	static const char unlocked[] = "orange";

	if (str && !strncmp(str, unlocked, sizeof(unlocked))) {
		boot_state_unlocked = true;
		defex_log_crit("Device is unlocked and DEFEX will be disabled");
	}
	return 0;
}

__visible_for_testing int __init warrantybit_setup(char *str)
{
	if (get_option(&str, &warranty_bit))
		defex_log_crit("Warranty bit setup");
	return 0;
}

__setup("androidboot.verifiedbootstate=", verifiedboot_state_setup);
__setup("androidboot.warranty_bit=", warrantybit_setup);
#endif /* DEFEX_DEPENDING_ON_OEMUNLOCK */

__visible_for_testing int __init bootstate_recovery_setup(char *str)
{
	if (str && *str == '2') {
		boot_state_recovery = true;
		defex_log_crit("Recovery mode setup");
	}
	return 0;
}
__setup("bootmode=", bootstate_recovery_setup);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
void __init defex_bootconfig_setup(void)
{
	char *value;

#ifdef DEFEX_DEPENDING_ON_OEMUNLOCK
	value = (char *)xbc_find_value("androidboot.verifiedbootstate", NULL);
	verifiedboot_state_setup(value);

	value = (char *)xbc_find_value("androidboot.warranty_bit", NULL);
	warrantybit_setup(value);
#endif /* DEFEX_DEPENDING_ON_OEMUNLOCK */

	value = (char *)xbc_find_value("androidboot.boot_recovery", NULL);
	bootstate_recovery_setup(value);
}
#endif /* LINUX_VERSION_CODE */


//INIT/////////////////////////////////////////////////////////////////////////
__visible_for_testing int __init defex_lsm_init(void)
{
#ifdef DEFEX_DEBUG_ENABLE
	int ret;
#endif /* DEFEX_DEBUG_ENABLE */

#ifdef DEFEX_CACHES_ENABLE
	defex_file_cache_init();
#endif /* DEFEX_CACHES_ENABLE */

#ifdef DEFEX_PED_ENABLE
	creds_fast_hash_init();
#endif /* DEFEX_PED_ENABLE */

#ifdef DEFEX_DEBUG_ENABLE
	ret = defex_init_sysfs();
	if (ret) {
		defex_log_crit("LSM defex_init_sysfs() failed!");
		return ret;
	}
#endif /* DEFEX_DEBUG_ENABLE */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	defex_bootconfig_setup();
#endif /* LINUX_VERSION_CODE */

	defex_log_info("LSM started");
#ifdef DEFEX_LP_ENABLE
	defex_log_info("ADB LP Enabled");
#endif /* DEFEX_LP_ENABLE */
	defex_init_done = 1;
	return 0;
}

__visible_for_testing int __init defex_lsm_load(void)
{
	if (!boot_state_unlocked && defex_init_done)
		do_load_rules();
	return 0;
}

module_init(defex_lsm_init);
late_initcall(defex_lsm_load);
