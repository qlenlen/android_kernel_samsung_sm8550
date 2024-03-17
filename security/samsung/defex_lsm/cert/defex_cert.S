/*
 * Copyright (c) 2019 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/export.h>
#include <linux/init.h>
#include <linux/version.h>

	__INITRODATA

.align 8

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || !defined(VMLINUX_SYMBOL))
#define VMLINUX_SYMBOL(name) name
#endif

#define GLOBAL(name)	\
	.globl VMLINUX_SYMBOL(name);	\
	VMLINUX_SYMBOL(name):

	.section ".ref.data", "aw"

GLOBAL(defex_public_key_start)
#ifdef DEFEX_DEBUG_ENABLE
	.incbin "security/samsung/defex_lsm/cert/pubkey_eng.der"
#else
	.incbin "security/samsung/defex_lsm/cert/pubkey_user.der"
#endif
GLOBAL(defex_public_key_end)
