/*
 * five_cert_builtin.S
 *
 * Copyright (C) 2016 Samsung Electronics, Inc.
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/export.h>
#include <linux/init.h>
#include <linux/version.h>

	__INITRODATA

.align 8

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
#define VMLINUX_SYMBOL(name) name
#endif

#define GLOBAL(name)	\
	.globl VMLINUX_SYMBOL(name);	\
	VMLINUX_SYMBOL(name):

#ifdef CONFIG_FIVE_CERT_ENG
GLOBAL(five_local_ca_start_eng)
	.incbin CONFIG_FIVE_CERT_ENG
GLOBAL(five_local_ca_end_eng)
#endif

#ifdef CONFIG_FIVE_CERT_USER
GLOBAL(five_local_ca_start_user)
	.incbin CONFIG_FIVE_CERT_USER
GLOBAL(five_local_ca_end_user)
#endif
