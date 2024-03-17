/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * FIVE task integrity
 *
 * Copyright (C) 2020 Samsung Electronics, Inc.
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
 * Viacheslav Vovchenko <v.vovchenko@samsung.com>
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
#ifndef __LINUX_FIVE_GKI_FIVE_TINT_DEV_H
#define __LINUX_FIVE_GKI_FIVE_TINT_DEV_H

int __init five_tint_init_dev(void);
void __exit five_tint_deinit_dev(void);

#endif
