/*
 * PROCA logging definitions
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 * Hryhorii Tur, <hryhorii.tur@partner.samsung.com>
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

#ifndef _LINUX_PROCA_LOG_H
#define _LINUX_PROCA_LOG_H

#ifdef CONFIG_PROCA_DEBUG
#define PROCA_DEBUG_LOG(msg, ...) pr_info("PROCA: "msg, ##__VA_ARGS__)
#else
#define PROCA_DEBUG_LOG(msg, ...)
#endif

#define PROCA_ERROR_LOG(msg, ...) pr_err("PROCA: "msg, ##__VA_ARGS__)

#define PROCA_INFO_LOG(msg, ...) pr_info("PROCA: "msg, ##__VA_ARGS__)

#define PROCA_WARN_LOG(msg, ...) pr_warn("PROCA: "msg, ##__VA_ARGS__)

#endif /* _LINUX_PROCA_LOG_H */

