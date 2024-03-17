/*
 * Memory information needed for address translation in tz driver
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

#ifndef _LINUX_PROCA_MEM_INFO_H
#define _LINUX_PROCA_MEM_INFO_H

#include <linux/proca.h>
#include <linux/types.h>

struct memory_range {
	uint64_t start;
	uint64_t end;
	uint64_t flags;
} __packed;

#define MAX_MEMORY_RANGES_NUM 64ULL

struct proca_config {
	uint32_t version;
	uint32_t size;

	uint64_t va_bits;
	uint64_t va_start;
	uint64_t page_offset;
	uint64_t kimage_vaddr;
	uint64_t kimage_voffset;

	const void *gaf_addr;
	const struct proca_table *proca_table_addr;

	struct memory_range sys_ram_ranges[MAX_MEMORY_RANGES_NUM];
	uint64_t sys_ram_ranges_num;

	uint32_t magic;
} __packed;

int init_proca_config(struct proca_config *conf,
		const struct proca_table *proca_table_addr);

#endif /* _LINUX_PROCA_MEM_INFO_H */
