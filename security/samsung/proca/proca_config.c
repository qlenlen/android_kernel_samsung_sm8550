/*
 * Information about kernel needed for proca ta
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

#include <linux/proca.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/version.h>

#include "proca_config.h"
#include "proca_log.h"
#include "proca_porting.h"
#include "gaf/proca_gaf.h"

#define PROCA_CONFIG_VERSION 3U
#define PROCA_CONFIG_MAGIC 0xCD0436EAU

static int append_sys_ram_range(struct resource *res, void *arg)
{
	struct proca_config *conf = arg;

	PROCA_DEBUG_LOG("System RAM region %llx-%llx was found\n",
			res->start, res->end);

	if (conf->sys_ram_ranges_num == MAX_MEMORY_RANGES_NUM) {
		PROCA_ERROR_LOG("Unsupported number of sys ram regions %llu\n",
		       MAX_MEMORY_RANGES_NUM);
		return -ENOMEM;
	}
	conf->sys_ram_ranges[conf->sys_ram_ranges_num].start = res->start;
	conf->sys_ram_ranges[conf->sys_ram_ranges_num].end = res->end;

	++conf->sys_ram_ranges_num;

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 42)
#define __walk_system_ram_res_cb append_sys_ram_range
#else
static int __walk_system_ram_res_cb(u64 start, u64 end, void *arg)
{
	struct resource res;

	res.start = start;
	res.end = end;
	return append_sys_ram_range(&res, arg);
}
#endif

static int prepare_sys_ram_ranges(struct proca_config *conf)
{
	int ret = 0;

	ret = walk_system_ram_res(0, ULONG_MAX, conf, __walk_system_ram_res_cb);
	if (ret)
		conf->sys_ram_ranges_num = 0;

	PROCA_DEBUG_LOG("Found %llu system RAM ranges\n",
			conf->sys_ram_ranges_num);

	return ret;
}

#ifndef PROCA_KUNIT_ENABLED
static void prepare_kernel_constants(struct proca_config *conf)
{
	conf->page_offset = PAGE_OFFSET;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	conf->va_bits = vabits_actual;
#else
	conf->va_bits = VA_BITS;
#endif
	conf->va_start = VA_START;
	conf->kimage_vaddr = get_kimage_vaddr();
	conf->kimage_voffset = get_kimage_voffset();
}
#else
static void prepare_kernel_constants(struct proca_config *conf) {}
#endif

static void dump_proca_config(const struct proca_config *conf)
{
	size_t i;

	PROCA_DEBUG_LOG("version:  %u\n", conf->version);
	PROCA_DEBUG_LOG("size:     %u\n", conf->size);
	PROCA_DEBUG_LOG("magic:    %u\n", conf->magic);

	PROCA_DEBUG_LOG("gaf_addr:         %llx\n", (uint64_t)conf->gaf_addr);
	PROCA_DEBUG_LOG("proca_table_addr: %llx\n", (uint64_t)conf->proca_table_addr);

	PROCA_DEBUG_LOG("page_offset:    %llx\n",  conf->page_offset);
	PROCA_DEBUG_LOG("va_bits:        %llu\n",  conf->va_bits);
	PROCA_DEBUG_LOG("va_start:       %llx\n",  conf->va_start);
	PROCA_DEBUG_LOG("kimage_vaddr:   %llx\n",  conf->kimage_vaddr);
	PROCA_DEBUG_LOG("kimage_voffset: %llx\n",  conf->kimage_voffset);

	PROCA_DEBUG_LOG("Discovered %llu system RAM ranges:\n",
			conf->sys_ram_ranges_num);

	for (i = 0; i < conf->sys_ram_ranges_num; ++i) {
		PROCA_DEBUG_LOG("%llx-%llx.\n",
				conf->sys_ram_ranges[i].start,
				conf->sys_ram_ranges[i].end);
	}
}

int init_proca_config(struct proca_config *conf,
		      const struct proca_table *proca_table_addr)
{
	int ret;

	BUG_ON(!conf || !proca_table_addr);

	prepare_kernel_constants(conf);
	conf->gaf_addr = proca_gaf_get_addr();
	conf->proca_table_addr = proca_table_addr;
	conf->version = PROCA_CONFIG_VERSION;
	conf->size = sizeof(*conf);
	conf->magic = PROCA_CONFIG_MAGIC;
	ret = prepare_sys_ram_ranges(conf);
	if (ret)
		return ret;
	dump_proca_config(conf);
	return ret;
}

