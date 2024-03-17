/*
 * Copyright (c) 2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/random.h>
#include <linux/sched/task.h>
#include "mz_internal.h"
#include "mz_log.h"

#define ADDR_INIT_SIZE 56

#ifdef CONFIG_MZ_USE_TZDEV
static void *list_addr_mz;
#elif IS_ENABLED(CONFIG_MZ_USE_QSEECOM)
static void __iomem *list_addr_mz1;
static void __iomem *list_addr_mz2;
static void __iomem *list_addr_mz3;
#endif

bool addrset;

int mz_addr_init(void)
{
	struct device_node *np;
#ifdef CONFIG_MZ_USE_TZDEV
	struct resource res;
#endif
	addr_list = NULL;

#ifdef CONFIG_MZ_USE_TZDEV
	np = of_find_compatible_node(NULL, NULL, "sboot,mz");
	if (unlikely(!np)) {
		MZ_LOG(err_level_error, "unable to find DT imem sboot,mz node\n");
		return -ENODEV;
	}

	if (of_address_to_resource(np, 0, &res)) {
		MZ_LOG(err_level_error, "%s of_address_to_resource fail\n", __func__);
		return -ENODEV;
	}
	list_addr_mz = phys_to_virt(res.start);
#elif IS_ENABLED(CONFIG_MZ_USE_QSEECOM)
	np = of_find_compatible_node(NULL, NULL, "samsung,security_mz1");
	if (unlikely(!np)) {
		MZ_LOG(err_level_error, "unable to find DT imem samsung,security_mz1 node\n");
		return -ENODEV;
	}

	list_addr_mz1 = of_iomap(np, 0);
	if (unlikely(!list_addr_mz1)) {
		MZ_LOG(err_level_error, "unable to map imem samsung,security_mz1 offset\n");
		return -ENODEV;
	}

	np = of_find_compatible_node(NULL, NULL, "samsung,security_mz2");
	if (unlikely(!np)) {
		MZ_LOG(err_level_error, "unable to find DT imem samsung,security_mz2 node\n");
		return -ENODEV;
	}

	list_addr_mz2 = of_iomap(np, 0);
	if (unlikely(!list_addr_mz2)) {
		MZ_LOG(err_level_error, "unable to map imem samsung,security_mz2 offset\n");
		return -ENODEV;
	}

	np = of_find_compatible_node(NULL, NULL, "samsung,security_mz3");
	if (unlikely(!np)) {
		MZ_LOG(err_level_error, "unable to find DT imem samsung,security_mz3 node\n");
		return -ENODEV;
	}

	list_addr_mz3 = of_iomap(np, 0);
	if (unlikely(!list_addr_mz3)) {
		MZ_LOG(err_level_error, "unable to map imem samsung,security_mz3 offset\n");
		return -ENODEV;
	}

	MZ_LOG(err_level_debug, "list addr1 : 0x%pK(0x%llx)\n", list_addr_mz1,
			(unsigned long long)virt_to_phys(list_addr_mz1));
	MZ_LOG(err_level_debug, "list addr2 : 0x%pK(0x%llx)\n", list_addr_mz2,
			(unsigned long long)virt_to_phys(list_addr_mz2));
	MZ_LOG(err_level_debug, "list addr3 : 0x%pK(0x%llx)\n", list_addr_mz3,
			(unsigned long long)virt_to_phys(list_addr_mz3));
#else
	MZ_LOG(err_level_error, "%s no tz config\n", __func__);
#endif

	addr_list = kmalloc(sizeof(uint64_t) * ADDR_INIT_SIZE, GFP_KERNEL);

	addr_list[0] = 0;
	get_random_bytes(&(addr_list[1]), sizeof(addr_list[1]) * 2);
	addr_list_count_max = ADDR_INIT_SIZE;

	MZ_LOG(err_level_debug, "%s iv %llx %llx\n", __func__, addr_list[1], addr_list[2]);

	addrset = false;

	return MZ_SUCCESS;
}

int set_mz_mem(void)
{
	unsigned long long addr_list1, addr_list2;
	uint32_t mz_magic = 0x4D5A4D5A;

	MZ_LOG(err_level_debug, "set_mz_mem start\n");

	if (!addr_list) {
		MZ_LOG(err_level_error, "%s list_addr null\n", __func__);
		return MZ_GENERAL_ERROR;
	}

	addr_list1 = (unsigned long long)virt_to_phys(addr_list);
	addr_list2 = addr_list1 >> 32;

#ifdef CONFIG_MZ_USE_TZDEV
	memcpy(list_addr_mz, &addr_list1, 4);
	memcpy(list_addr_mz+4, &addr_list2, 4);
	memcpy(list_addr_mz+8, &mz_magic, 4);
#elif IS_ENABLED(CONFIG_MZ_USE_QSEECOM)
	if (unlikely(!list_addr_mz1) || unlikely(!list_addr_mz2) || unlikely(!list_addr_mz3)) {
		MZ_LOG(err_level_error, "list_addr address unmapped\n");
		return MZ_GENERAL_ERROR;
	}
	__raw_writel(addr_list1, list_addr_mz1);
	__raw_writel(addr_list2, list_addr_mz2);
	__raw_writel(mz_magic, list_addr_mz3);
#else
	MZ_LOG(err_level_error, "%s mz_magic set fail\n", __func__);
#endif

	MZ_LOG(err_level_debug, "addr_list addr : (0x%llx) (0x%llx) (0x%llx)\n",
			addr_list1, addr_list2, (unsigned long long)virt_to_phys(addr_list));

	addrset = true;

	return MZ_SUCCESS;
}

bool isaddrset(void)
{
	return addrset;
}
