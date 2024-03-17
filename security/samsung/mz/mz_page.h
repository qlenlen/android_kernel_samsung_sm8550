/*
 * Copyright (c) 2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */


#ifndef __MZ_PAGE_H__
#define __MZ_PAGE_H__

#include <linux/kernel.h>
#include <linux/migrate.h>
#include <linux/version.h>

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE
#define _mz_migrate_pages(list, alloc, free) \
		migrate_pages((list), (alloc), (free), 0, MIGRATE_SYNC, MR_MEMORY_FAILURE, 0)
#else
#define _mz_migrate_pages(list, alloc, free) \
		migrate_pages((list), (alloc), (free), 0, MIGRATE_SYNC, MR_MEMORY_FAILURE)
#endif

unsigned long mz_get_migratetype(struct page *page);
MzResult mz_migrate_pages(struct page *page);
MzResult mz_get_user_pages(struct task_struct *task, struct mm_struct *mm, unsigned long va,
							struct page **target_page, int after_mig, uint8_t __user *buf);
void move_page_data(struct page *from, struct page *to);
MzResult mz_migrate_and_pin(struct page *target_page, unsigned long va, uint8_t __user *buf,
							unsigned long *new_pfn, pid_t tgid);
unsigned long mz_ptw(unsigned long va, struct mm_struct *mm);

#endif /* __MZ_PAGE_H__ */
