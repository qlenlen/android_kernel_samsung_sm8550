/*
 * Copyright (c) 2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/migrate.h>
#include <linux/mmzone.h>
#include <linux/mutex.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/sched/mm.h>
#include "mz_internal.h"
#include "mz_log.h"
#include "mz_page.h"

static inline struct page *mz_migrate_alloc(struct page *page, unsigned long private)
{
	return alloc_page(GFP_KERNEL);
}

static void mz_migrate_free(struct page *page, unsigned long private)
{
	__free_page(page);
}

unsigned long mz_get_migratetype(struct page *page)
{
	struct zone *zone;
	unsigned long flags;
	unsigned long migrate_type;

	// Zone lock must be held to avoid race with
	// set_pageblock_migratetype()
	zone = page_zone(page);
	spin_lock_irqsave(&zone->lock, flags);
	migrate_type = get_pageblock_migratetype(page);
	spin_unlock_irqrestore(&zone->lock, flags);

	return migrate_type;
}

void move_page_data(struct page *from, struct page *to)
{
	void *old_page_addr, *new_page_addr;
#ifdef MZ_DEBUG
	uint64_t opa, npa;
#endif

	old_page_addr = kmap_atomic(from);
	new_page_addr = kmap_atomic(to);
	memcpy(new_page_addr, old_page_addr, PAGE_SIZE);
	memset(old_page_addr, MZ_PAGE_POISON, PAGE_SIZE);

#ifdef MZ_DEBUG
	opa = page_to_phys(from);
	npa = page_to_phys(to);
	MZ_LOG(err_level_debug, "%s %llx %llx\n", __func__, opa, npa);
#endif

	kunmap_atomic(old_page_addr);
	kunmap_atomic(new_page_addr);
}


MzResult mz_migrate_pages(struct page *page)
{
	int res;
	MzResult mz_ret = MZ_SUCCESS;
	LIST_HEAD(pages_list);

	MZ_LOG(err_level_debug, "%s start\n", __func__);

	migrate_prep();

	res = isolate_lru_page(page);
	if (res < 0) {
		MZ_LOG(err_level_error, "%s isolate_lru_page fail %d\n", __func__, res);
		return MZ_PAGE_FAIL;
	}

	list_add_tail(&page->lru, &pages_list);
	put_page(page);
	/* page will be refilled with migrated pages later */
	page = NULL;

	res = _mz_migrate_pages(&pages_list, mz_migrate_alloc, mz_migrate_free);
	if (res) {
		MZ_LOG(err_level_error, "%s migrate fail %d\n", __func__, res);
		putback_movable_pages(&pages_list);
		mz_ret = MZ_PAGE_FAIL;
	}

	MZ_LOG(err_level_debug, "%s end\n", __func__);

	return mz_ret;
}

static __maybe_unused unsigned int gup_flags(int write, int force)
{
	unsigned int flags = 0;

	if (write)
		flags |= FOLL_WRITE;
	if (force)
		flags |= FOLL_FORCE;

	return flags;
}

static int mz_verify_migration_page(struct page *page)
{
	unsigned long migrate_type;

	migrate_type = mz_get_migratetype(page);
	if (migrate_type == MIGRATE_CMA)
		return -EFAULT;

	return 0;
}

MzResult mz_get_user_pages(struct task_struct *task, struct mm_struct *mm, unsigned long va,
							struct page **target_page, int after_mig, uint8_t __user *buf)
{
	int res;
	MzResult mz_ret = MZ_SUCCESS;

	MZ_LOG(err_level_debug, "%s start %llx %d %llx\n", __func__, va, after_mig, (unsigned long)buf);

	res = get_user_pages_remote(task, mm, (unsigned long)buf, 1, gup_flags(1, 0), target_page, NULL, NULL);
	if (res <= 0) {
		MZ_LOG(err_level_error, "%s gup fail %d\n", __func__, res);
		mz_ret = MZ_PAGE_FAIL;
		goto fail;
	}

	if (!after_mig)
		atomic64_inc(&(mm->pinned_vm));

	MZ_LOG(err_level_debug, "%s end\n", __func__);

	return MZ_SUCCESS;

fail:
	put_page(target_page[0]);

	return mz_ret;
}

MzResult mz_migrate_and_pin(struct page *target_page, unsigned long va, uint8_t __user *buf,
							unsigned long *new_pfn, pid_t tgid)
{
	MzResult mz_ret = MZ_SUCCESS;
	struct page *mig_temp = NULL;
	struct page **new_page;
	struct task_struct *task;
	struct mm_struct *mm;
	int res;
	page_node *cur_page;

	task = current;
	mm = get_task_mm(task);
	if (!mm) {
		MZ_LOG(err_level_error, "%s get_task_mm fail\n", __func__);
		return MZ_PAGE_FAIL;
	}
	new_page = kcalloc(1, sizeof(struct page *), GFP_KERNEL);

	/*
	 * Holding 'mm->mmap_sem' is required to synchronize users who try to register same pages simultaneously.
	 * Migration is impossible without synchronization due to page refcount holding by both users.
	 */
	down_write(&mm->mmap_sem);

#ifdef MZ_DEBUG
	if (mz_get_migratetype(target_page) == MIGRATE_CMA)
		MZ_LOG(err_level_debug, "%s target_page is CMA\n", __func__);
#endif

	mz_ret = mz_get_user_pages(task, mm, va, &new_page[0], 0, buf);
	if (mz_ret != MZ_SUCCESS)
		goto out_pfns;

	if (mz_get_migratetype(new_page[0]) == MIGRATE_CMA) {
		mig_temp = alloc_page(GFP_KERNEL);
		move_page_data(target_page, mig_temp);

		mz_ret = mz_migrate_pages(new_page[0]);
		if (mz_ret != MZ_SUCCESS)
			goto out_pin;

		mz_ret = mz_get_user_pages(task, mm, va, &new_page[0], 1, buf);
		if (mz_ret != MZ_SUCCESS)
			goto out_pin;

		res = mz_verify_migration_page(new_page[0]);
		if (res != 0) {
			MZ_LOG(err_level_error, "%s mz_verify_migration_page fail %d\n", __func__, res);
			mz_ret = MZ_PAGE_FAIL;
			goto out_pin;
		}

		*new_pfn = mz_ptw(va, mm);
		if (*new_pfn == 0) {
			MZ_LOG(err_level_error, "%s mz_ptw fail\n", __func__);
			mz_ret = MZ_PAGE_FAIL;
			goto out_pin;
		}

		if (mig_temp) {
			move_page_data(mig_temp, pfn_to_page(*new_pfn));
			__free_page(mig_temp);
		}
	}

	up_write(&mm->mmap_sem);

	cur_page = kmalloc(sizeof(*cur_page), GFP_ATOMIC);
	cur_page->mz_page = new_page;
	INIT_LIST_HEAD(&(cur_page->list));

	mutex_lock(&page_list_lock);
	list_add_tail(&(cur_page->list), &(mz_pt_list[tgid].mz_list_head_page));
	mutex_unlock(&page_list_lock);

	return mz_ret;

out_pin:
	put_page(new_page[0]);
	down_write(&mm->mmap_sem);
	atomic64_dec(&(mm->pinned_vm));
	up_write(&mm->mmap_sem);
out_pfns:
	up_write(&mm->mmap_sem);
	kfree(new_page);
	mmput(mm);

	return mz_ret;
}

unsigned long mz_ptw(unsigned long ava, struct mm_struct *mm)
{
	pte_t pte;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep = NULL;
	unsigned long pfn = 0;

	pgd = pgd_offset(mm, ava);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		MZ_LOG(err_level_error, "%s pgd_offset fail\n", __func__);
		goto out;
	}
	pud = pud_offset(pgd, ava);
	if (pud_none(*pud) || pud_bad(*pud)) {
		MZ_LOG(err_level_error, "%s pud_offset fail\n", __func__);
		goto out;
	}
	pmd = pmd_offset(pud, ava);
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		MZ_LOG(err_level_error, "%s pmd_offset fail\n", __func__);
		goto out;
	}
	ptep = pte_offset_map(pmd, ava);
	if (!ptep) {
		MZ_LOG(err_level_error, "%s pte_offset_map fail\n", __func__);
		goto out;
	}

	pte = *ptep;
	pfn = pte_pfn(pte);

out:
	if (ptep) {
		pte_unmap(ptep);
		ptep = NULL;
	}

	return pfn;
}

