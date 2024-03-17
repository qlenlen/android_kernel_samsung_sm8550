// SPDX-License-Identifier: GPL-2.0-only
/*
 * PGD allocation/freeing
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_RKP
#include <linux/rkp.h>
#endif
static struct kmem_cache *pgd_cache __ro_after_init;

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	gfp_t gfp = GFP_PGTABLE_USER;
#ifdef CONFIG_RKP
	pgd_t *ret = NULL;

	ret = (pgd_t *) rkp_ro_alloc();

	if (!ret) {
		if (PGD_SIZE == PAGE_SIZE)
			ret = (pgd_t *)__get_free_page(gfp);
		else
			ret = kmem_cache_alloc(pgd_cache, gfp);
	}

	if (unlikely(!ret)) {
		pr_warn("%s: pgd alloc is failed\n", __func__);
		return ret;
	}

	if (rkp_started)
		uh_call(UH_APP_RKP, RKP_PGD_RO, (u64)ret, 0, 0, 0);

	return ret;
#else
	if (PGD_SIZE == PAGE_SIZE)
		return (pgd_t *)__get_free_page(gfp);
	else
		return kmem_cache_alloc(pgd_cache, gfp);
#endif
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
#ifdef CONFIG_RKP
	if (rkp_started)
		uh_call(UH_APP_RKP, RKP_PGD_RW, (u64)pgd, 0, 0, 0);

	/* if pgd memory come from read only buffer, the put it back */
	if (is_rkp_ro_buffer((u64)pgd)) {
		rkp_ro_free((void *)pgd);
	} else {
		if (PGD_SIZE == PAGE_SIZE)
			free_page((unsigned long)pgd);
		else
			kmem_cache_free(pgd_cache, pgd);
	}
#else
	if (PGD_SIZE == PAGE_SIZE)
		free_page((unsigned long)pgd);
	else
		kmem_cache_free(pgd_cache, pgd);
#endif
}

void __init pgtable_cache_init(void)
{
	if (PGD_SIZE == PAGE_SIZE)
		return;

#ifdef CONFIG_ARM64_PA_BITS_52
	/*
	 * With 52-bit physical addresses, the architecture requires the
	 * top-level table to be aligned to at least 64 bytes.
	 */
	BUILD_BUG_ON(PGD_SIZE < 64);
#endif

	/*
	 * Naturally aligned pgds required by the architecture.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_SIZE,
				      SLAB_PANIC, NULL);
}
