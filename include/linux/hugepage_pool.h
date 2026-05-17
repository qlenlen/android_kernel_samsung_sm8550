/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __INCLUDE_LINUX_HUGEPAGE_POOL_H
#define __INCLUDE_LINUX_HUGEPAGE_POOL_H

#include <linux/sched.h>
#include <linux/oom.h>

#define HUGEPAGE_ORDER HPAGE_PMD_ORDER

enum hpage_type {
	HPAGE_ANON,
	HPAGE_ION,
	HPAGE_GPU,
	HPAGE_TYPE_MAX,
};

extern int use_hugepage_pool_global;

#ifdef CONFIG_HUGEPAGE_POOL
unsigned long total_hugepage_pool_pages(void);
#else
unsigned long total_hugepage_pool_pages(void) { return 0; }
#endif

/* TODO : the below value may vary depending on DRAM size */
#define GB_TO_PAGES(x) ((x) << (30 - PAGE_SHIFT))
#define MAX_ANON_NUM GB_TO_PAGES(2) /* 2GB */
static inline bool check_max_thp_limit_violation(void)
{
	return global_node_page_state(NR_ANON_THPS) >= MAX_ANON_NUM
		? true : false;
}

static inline bool is_hugepage_allowed(struct task_struct *task, int order,
				       bool global_check, enum hpage_type type)
{
#ifndef CONFIG_HUGEPAGE_POOL_ALLOW_ALL
	/* rule #1 : alloc context should have "use_hugepage_pool" flag */
	if (global_check && !use_hugepage_pool_global)
		return false;
#endif

	/* rule #2 : do not allow for native apps */
	if (type == HPAGE_ANON && current->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
		return false;

	/* rule #3 : order should be HUGEPAGE_ORDER */
	if (order != HUGEPAGE_ORDER)
		return false;

	/* rule #4 : check max limit for HPAGE_ANON type */
	if (type == HPAGE_ANON && check_max_thp_limit_violation())
		return false;
	return true;
}
extern struct page *alloc_zeroed_hugepage(gfp_t gfp_mask, int order,
				bool global_check, enum hpage_type type);
extern bool insert_hugepage_pool(struct page *page, int order);
#endif /* _INCLUDE_LINUX_OOM_H */
