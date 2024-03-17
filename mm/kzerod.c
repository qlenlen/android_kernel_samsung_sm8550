// SPDX-License-Identifier: GPL-2.0
/*
 * linux/mm/kzerod.c
 *
 * Copyright (C) 2019 Samsung Electronics
 *
 */
#include <uapi/linux/sched/types.h>
#include <linux/suspend.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/ratelimit.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/memblock.h>
#include "internal.h"

#ifdef CONFIG_KZEROD_ENABLE
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/migrate.h>
#endif

static bool kzerod_enabled = true;

#define K(x) ((x) << (PAGE_SHIFT-10))
#define GB_TO_PAGES(x) ((x) << (30 - PAGE_SHIFT))
#define MB_TO_PAGES(x) ((x) << (20 - PAGE_SHIFT))

#ifdef CONFIG_KZEROD_ENABLE
static struct task_struct *task_kzerod;
DECLARE_WAIT_QUEUE_HEAD(kzerod_wait);

enum kzerod_enum_state {
	KZEROD_RUNNING = 0,
	KZEROD_SLEEP_DONE,
	KZEROD_SLEEP_NOMEM,
	KZEROD_SLEEP_DISABLED,
};
static enum kzerod_enum_state kzerod_state = KZEROD_SLEEP_DONE;

static LIST_HEAD(prezeroed_list);
static spinlock_t prezeroed_lock;
static unsigned long nr_prezeroed;
static unsigned long kzerod_wmark_high;
static unsigned long kzerod_wmark_low;
static void try_wake_up_kzerod(void);
#endif

static bool app_launch;

static bool need_pause(void)
{
	if (app_launch || need_memory_boosting())
		return true;

	return false;
}

#ifdef CONFIG_HUGEPAGE_POOL
static void try_wake_up_hugepage_kzerod(void);
#endif

static int kzerod_app_launch_notifier(struct notifier_block *nb,
					 unsigned long action, void *data)
{
	bool prev_launch;

	prev_launch = app_launch;
	app_launch = action ? true : false;

	if (prev_launch && !app_launch) {
		if (kzerod_enabled) {
#ifdef CONFIG_KZEROD_ENABLE
			try_wake_up_kzerod();
#endif
#ifdef CONFIG_HUGEPAGE_POOL
			try_wake_up_hugepage_kzerod();
#endif
		}
	}

	return 0;
}

static struct notifier_block kzerod_app_launch_nb = {
	.notifier_call = kzerod_app_launch_notifier,
};

#ifdef CONFIG_KZEROD_ENABLE
unsigned long kzerod_get_zeroed_size(void)
{
	return nr_prezeroed;
}

static unsigned long kzerod_totalram[] = {
	GB_TO_PAGES(4),
};
static unsigned long kzerod_wmark[] = {
	MB_TO_PAGES(50),
};
#define KZEROD_MAX_WMARK	MB_TO_PAGES(50)

static inline void kzerod_update_wmark(void)
{
	static unsigned long kzerod_totalram_pages;
	int i, array_size;
	unsigned long totalram;

	totalram = totalram_pages();
	if (!kzerod_totalram_pages || kzerod_totalram_pages != totalram) {
		kzerod_totalram_pages = totalram;

		array_size = ARRAY_SIZE(kzerod_totalram);
		for (i = 0; i < array_size; i++) {
			if (totalram <= kzerod_totalram[i]) {
				kzerod_wmark_high = kzerod_wmark[i];
				break;
			}
		}
		if (i == array_size)
			kzerod_wmark_high = KZEROD_MAX_WMARK;
		kzerod_wmark_low = kzerod_wmark_high >> 1;
	}
}

static inline bool kzerod_wmark_high_ok(void)
{
	return nr_prezeroed >= kzerod_wmark_high;
}

static inline bool kzerod_wmark_low_ok(void)
{
	return nr_prezeroed >= kzerod_wmark_low;
}

static struct vfsmount *kzerod_mnt;
static struct inode *kzerod_inode;

/* should be called with page lock */
static inline void set_kzerod_page(struct page *page)
{
	__SetPageMovable(page, kzerod_inode->i_mapping);
}

/* should be called with page lock */
static inline void unset_kzerod_page(struct page *page)
{
	__ClearPageMovable(page);
}

static void try_wake_up_kzerod(void)
{
	if (need_pause())
		return;

	if (!kzerod_wmark_low_ok() && (kzerod_state != KZEROD_RUNNING)) {
		kzerod_state = KZEROD_RUNNING,
		wake_up(&kzerod_wait);
	}
}

struct page *alloc_zeroed_page(void)
{
	struct page *page = NULL;

	if (!kzerod_enabled)
		return NULL;

	if (unlikely(!spin_trylock(&prezeroed_lock)))
		return NULL;
	if (!list_empty(&prezeroed_list)) {
		page = list_first_entry(&prezeroed_list, struct page, lru);
		if (trylock_page(page)) {
			list_del(&page->lru);
			unset_kzerod_page(page);
			/* The page will be served soon. Let's clean it up */
			page->mapping = NULL;
			unlock_page(page);
			nr_prezeroed--;
		} else {
			page = NULL;
		}
	}
	spin_unlock(&prezeroed_lock);

	try_wake_up_kzerod();

	/*
	 * putback to prezereoed list and return NULL
	 * if page is being touched by migration context
	 */
	if (page && page_count(page) != 1) {
		lock_page(page);
		spin_lock(&prezeroed_lock);
		set_kzerod_page(page);
		list_add_tail(&page->lru, &prezeroed_list);
		nr_prezeroed++;
		spin_unlock(&prezeroed_lock);
		unlock_page(page);
		page = NULL;
	}

	return page;
}

static void drain_zeroed_page(void)
{
	struct page *page, *next;
	unsigned long prev_zero;

	prev_zero = nr_prezeroed;
restart:
	spin_lock(&prezeroed_lock);
	list_for_each_entry_safe(page, next, &prezeroed_list, lru) {
		if (trylock_page(page)) {
			list_del(&page->lru);
			unset_kzerod_page(page);
			unlock_page(page);
			__free_pages(page, 0);
			nr_prezeroed--;
		} else {
			spin_unlock(&prezeroed_lock);
			goto restart;
		}
	}
	spin_unlock(&prezeroed_lock);
}

/* page is already locked before this function is called */
bool kzerod_page_isolate(struct page *page, isolate_mode_t mode)
{
	bool ret = true;

	BUG_ON(!PageMovable(page));
	BUG_ON(PageIsolated(page));

	spin_lock(&prezeroed_lock);
	/* kzerod page must be in the prezeroed_list at this point */
	list_del(&page->lru);
	nr_prezeroed--;
	spin_unlock(&prezeroed_lock);

	return ret;
}

/* page and newpage are already locked before this function is called */
int kzerod_page_migrate(struct address_space *mapping, struct page *newpage,
		struct page *page, enum migrate_mode mode)
{
	int ret = MIGRATEPAGE_SUCCESS;
	void *s_addr, *d_addr;

	BUG_ON(!PageMovable(page));
	BUG_ON(!PageIsolated(page));

	/* set the newpage attributes and copy content from page to newpage */
	get_page(newpage);
	set_kzerod_page(newpage);
	s_addr = kmap_atomic(page);
	d_addr = kmap_atomic(newpage);
	memcpy(d_addr, s_addr, PAGE_SIZE);
	kunmap_atomic(d_addr);
	kunmap_atomic(s_addr);

	/* clear the original page attributes */
	unset_kzerod_page(page);
	put_page(page);

	/* put the newpage into the list again */
	spin_lock(&prezeroed_lock);
	list_add(&newpage->lru, &prezeroed_list);
	nr_prezeroed++;
	spin_unlock(&prezeroed_lock);

	return ret;
}

/* page is already locked before this function is called */
void kzerod_page_putback(struct page *page)
{
	BUG_ON(!PageMovable(page));
	BUG_ON(!PageIsolated(page));

	/* put the page into the list again */
	spin_lock(&prezeroed_lock);
	list_add(&page->lru, &prezeroed_list);
	nr_prezeroed++;
	spin_unlock(&prezeroed_lock);
}

const struct address_space_operations kzerod_aops = {
	.isolate_page = kzerod_page_isolate,
	.migratepage = kzerod_page_migrate,
	.putback_page = kzerod_page_putback,
};

static int kzerod_register_migration(void)
{
	kzerod_inode = alloc_anon_inode(kzerod_mnt->mnt_sb);
	if (IS_ERR(kzerod_inode)) {
		kzerod_inode = NULL;
		return 1;
	}

	kzerod_inode->i_mapping->a_ops = &kzerod_aops;
	return 0;
}

static void kzerod_unregister_migration(void)
{
	iput(kzerod_inode);
}

static char *kzerodfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(dentry, buffer, buflen, "kzerodfs:[%lu]",
				d_inode(dentry)->i_ino);
}

static int kzerod_init_fs_context(struct fs_context *fc)
{
	static const struct dentry_operations ops = {
		.d_dname = kzerodfs_dname,
	};
	struct pseudo_fs_context *ctx = init_pseudo(fc, KZEROD_MAGIC);

	if (!ctx)
		return -ENOMEM;
	ctx->dops = &ops;
	return 0;
}

static struct file_system_type kzerod_fs = {
	.name		= "kzerod",
	.init_fs_context = kzerod_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static int kzerod_mount(void)
{
	int ret = 0;

	kzerod_mnt = kern_mount(&kzerod_fs);
	if (IS_ERR(kzerod_mnt)) {
		ret = PTR_ERR(kzerod_mnt);
		kzerod_mnt = NULL;
	}

	return ret;
}

static void kzerod_unmount(void)
{
	kern_unmount(kzerod_mnt);
}


static int kzerod_zeroing(void)
{
	struct page *page;
	int ret;
	gfp_t gfp_mask;

	kzerod_update_wmark();
	gfp_mask = (GFP_HIGHUSER_MOVABLE & ~__GFP_DIRECT_RECLAIM) | __GFP_ZERO
			| __GFP_NOWARN;
#if defined(__GFP_CMA)
	gfp_mask |= __GFP_CMA;
#endif
	while (true) {
		if (!kzerod_enabled) {
			ret = -ENODEV;
			break;
		}
		if (need_pause()) {
			ret = -ENODEV;
			break;
		}
		if (kzerod_wmark_high_ok()) {
			ret = 0;
			break;
		}
		page = alloc_pages(gfp_mask, 0);
		if (!page) {
			ret = -ENOMEM;
			break;
		}
		lock_page(page);
		spin_lock(&prezeroed_lock);
		set_kzerod_page(page);
		list_add(&page->lru, &prezeroed_list);
		nr_prezeroed++;
		spin_unlock(&prezeroed_lock);
		unlock_page(page);
	}
	return ret;
}

static int kzerod(void *p)
{
	int ret;

	kzerod_update_wmark();
	while (true) {
		wait_event_freezable(kzerod_wait,
				     kzerod_state == KZEROD_RUNNING);
		ret = kzerod_zeroing();
		switch (ret) {
		case 0:
			kzerod_state = KZEROD_SLEEP_DONE;
			break;
		case -ENOMEM:
			kzerod_state = KZEROD_SLEEP_NOMEM;
			break;
		case -ENODEV:
			kzerod_state = KZEROD_SLEEP_DISABLED;
			break;
		}
	}

	return 0;
}
#endif

#ifdef CONFIG_HUGEPAGE_POOL
#include <linux/hugepage_pool.h>
int use_hugepage_pool_global;

DECLARE_WAIT_QUEUE_HEAD(hugepage_kzerod_wait);
static struct list_head hugepage_list[MAX_NR_ZONES];
static struct list_head hugepage_nonzero_list[MAX_NR_ZONES];
int nr_hugepages_quota[MAX_NR_ZONES];
int nr_hugepages_limit[MAX_NR_ZONES];
int nr_hugepages[MAX_NR_ZONES];
int nr_hugepages_nonzero[MAX_NR_ZONES];
int nr_hugepages_tried[MAX_NR_ZONES];
int nr_hugepages_alloced[MAX_NR_ZONES];
int nr_hugepages_alloced_types[HPAGE_TYPE_MAX];
int nr_hugepages_fill_tried[MAX_NR_ZONES];
int nr_hugepages_fill_done[MAX_NR_ZONES];
static spinlock_t hugepage_list_lock[MAX_NR_ZONES];
static spinlock_t hugepage_nonzero_list_lock[MAX_NR_ZONES];

/* free pool if available memory is below this value */
static unsigned long hugepage_avail_low[MAX_NR_ZONES];
/* fill pool if available memory is above this value */
static unsigned long hugepage_avail_high[MAX_NR_ZONES];

/* default policy : 2GB@12GB */
static unsigned long get_hugepage_quota(void)
{
	unsigned long memblock_memory_size;
	unsigned long totalram;

	memblock_memory_size = (unsigned long)memblock_phys_mem_size();
	totalram = memblock_memory_size >> PAGE_SHIFT;

	if (totalram > GB_TO_PAGES(10))
		return GB_TO_PAGES(1);
	else
		return GB_TO_PAGES(0);
}

static void init_hugepage_pool(void)
{
	struct zone *zone;

	long hugepage_quota = get_hugepage_quota();
	long avail_low = totalram_pages() >> 2;
	long avail_high = avail_low + (avail_low >> 2);
	uint32_t totalram_pages_uint = totalram_pages();

	for_each_zone(zone) {
		u64 num_pages;
		int zidx = zone_idx(zone);
		unsigned long managed_pages = zone_managed_pages(zone);

		/*
		 * calculate without zone lock as we assume managed_pages of
		 * zones do not change at runtime
		 */
		num_pages = (u64)hugepage_quota * managed_pages;
		do_div(num_pages, totalram_pages_uint);
		nr_hugepages_quota[zidx] = (num_pages >> HUGEPAGE_ORDER);
		nr_hugepages_limit[zidx] = nr_hugepages_quota[zidx];

		hugepage_avail_low[zidx] = (u64)avail_low * managed_pages;
		do_div(hugepage_avail_low[zidx], totalram_pages_uint);

		hugepage_avail_high[zidx] = (u64)avail_high * managed_pages;
		do_div(hugepage_avail_high[zidx], totalram_pages_uint);

		spin_lock_init(&hugepage_list_lock[zidx]);
		spin_lock_init(&hugepage_nonzero_list_lock[zidx]);
		INIT_LIST_HEAD(&hugepage_list[zidx]);
		INIT_LIST_HEAD(&hugepage_nonzero_list[zidx]);
	}
}

static unsigned long get_zone_pool_pages(enum zone_type zidx)
{
	unsigned long total_nr_hugepages = 0;

	spin_lock(&hugepage_list_lock[zidx]);
	total_nr_hugepages += nr_hugepages[zidx];
	spin_unlock(&hugepage_list_lock[zidx]);

	spin_lock(&hugepage_nonzero_list_lock[zidx]);
	total_nr_hugepages += nr_hugepages_nonzero[zidx];
	spin_unlock(&hugepage_nonzero_list_lock[zidx]);

	return total_nr_hugepages << HUGEPAGE_ORDER;
}

static unsigned long get_zone_pool_pages_unsafe(enum zone_type zidx)
{
	return (nr_hugepages[zidx] + nr_hugepages_nonzero[zidx]) << HUGEPAGE_ORDER;
}

static unsigned long get_pool_pages_under_zone(enum zone_type zidx, bool accurate)
{
	unsigned long total_pool_pages = 0;
	int i;

	for (i = zidx; i >= 0; i--)
		total_pool_pages += (accurate ? get_zone_pool_pages(i)
				: get_zone_pool_pages_unsafe(i));

	return total_pool_pages;
}

static unsigned long get_total_pool_pages(bool accurate)
{
	return get_pool_pages_under_zone(MAX_NR_ZONES - 1, accurate);
}

unsigned long total_hugepage_pool_pages(void)
{
	if (!kzerod_enabled)
		return 0;

	return get_total_pool_pages(true);
}

/*
 * adjust limits depending on available memory
 * then return total limits in #pages under the specified zone.
 * If ratelimited, it returns -1. Caller should check returned value.
 */
static long hugepage_calculate_limits_under_zone(
		enum zone_type high_zoneidx, bool accurate)
{
	long total_limits_under_zone = 0;
	struct zone *zone;
	int prev_limit;

	/* calculate only after 100ms passed */
	static DEFINE_RATELIMIT_STATE(hugepage_calc_rs, HZ/10, 1);

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	bool print_debug_log = false;
	static DEFINE_RATELIMIT_STATE(hugepage_calc_log_rs, HZ, 1);

	ratelimit_set_flags(&hugepage_calc_log_rs, RATELIMIT_MSG_ON_RELEASE);
#else
	ratelimit_set_flags(&hugepage_calc_rs, RATELIMIT_MSG_ON_RELEASE);
#endif

	if (!__ratelimit(&hugepage_calc_rs))
		return -1;

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	if (__ratelimit(&hugepage_calc_log_rs))
		print_debug_log = true;

	if (print_debug_log) {
		pr_err("%s(high_zoneidx=%d, accurate=%d): ", __func__, high_zoneidx, accurate);
		pr_err("%s: zidx curavail newavail  d_avail "
				" curpool  newpool curlimit newlimit\n", __func__);
	}
#endif
	for_each_zone(zone) {
		int zidx = zone_idx(zone);
		long avail_pages = zone_available_simple(zone);
		long delta_avail = 0;
		long current_pool_pages = accurate ?
			get_zone_pool_pages(zidx) : get_zone_pool_pages_unsafe(zidx);
		long pool_pages_should_be = current_pool_pages;
		long avail_pages_should_be = avail_pages;
		long quota_pages = ((long)nr_hugepages_quota[zidx]) << HUGEPAGE_ORDER;

		prev_limit = nr_hugepages_limit[zidx];
		if (zidx <= high_zoneidx) {
			if (avail_pages < hugepage_avail_low[zidx])
				delta_avail = hugepage_avail_low[zidx] - avail_pages;
			else if (avail_pages > hugepage_avail_high[zidx])
				delta_avail = hugepage_avail_high[zidx] - avail_pages;

			if (current_pool_pages - delta_avail < 0)
				delta_avail = current_pool_pages;
			else if (current_pool_pages - delta_avail > quota_pages)
				delta_avail = current_pool_pages - quota_pages;
			pool_pages_should_be = current_pool_pages - delta_avail;
			avail_pages_should_be = avail_pages + delta_avail;

			nr_hugepages_limit[zidx] = pool_pages_should_be >> HUGEPAGE_ORDER;
			total_limits_under_zone += nr_hugepages_limit[zidx];
		}

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
		if (print_debug_log) {
			pr_err("%s: %4d %8ld %8ld %8ld %8ld %8ld %8d %8d\n",
					__func__, zidx,
					avail_pages, avail_pages_should_be, delta_avail,
					current_pool_pages, pool_pages_should_be,
					prev_limit, nr_hugepages_limit[zidx]);
		}
#endif
	}

	return total_limits_under_zone << HUGEPAGE_ORDER;
}

static int nr_pages_to_fill(enum zone_type ht)
{
	int ret = nr_hugepages_limit[ht] - nr_hugepages[ht];

	return ret > 0 ? ret : 0;
}

static int hugepage_kzerod_wakeup = 1;

static inline bool hugepage_kzerod_required(void)
{
	return hugepage_kzerod_wakeup;
}

static unsigned long last_wakeup_stamp;
static inline void __try_wake_up_hugepage_kzerod(enum zone_type ht)
{
	if (need_pause())
		return;

	if (time_is_after_jiffies(last_wakeup_stamp + 10 * HZ))
		return;

	if (!hugepage_kzerod_wakeup && nr_hugepages_limit[ht] &&
	    (nr_hugepages[ht] * 2 < nr_hugepages_limit[ht] ||
	     nr_hugepages_nonzero[ht])) {
		hugepage_kzerod_wakeup = 1;
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
		pr_info("kzerod_h: woken up\n");
#endif
		wake_up(&hugepage_kzerod_wait);
	}
}

static void try_wake_up_hugepage_kzerod(void)
{
	int i;
	enum zone_type high_zoneidx;

	high_zoneidx = gfp_zone(GFP_HIGHUSER_MOVABLE);

	for (i = high_zoneidx; i >= 0; i--)
		__try_wake_up_hugepage_kzerod(i);
}

static inline gfp_t get_gfp(enum zone_type ht)
{
	gfp_t ret;

	if (ht == ZONE_MOVABLE)
		ret = __GFP_MOVABLE | __GFP_HIGHMEM;
#ifdef CONFIG_ZONE_DMA
	else if (ht == ZONE_DMA)
		ret = __GFP_DMA;
#elif defined(CONFIG_ZONE_DMA32)
	else if (ht == ZONE_DMA32)
		ret = __GFP_DMA32;
#endif
	else
		ret = 0;
	return ret & ~__GFP_RECLAIM;
}

bool insert_hugepage_pool(struct page *page, int order)
{
	enum zone_type ht = page_zonenum(page);

	if (!kzerod_enabled)
		return NULL;

	if (order != HUGEPAGE_ORDER || !nr_hugepages_limit[ht])
		return false;

	if (nr_hugepages[ht] + nr_hugepages_nonzero[ht] >= nr_hugepages_limit[ht])
		return false;

	if (unlikely(!spin_trylock(&hugepage_nonzero_list_lock[ht])))
		return false;
	/*
	 * note that, at this point, the page is in the free page state except
	 * it is not in buddy. need prep_new_page before going to hugepage list.
	 */
	list_add(&page->lru, &hugepage_nonzero_list[ht]);
	nr_hugepages_nonzero[ht]++;
	spin_unlock(&hugepage_nonzero_list_lock[ht]);

	return true;
}

static void zeroing_nonzero_list(enum zone_type ht)
{
	if (!nr_hugepages_nonzero[ht])
		return;

	spin_lock(&hugepage_nonzero_list_lock[ht]);
	while (!list_empty(&hugepage_nonzero_list[ht])) {
		struct page *page = list_first_entry(&hugepage_nonzero_list[ht],
						     struct page, lru);
		list_del(&page->lru);
		nr_hugepages_nonzero[ht]--;
		spin_unlock(&hugepage_nonzero_list_lock[ht]);

		spin_lock(&hugepage_list_lock[ht]);
		if (nr_pages_to_fill(ht)) {
			prep_new_page(page, HUGEPAGE_ORDER, __GFP_ZERO, 0);
			list_add(&page->lru, &hugepage_list[ht]);
			nr_hugepages[ht]++;
		} else
			___free_pages_ok(page, HUGEPAGE_ORDER, (__force int __bitwise)0, true);

		spin_unlock(&hugepage_list_lock[ht]);

		spin_lock(&hugepage_nonzero_list_lock[ht]);
	}
	spin_unlock(&hugepage_nonzero_list_lock[ht]);

}

static void prepare_hugepage_alloc(void);

static void fill_hugepage_pool(enum zone_type ht)
{
	int trial = nr_pages_to_fill(ht);

	prepare_hugepage_alloc();

	nr_hugepages_fill_tried[ht] += trial;
	while (trial--) {
		struct page *page = alloc_pages(get_gfp(ht) | __GFP_ZERO |
						__GFP_NOWARN, HUGEPAGE_ORDER);

		/* if alloc fails, future requests may fail also. stop here. */
		if (!page)
			break;

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
		BUG_ON(is_migrate_cma_page(page));
#endif

		if (page_zonenum(page) != ht) {
			__free_pages(page, HUGEPAGE_ORDER);
			/*
			 * if page is from the lower zone, future requests may
			 * also get the lower zone pages. stop here.
			 */
			break;
		}
		nr_hugepages_fill_done[ht]++;
		spin_lock(&hugepage_list_lock[ht]);
		list_add(&page->lru, &hugepage_list[ht]);
		nr_hugepages[ht]++;
		spin_unlock(&hugepage_list_lock[ht]);
	}
}

struct page *alloc_zeroed_hugepage(gfp_t gfp_mask, int order, bool global_check,
				   enum hpage_type type)
{
	int i;
	enum zone_type high_zoneidx;
	struct page *page = NULL;

	if (!kzerod_enabled)
		return NULL;

	if (!is_hugepage_allowed(current, order, global_check, type))
		return NULL;

	high_zoneidx = gfp_zone(gfp_mask);
	nr_hugepages_tried[high_zoneidx]++;
	for (i = high_zoneidx; i >= 0; i--) {
		__try_wake_up_hugepage_kzerod(i);
		if (!nr_hugepages[i])
			continue;
		if (unlikely(!spin_trylock(&hugepage_list_lock[i])))
			continue;

		if (!list_empty(&hugepage_list[i])) {
			page = list_first_entry(&hugepage_list[i], struct page,
						lru);
			list_del(&page->lru);
			nr_hugepages[i]--;
		}
		spin_unlock(&hugepage_list_lock[i]);

		if (page) {
			nr_hugepages_alloced[i]++;
			nr_hugepages_alloced_types[type]++;
			if (order && (gfp_mask & __GFP_COMP))
				prep_compound_page(page, order);
			break;
		}
	}

	return page;
}

static int hugepage_kzerod(void *p)
{
	while (!kthread_should_stop()) {
		int i;

		wait_event_freezable(hugepage_kzerod_wait,
				     hugepage_kzerod_required() ||
				     kthread_should_stop());

		hugepage_kzerod_wakeup = 0;
		last_wakeup_stamp = jiffies;

		hugepage_calculate_limits_under_zone(MAX_NR_ZONES - 1, true);
		for (i = 0; i < MAX_NR_ZONES; i++) {
			if (need_pause())
				break;

			zeroing_nonzero_list(i);
			fill_hugepage_pool(i);
		}
	}

	return 0;
}

static unsigned long hugepage_pool_count(struct shrinker *shrink,
				struct shrink_control *sc)
{
	long count;
	long limit_pages;
	enum zone_type high_zoneidx;
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	static DEFINE_RATELIMIT_STATE(hugepage_count_log_rs, HZ, 1);
#endif

	high_zoneidx = gfp_zone(sc->gfp_mask);
	if (current_is_kswapd())
		high_zoneidx = MAX_NR_ZONES - 1;
	else
		return 0;

	limit_pages = hugepage_calculate_limits_under_zone(high_zoneidx, false);
	count = get_pool_pages_under_zone(high_zoneidx, false) - limit_pages;
	if (count < 0 || limit_pages < 0)
		count = 0;
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	if (__ratelimit(&hugepage_count_log_rs))
		pr_err("%s returned %ld\n", __func__, count);
#endif

	return count;
}

static unsigned long hugepage_pool_scan(struct shrinker *shrink,
				struct shrink_control *sc)
{
	unsigned long freed = 0;
	long freed_zone, to_scan_zone; /* freed & to_scan per zone */
	struct zone *zone;
	struct page *page;
	int zidx;
	enum zone_type high_zoneidx;
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	static DEFINE_RATELIMIT_STATE(hugepage_scan_log_rs, HZ, 2);
#endif

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	if (__ratelimit(&hugepage_scan_log_rs))
		pr_err("%s was requested %lu\n", __func__, sc->nr_to_scan);
#endif
	high_zoneidx = gfp_zone(sc->gfp_mask);
	if (current_is_kswapd())
		high_zoneidx = MAX_NR_ZONES - 1;

	hugepage_calculate_limits_under_zone(high_zoneidx, true);
	for_each_zone(zone) {
		zidx = zone_idx(zone);
		to_scan_zone = nr_hugepages[zidx] - nr_hugepages_limit[zidx];
		to_scan_zone = (to_scan_zone < 0) ? 0 : to_scan_zone;
		if (zidx > high_zoneidx || !to_scan_zone)
			continue;

		freed_zone = 0;
		spin_lock(&hugepage_nonzero_list_lock[zidx]);
		while (!list_empty(&hugepage_nonzero_list[zidx]) &&
				freed_zone < to_scan_zone) {
			page = list_first_entry(&hugepage_nonzero_list[zidx],
					struct page, lru);
			list_del(&page->lru);
			___free_pages_ok(page, HUGEPAGE_ORDER, (__force int __bitwise)0, true);
			nr_hugepages_nonzero[zidx]--;
			freed_zone++;
		}
		spin_unlock(&hugepage_nonzero_list_lock[zidx]);

		spin_lock(&hugepage_list_lock[zidx]);
		while (!list_empty(&hugepage_list[zidx]) &&
				freed_zone < to_scan_zone) {
			page = list_first_entry(&hugepage_list[zidx],
					struct page, lru);
			list_del(&page->lru);
			__free_pages(page, HUGEPAGE_ORDER);
			nr_hugepages[zidx]--;
			freed_zone++;
		}
		spin_unlock(&hugepage_list_lock[zidx]);

		freed += freed_zone;
	}
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	if (__ratelimit(&hugepage_scan_log_rs))
		pr_err("%s freed %ld hugepages(%ldK)\n",
				__func__, freed, K(freed << HUGEPAGE_ORDER));
#endif

	if (freed == 0)
		return SHRINK_STOP;

	return freed << HUGEPAGE_ORDER;
}

/*
 * this function should be called within hugepage_kzerod context, only.
 */
static void prepare_hugepage_alloc(void)
{
	static int compact_count;
	static DEFINE_RATELIMIT_STATE(hugepage_compact_rs, 60 * 60 * HZ, 1);

	if (__ratelimit(&hugepage_compact_rs)) {
		struct sched_param param_normal = { .sched_priority = 0 };
		struct sched_param param_idle = { .sched_priority = 0 };

		if (!sched_setscheduler(current, SCHED_NORMAL,
				   &param_normal)) {
			pr_info("kzerod_h: compact start\n");
			compact_node_async();
			pr_info("kzerod_h: compact end (%d done)\n",
				++compact_count);

			if (sched_setscheduler(current, SCHED_IDLE,
					   &param_idle))
				pr_err("kzerod_h: fail to set sched_idle\n");
		}
	}
}

static struct shrinker hugepage_pool_shrinker_info = {
	.scan_objects = hugepage_pool_scan,
	.count_objects = hugepage_pool_count,
	.seeks = DEFAULT_SEEKS,
};

module_param_array(nr_hugepages, int, NULL, 0444);
module_param_array(nr_hugepages_nonzero, int, NULL, 0444);
module_param_array(nr_hugepages_alloced, int, NULL, 0444);
module_param_array(nr_hugepages_alloced_types, int, NULL, 0444);
module_param_array(nr_hugepages_tried, int, NULL, 0444);
module_param_array(nr_hugepages_fill_tried, int, NULL, 0444);
module_param_array(nr_hugepages_fill_done, int, NULL, 0444);
module_param_array(nr_hugepages_quota, int, NULL, 0444);
module_param_array(nr_hugepages_limit, int, NULL, 0444);

module_param_array(hugepage_avail_low, ulong, NULL, 0644);
module_param_array(hugepage_avail_high, ulong, NULL, 0644);
#endif

#ifdef CONFIG_KZEROD_ENABLE
static int __init __kzerod_init(void)
{
	int ret;
	struct sched_param param = { .sched_priority = 0 };

	spin_lock_init(&prezeroed_lock);
	task_kzerod = kthread_run(kzerod, NULL, "kzerod");
	if (IS_ERR(task_kzerod)) {
		task_kzerod = NULL;
		pr_err("Failed to start kzerod\n");
		return 0;
	}
	sched_setscheduler(task_kzerod, SCHED_IDLE, &param);

	ret = kzerod_mount();
	if (ret)
		goto out;
	if (kzerod_register_migration())
		goto out;

	return 0;
out:
	BUG();
	return -EINVAL;
}
#endif

#ifdef CONFIG_HUGEPAGE_POOL
static int __init __kzerod_huge_init(void)
{
	int ret;
	struct sched_param param = { .sched_priority = 0 };
	struct task_struct *task;

	if (!get_hugepage_quota()) {
		kzerod_enabled = false;
		goto skip_all;
	}

	init_hugepage_pool();
	task = kthread_run(hugepage_kzerod, NULL,
					   "kzerod_huge");
	if (IS_ERR(task)) {
		pr_err("Failed to start kzerod_huge\n");
		goto skip_all;
	}
	sched_setscheduler(task, SCHED_IDLE, &param);
	ret = register_shrinker(&hugepage_pool_shrinker_info);
	if (ret)
		kthread_stop(task);

skip_all:
	return 0;
}
#endif

static int __init kzerod_init(void)
{
#if defined(CONFIG_KZEROD_ENABLE) || defined(CONFIG_HUGEPAGE_POOL)
	am_app_launch_notifier_register(&kzerod_app_launch_nb);
#endif
#ifdef CONFIG_KZEROD_ENABLE
	__kzerod_init();
#endif
#ifdef CONFIG_HUGEPAGE_POOL
	__kzerod_huge_init();
#endif
	return 0;
}

static void __exit kzerod_exit(void)
{
#ifdef CONFIG_KZEROD_ENABLE
	if (kzerod_inode)
		kzerod_unregister_migration();
	if (kzerod_mnt)
		kzerod_unmount();
#endif
}

static int kzerod_enabled_param_set(const char *val,
				   const struct kernel_param *kp)
{
#ifdef CONFIG_KZEROD_ENABLE
	int error;
	bool prev;

	if (!task_kzerod) {
		pr_err("can't enable, task_kzerod is not ready\n");
		return -ENODEV;
	}

	prev = kzerod_enabled;
	error = param_set_bool(val, kp);
	if (error)
		return error;

	if (!prev && kzerod_enabled) {
		kzerod_state = KZEROD_RUNNING,
		wake_up(&kzerod_wait);
	} else if (prev && !kzerod_enabled) {
		drain_zeroed_page();
	}
	return error;
#else
	return param_set_bool(val, kp);
#endif
}

static struct kernel_param_ops kzerod_enabled_param_ops = {
	.set =	kzerod_enabled_param_set,
	.get =	param_get_bool,
};
module_param_cb(enabled, &kzerod_enabled_param_ops, &kzerod_enabled, 0644);

#undef K
module_init(kzerod_init)
module_exit(kzerod_exit);
