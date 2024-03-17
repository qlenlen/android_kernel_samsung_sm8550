/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/mock.h>
#include <kunit/test.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "include/defex_internal.h"

#define NEGATIVE_ID (0-1)
#define MAX_PID_32 32768
#define DEFEX_MEM_CACHE_SIZE 32
#define TEST_PID_MAIN 42000
#define TEST_PID_FORK 43000
#define TEST_UID 1000
#define TEST_FSUID 1000
#define TEST_EGID 1000
#define TEST_FLAGS 0

#define DEFEX_MEM_CACHE_COUNT 3
#define CACHE_CRED_DATA 0
#define CACHE_CRED_DATA_ID 1
#define CACHE_HTABLE_ITEM 2

struct id_set {
	unsigned int uid, fsuid, egid;
};

struct proc_cred_data {
	unsigned short cred_flags;
	unsigned short tcnt;
	struct id_set default_ids;
	struct id_set main_ids[];
};

struct mem_cache_list {
	atomic_t count;
	char name[8];
	struct kmem_cache *allocator;
	void *mem_cache_array[DEFEX_MEM_CACHE_SIZE];
};

#ifdef DEFEX_PED_ENABLE
extern struct hlist_head creds_hash[1 << 15];
extern spinlock_t creds_hash_update_lock;
extern struct mem_cache_list mem_cache[DEFEX_MEM_CACHE_COUNT];

extern struct proc_cred_data *get_cred_data(int id);
extern struct proc_cred_data **get_cred_ptr(int id);
extern void set_cred_data(int id, struct proc_cred_data **cred_ptr, struct proc_cred_data *cred_data);
extern void *mem_cache_get(int cache_number);
extern void *mem_cache_reclaim(int cache_number, void *ptr);
extern void mem_cache_alloc(void);
#endif /* DEFEX_PED_ENABLE */

struct task_struct *main_task, *fork_task;

static void set_task_creds_tcnt_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE
	int i;
	unsigned int uid = TEST_UID, fsuid = TEST_FSUID, egid = TEST_EGID;
	unsigned short cred_flags = TEST_FLAGS;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	/* First, we need to allocate DEFEX_MEM_CACHE_SIZE so we can fill up the cache later on.
	 * We will also need a pair of tasks which will be freed when the cache is full.
	 */
	KUNIT_ASSERT_EQ(test, set_task_creds(main_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);
	KUNIT_ASSERT_EQ(test, set_task_creds(fork_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);
	for(i = 0; i < (DEFEX_MEM_CACHE_SIZE / 2); i++) {
		main_task->pid += 1;
		main_task->tgid += 1;
		fork_task->pid += 1;
		fork_task->tgid += 1;
		KUNIT_ASSERT_EQ(test, set_task_creds(main_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);
		KUNIT_ASSERT_EQ(test, set_task_creds(fork_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);
	}

	/* Now we set the thread count to zero -> memory will be put in cache until it's full. */
	for(i = 0; i < (DEFEX_MEM_CACHE_SIZE / 2); i++) {
		set_task_creds_tcnt(fork_task, -1);
		set_task_creds_tcnt(main_task, -1);
		main_task->pid -= 1;
		main_task->tgid -= 1;
		fork_task->pid -= 1;
		fork_task->tgid -= 1;
	}

	/* CACHE_CRED_DATA and CACHE_HTABLE_ITEM caches should be full now. */
	KUNIT_ASSERT_EQ(test, atomic_read(&mem_cache[CACHE_CRED_DATA].count), DEFEX_MEM_CACHE_SIZE);
	KUNIT_ASSERT_EQ(test, atomic_read(&mem_cache[CACHE_HTABLE_ITEM].count), DEFEX_MEM_CACHE_SIZE);

	/* Let's reclaim that last pair so it triggers kfree */
	set_task_creds_tcnt(fork_task, -1);
	set_task_creds_tcnt(main_task, -1);

	/* Let's verify there is no cred data in cache */
	get_task_creds(main_task, &uid, &fsuid, &egid, &cred_flags);
	KUNIT_EXPECT_EQ(test, uid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, fsuid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, egid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, cred_flags, (unsigned short)CRED_FLAGS_PROOT);

	uid = TEST_UID;
	fsuid = TEST_FSUID;
	egid = TEST_EGID;
	cred_flags = TEST_FLAGS;

	get_task_creds(fork_task, &uid, &fsuid, &egid, &cred_flags);
	KUNIT_EXPECT_EQ(test, uid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, fsuid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, egid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, cred_flags, (unsigned short)CRED_FLAGS_PROOT);

	KUNIT_EXPECT_TRUE(test, hash_empty(creds_hash));

#else
	set_task_creds_tcnt(NULL, 0);
#endif /* DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void set_task_creds_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE
	struct proc_cred_data *query;
	unsigned long flags;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	/* T1: Main process initial data */
	KUNIT_EXPECT_EQ(test, set_task_creds(main_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	query = get_cred_data(TEST_PID_MAIN);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_ASSERT_PTR_NE(test, query, (struct proc_cred_data *)NULL);
	KUNIT_EXPECT_EQ(test, query->cred_flags, (unsigned short)0);
	KUNIT_EXPECT_EQ(test, query->default_ids.uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, query->default_ids.fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, query->default_ids.egid, (unsigned int)TEST_EGID);
	KUNIT_EXPECT_EQ(test, query->tcnt, (unsigned short)1);

	/* T2: Fork task data */
	set_task_creds_tcnt(main_task, 1);
	KUNIT_EXPECT_EQ(test, set_task_creds(fork_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);

	spin_lock_irqsave(&creds_hash_update_lock, flags);
	query = get_cred_data(TEST_PID_MAIN);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_ASSERT_PTR_NE(test, query, (struct proc_cred_data *)NULL);
	KUNIT_EXPECT_EQ(test, query->cred_flags, (unsigned short)CRED_FLAGS_SUB_UPDATED);

	spin_lock_irqsave(&creds_hash_update_lock, flags);
	query = get_cred_data(TEST_PID_FORK);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_ASSERT_PTR_NE(test, query, (struct proc_cred_data *)NULL);
	KUNIT_EXPECT_EQ(test, query->cred_flags, (unsigned short)0);
	KUNIT_EXPECT_EQ(test, query->tcnt, (unsigned short)0);
	KUNIT_EXPECT_EQ(test, query->default_ids.uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, query->default_ids.fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, query->default_ids.egid, (unsigned int)TEST_EGID);

	/* T3: Update Main process cred */
	KUNIT_EXPECT_EQ(test, set_task_creds(main_task, TEST_UID + 1, TEST_FSUID + 1, TEST_EGID + 1, TEST_FLAGS), 0);

	spin_lock_irqsave(&creds_hash_update_lock, flags);
	query = get_cred_data(TEST_PID_MAIN);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_ASSERT_PTR_NE(test, query, (struct proc_cred_data *)NULL);
	KUNIT_EXPECT_EQ(test, query->cred_flags, (unsigned short)(CRED_FLAGS_SUB_UPDATED | CRED_FLAGS_MAIN_UPDATED));
	KUNIT_EXPECT_EQ(test, query->tcnt, (unsigned short)2);
	KUNIT_EXPECT_EQ(test, query->default_ids.uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, query->default_ids.fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, query->default_ids.egid, (unsigned int)TEST_EGID);
	KUNIT_EXPECT_EQ(test, query->main_ids[0].uid, (unsigned int)TEST_UID + 1);
	KUNIT_EXPECT_EQ(test, query->main_ids[0].fsuid, (unsigned int)(TEST_FSUID + 1));
	KUNIT_EXPECT_EQ(test, query->main_ids[0].egid, (unsigned int)(TEST_EGID + 1));

	/* Cleanup */
	set_task_creds_tcnt(fork_task, -1);
	set_task_creds_tcnt(main_task, -1);
	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

#endif /* DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void set_cred_data_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLED
	struct proc_cred_data *cred_data, *new_creds, **cred_data_ptr;
	unsigned int task_uid, task_fsuid, task_egid;
	unsigned long flags;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	/* T1: negative ID */
	set_cred_data(-TEST_PID_MAIN, NULL, NULL);

	/* T2: inexistent data */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	set_cred_data(TEST_PID_MAIN, NULL, NULL);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);

	/* Alloc new space in cache and add put cred data. */
	mem_cache_alloc();
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_data = mem_cache_get(CACHE_CRED_DATA);
	if (!cred_data) {
		spin_unlock_irqrestore(&creds_hash_update_lock, flags);
		KUNIT_FAIL(test, "Test failed in getting cred_data");
	}
	cred_data->cred_flags = 0;
	cred_data->tcnt = 1;
	cred_data->default_ids.uid = TEST_UID;
	cred_data->default_ids.fsuid = TEST_FSUID;
	cred_data->default_ids.egid = TEST_EGID;

	/* T3: Insert new data */
	set_cred_data(TEST_PID_MAIN, NULL, cred_data);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	mem_cache_alloc();

	/* Verify inserted data */
	get_task_creds(main_task, &task_uid, &task_fsuid, &task_egid, &task_cred_flags);
	KUNIT_EXPECT_EQ(test, task_uid, TEST_UID);
	KUNIT_EXPECT_EQ(test, task_fsuid, TEST_FSUID);
	KUNIT_EXPECT_EQ(test, task_egid, TEST_EGID);
	KUNIT_EXPECT_EQ(test, task_cred_flags, 0);

	/* Allocate new data to change main_task data */
	new_creds = kmem_cache_alloc(mem_cache[CACHE_CRED_DATA].allocator,
				in_atomic() ? GFP_ATOMIC:GFP_KERNEL);
	KUNIT_ASSERT_PTR_NE(test, new_creds, (struct proc_cred_data *)NULL);
	new_creds->cred_flags = CRED_FLAGS_PROOT;
	new_creds->tcnt = 1;
	new_creds->default_ids.uid = TEST_UID + 1;
	new_creds->default_ids.fsuid = TEST_FSUID + 1;
	new_creds->default_ids.egid = TEST_EGID + 1;

	/* T4: existing cred_ptr */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_data_ptr = get_cred_ptr(TEST_PID_MAIN);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_ASSERT_PTR_NE(test, cred_data_ptr, (struct proc_cred_data **)NULL);

	spin_lock_irqsave(&creds_hash_update_lock, flags);
	set_cred_data(TEST_PID_MAIN, cred_data_ptr, new_creds);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);

	/* Verify inserted data */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	get_task_creds(main_task, &task_uid, &task_fsuid, &task_egid, &task_cred_flags);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_EQ(test, task_uid, TEST_UID + 1);
	KUNIT_EXPECT_EQ(test, task_fsuid, TEST_FSUID + 1);
	KUNIT_EXPECT_EQ(test, task_egid, TEST_EGID + 1);
	KUNIT_EXPECT_EQ(test, task_cred_flags, CRED_FLAGS_PROOT);

	/* Cleanup */
	set_task_creds_tcnt(main_task, -1);
	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));
	kmem_cache_free(mem_cache[CACHE_CRED_DATA].allocator, cred_data);

#endif /* DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void mem_cache_reclaim_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLED
	void *cache;
	int count_backup;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cache = mem_cache_get(CACHE_CRED_DATA);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_ASSERT_PTR_NE(test, cache, NULL);
	count_backup = atomic_read(&mem_cache[CACHE_CRED_DATA].count);

	/* T1: count >= DEFEX_MEM_CACHE_SIZE -> cache not reclaimed. */
	atomic_write(&mem_cache[CACHE_CRED_DATA].count, DEFEX_MEM_CACHE_SIZE);
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cache = mem_cache_reclaim(CACHE_CRED_DATA, cache);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_NE(test, cache, NULL);
	KUNIT_EXPECT_EQ(test, atomic_read(&mem_cache[CACHE_CRED_DATA].count), DEFEX_MEM_CACHE_SIZE);

	/* T2: count < DEFEX_MEM_CACHE_SIZE -> cache reclaimed. */
	atomic_write(&mem_cache[CACHE_CRED_DATA].count, count_backup);
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cache = mem_cache_reclaim(CACHE_CRED_DATA, cache);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_EQ(test, cache, NULL);
	KUNIT_EXPECT_EQ(test, atomic_read(&mem_cache[CACHE_CRED_DATA].count), count_backup + 1);

#endif /* DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void mem_cache_get_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLED
	void *cache[DEFEX_MEM_CACHE_SIZE], *cache_mem;
	int index;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	/* At initialization, only half cache is initialized */
	for(index = 0; index < (DEFEX_MEM_CACHE_SIZE / 2); index++) {
		spin_lock_irqsave(&creds_hash_update_lock, flags);
		cache[index] = mem_cache_get(CACHE_CRED_DATA);
		spin_unlock_irqrestore(&creds_hash_update_lock, flags);
		KUNIT_EXPECT_PTR_NE(test, cache[index], NULL);
	}

	KUNIT_EXPECT_EQ(test, atomic_read(&mem_cache[CACHE_CRED_DATA].count), 0);
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cache_mem = mem_cache_get(CACHE_CRED_DATA);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_EQ(test, cache[index], NULL);

	/* Clean up */
	for(index = 0; index < (DEFEX_MEM_CACHE_SIZE / 2); index++) {
		spin_lock_irqsave(&creds_hash_update_lock, flags);
		cache_mem = mem_cache_reclaim(0, cache[index]);
		spin_unlock_irqrestore(&creds_hash_update_lock, flags);
		KUNIT_ASSERT_NULL(test, cache_mem);
	}
#endif /* DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void mem_cache_alloc_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLED
	int count_backup_cache[DEFEX_MEM_CACHE_COUNT], count_allocations = 0;
	void *cache_allocated_memory[DEFEX_MEM_CACHE_COUNT];
	int count_backup;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	/* At initial state, the cache already has DEFEX_MEM_CACHE_SIZE /2 positions
	 * allocated, so no new allocations are made.
	 */
	count_backup = atomic_read(&mem_cache[CACHE_CRED_DATA].count);
	mem_cache_alloc();
	KUNIT_EXPECT_EQ(test, count_backup, atomic_read(&mem_cache[CACHE_CRED_DATA].count));

	/* Now we get some pointers to force memory allocation. */
	for (i = 0; i < DEFEX_MEM_CACHE_COUNT; i++) {
		spin_lock_irqsave(&creds_hash_update_lock, flags);
		cache_allocated_memory[i] = mem_cache_get(i);
		spin_unlock_irqrestore(&creds_hash_update_lock, flags);
		KUNIT_ASSERT_PTR_NE(test, cache_allocated_memory[i], NULL);
	}
	mem_cache_alloc();

	/* Clean up */
	for (i = 0; i < DEFEX_MEM_CACHE_COUNT; i++) {
		spin_lock_irqsave(&creds_hash_update_lock, flags);
		cache_allocated_memory[i] = mem_cache_reclaim(i, cache_allocated_memory[i]);
		spin_unlock_irqrestore(&creds_hash_update_lock, flags);
		KUNIT_ASSERT_NULL(test, cache_allocated_memory[i]);
	}

#endif /* DEFEX_PED_ENABLED */
	KUNIT_SUCCEED(test);
}


static void is_task_creds_ready_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 1, is_task_creds_ready());
}


static void get_task_creds_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE

	unsigned int task_uid, task_fsuid, task_egid;
	unsigned short task_cred_flags;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	/* T1: inexistent data */
	task_uid = TEST_UID;
	task_fsuid = TEST_FSUID;
	task_egid = TEST_EGID;

	get_task_creds(main_task, &task_uid, &task_fsuid, &task_egid, &task_cred_flags);
	KUNIT_EXPECT_EQ(test, task_uid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, task_fsuid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, task_egid, (unsigned int)0);
	KUNIT_EXPECT_EQ(test, task_cred_flags, (unsigned short)CRED_FLAGS_PROOT);

	/* T2: existent main task data */
	KUNIT_ASSERT_EQ(test, set_task_creds(main_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);
	get_task_creds(main_task, &task_uid, &task_fsuid, &task_egid, &task_cred_flags);
	KUNIT_EXPECT_EQ(test, task_uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, task_fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, task_egid, (unsigned int)TEST_EGID);
	KUNIT_EXPECT_EQ(test, task_cred_flags, (unsigned short)0);

	/* T3: Fork task data */
	set_task_creds_tcnt(main_task, 1);
	KUNIT_ASSERT_EQ(test, set_task_creds(fork_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);
	get_task_creds(main_task, &task_uid, &task_fsuid, &task_egid, &task_cred_flags);
	KUNIT_EXPECT_EQ(test, task_cred_flags, (unsigned short)CRED_FLAGS_SUB_UPDATED);
	get_task_creds(fork_task, &task_uid, &task_fsuid, &task_egid, &task_cred_flags);
	KUNIT_EXPECT_EQ(test, task_uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, task_fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, task_egid, (unsigned int)TEST_EGID);
	KUNIT_EXPECT_EQ(test, task_cred_flags, (unsigned short)0);

	/* T4: Update main task data */
	KUNIT_ASSERT_EQ(test, set_task_creds(main_task, TEST_UID + 1, TEST_FSUID + 1, TEST_EGID + 1, TEST_FLAGS), 0);
	get_task_creds(main_task, &task_uid, &task_fsuid, &task_egid, &task_cred_flags);
	KUNIT_EXPECT_EQ(test, task_uid, (unsigned int)TEST_UID + 1);
	KUNIT_EXPECT_EQ(test, task_fsuid, (unsigned int)TEST_FSUID + 1);
	KUNIT_EXPECT_EQ(test, task_egid, (unsigned int)TEST_EGID + 1);
	KUNIT_EXPECT_EQ(test, task_cred_flags, (unsigned short)(CRED_FLAGS_MAIN_UPDATED | CRED_FLAGS_SUB_UPDATED));

	/* Cleanup */
	set_task_creds_tcnt(fork_task, -1);
	set_task_creds_tcnt(main_task, -1);
	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

#endif /* DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void get_cred_ptr_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE
	struct proc_cred_data **cred_ptr;
	unsigned long flags;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	/* T1: negative ID */
	get_cred_ptr(NEGATIVE_ID);

	/* Add cred data with ID < MAX_PID_32 */
	fork_task->pid = MAX_PID_32 - 1;
	fork_task->tgid = MAX_PID_32 - 1;
	KUNIT_ASSERT_EQ(test, set_task_creds(fork_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);

	/* T2: ID < MAX_PID_32 */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_ptr = get_cred_ptr(MAX_PID_32 - 1);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_NE(test, cred_ptr, (struct proc_cred_data **)NULL);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->cred_flags, (unsigned short)TEST_FLAGS);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->tcnt, (unsigned short)1);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->default_ids.uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->default_ids.fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->default_ids.egid, (unsigned int)TEST_EGID);

	/* T3a: id > MAX_PID_32, inexistent data */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_ptr = get_cred_ptr(main_task->pid);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_EQ(test, cred_ptr, (struct proc_cred_data **)NULL);

	/* Add cred data with ID > MAX_PID_32 */
	KUNIT_ASSERT_EQ(test, set_task_creds(main_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);

	/* T3b: ID > MAX_PID_32 */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_ptr = get_cred_ptr(main_task->pid);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_NE(test, cred_ptr, (struct proc_cred_data **)NULL);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->cred_flags, (unsigned short)TEST_FLAGS);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->tcnt, (unsigned short)1);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->default_ids.uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->default_ids.fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, (*cred_ptr)->default_ids.egid, (unsigned int)TEST_EGID);

	/* Cleanup */
	set_task_creds_tcnt(fork_task, -1);
	set_task_creds_tcnt(main_task, -1);
	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));
	fork_task->pid = TEST_PID_FORK;
	fork_task->tgid = TEST_PID_MAIN;
#endif /* DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void get_cred_data_test(struct kunit *test)
{
#ifdef DEFEX_PED_ENABLE
	struct proc_cred_data *cred_data, **cred_ptr;
	unsigned long flags;

	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));

	/* T1: negative ID */
	get_cred_data(NEGATIVE_ID);

	/* Add cred data with ID < MAX_PID_32 */
	fork_task->pid = MAX_PID_32 - 1;
	fork_task->tgid = MAX_PID_32 - 1;
	KUNIT_ASSERT_EQ(test, set_task_creds(fork_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);

	/* T2: id < MAX_PID_32, get from vector */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_data = get_cred_data(MAX_PID_32 - 1);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_NE(test, cred_data, (struct proc_cred_data *)NULL);
	KUNIT_EXPECT_EQ(test, cred_data->cred_flags, (unsigned short)TEST_FLAGS);
	KUNIT_EXPECT_EQ(test, cred_data->tcnt, (unsigned short)1);
	KUNIT_EXPECT_EQ(test, cred_data->default_ids.uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, cred_data->default_ids.fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, cred_data->default_ids.egid, (unsigned int)TEST_EGID);

	/* T3a: id > MAX_PID_32, inexistent data */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_ptr = get_cred_ptr(main_task->pid);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_EQ(test, cred_ptr, (struct proc_cred_data **)NULL);

	/* Add cred data with ID > MAX_PID_32 */
	KUNIT_ASSERT_EQ(test, set_task_creds(main_task, TEST_UID, TEST_FSUID, TEST_EGID, TEST_FLAGS), 0);

	/* T3b: id > MAX_PID_32, get from vector */
	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_data = get_cred_data(main_task->pid);
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	KUNIT_EXPECT_PTR_NE(test, cred_data, (struct proc_cred_data *)NULL);
	KUNIT_EXPECT_EQ(test, cred_data->cred_flags, (unsigned short)TEST_FLAGS);
	KUNIT_EXPECT_EQ(test, cred_data->tcnt, (unsigned short)1);
	KUNIT_EXPECT_EQ(test, cred_data->default_ids.uid, (unsigned int)TEST_UID);
	KUNIT_EXPECT_EQ(test, cred_data->default_ids.fsuid, (unsigned int)TEST_FSUID);
	KUNIT_EXPECT_EQ(test, cred_data->default_ids.egid, (unsigned int)TEST_EGID);

	/* Cleanup */
	set_task_creds_tcnt(fork_task, -1);
	set_task_creds_tcnt(main_task, -1);
	KUNIT_ASSERT_TRUE(test, hash_empty(creds_hash));
	fork_task->pid = TEST_PID_FORK;
	fork_task->tgid = TEST_PID_MAIN;

#endif /* DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void creds_fast_hash_init_test(struct kunit *test)
{
	/* __init function */
	KUNIT_SUCCEED(test);
}


static int defex_ht_test_init(struct kunit *test)
{
	main_task = kzalloc(sizeof(*main_task), GFP_KERNEL);
	if(!main_task) {
		return -ENOMEM;
	}
	fork_task = kzalloc(sizeof(*fork_task), GFP_KERNEL);
	if(!fork_task) {
		kfree(main_task);
		return -ENOMEM;
	}
	main_task->pid = TEST_PID_MAIN;
	main_task->tgid = TEST_PID_MAIN;
	fork_task->pid = TEST_PID_FORK;
	fork_task->tgid = TEST_PID_MAIN;
	return 0;
}

static void defex_ht_test_exit(struct kunit *test)
{
	if(main_task)
		kfree(main_task);
	if(fork_task)
		kfree(fork_task);
}

static struct kunit_case defex_ht_test_cases[] = {
	/* TEST FUNC DEFINES */
	KUNIT_CASE(set_task_creds_tcnt_test),
	KUNIT_CASE(set_task_creds_test),
	KUNIT_CASE(set_cred_data_test),
	KUNIT_CASE(mem_cache_reclaim_test),
	KUNIT_CASE(mem_cache_get_test),
	KUNIT_CASE(mem_cache_alloc_test),
	KUNIT_CASE(is_task_creds_ready_test),
	KUNIT_CASE(get_task_creds_test),
	KUNIT_CASE(get_cred_ptr_test),
	KUNIT_CASE(get_cred_data_test),
	KUNIT_CASE(creds_fast_hash_init_test),
	{},
};

static struct kunit_suite defex_ht_test_module = {
	.name = "defex_ht_test",
	.init = defex_ht_test_init,
	.exit = defex_ht_test_exit,
	.test_cases = defex_ht_test_cases,
};
kunit_test_suites(&defex_ht_test_module);

