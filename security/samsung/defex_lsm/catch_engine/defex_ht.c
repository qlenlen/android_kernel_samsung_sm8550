/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include "include/defex_catch_list.h"
#include "include/defex_internal.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#endif

#define MAX_PID_32		32768
#define DEFEX_MEM_CACHE_SIZE	32
#define DEFEX_MEM_CACHE_COUNT	3
#define CACHE_CRED_DATA		0
#define CACHE_CRED_DATA_ID	1
#define CACHE_HTABLE_ITEM	2

struct id_set {
	unsigned int uid, fsuid, egid;
};

struct proc_cred_data {
	unsigned short cred_flags;
	unsigned short tcnt;
	struct id_set default_ids;
	struct id_set main_ids[];
};

struct hash_item_struct {
	struct hlist_node node;
	struct proc_cred_data *cred_data;
	int id;
};

struct mem_cache_list {
	atomic_t count;
	char name[8];
	struct kmem_cache *allocator;
	void *mem_cache_array[DEFEX_MEM_CACHE_SIZE];
};

#ifdef DEFEX_PED_ENABLE
DECLARE_HASHTABLE(creds_hash, 15);
__visible_for_testing DEFINE_SPINLOCK(creds_hash_update_lock);
static struct proc_cred_data *creds_fast_hash[MAX_PID_32 + 1];
__visible_for_testing struct mem_cache_list mem_cache[DEFEX_MEM_CACHE_COUNT];
static int creds_fast_hash_ready __ro_after_init;
__visible_for_testing void mem_cache_alloc(void);


void __init creds_fast_hash_init(void)
{
	unsigned int i;
	static const int sizes[DEFEX_MEM_CACHE_COUNT] __initdata = {
		sizeof(struct proc_cred_data),
		sizeof(struct proc_cred_data) + sizeof(struct id_set),
		sizeof(struct hash_item_struct)
	};

	hash_init(creds_hash);
	for (i = 0; i <= MAX_PID_32; i++)
		creds_fast_hash[i] = NULL;

	for(i = 0; i < ARRAY_SIZE(sizes); i++) {
		snprintf(mem_cache[i].name, sizeof(mem_cache[i].name), "defex%d", i);
		mem_cache[i].allocator = kmem_cache_create(mem_cache[i].name, sizes[i], 0, 0, NULL);
	}

	for(i = 0; i < (DEFEX_MEM_CACHE_SIZE / 2); i++)
		mem_cache_alloc();

	creds_fast_hash_ready = 1;
}

int is_task_creds_ready(void)
{
	return creds_fast_hash_ready;
}

__visible_for_testing inline void *mem_cache_get(int cache_number)
{
	int n;
	n = atomic_read(&mem_cache[cache_number].count);
	if (n) {
		atomic_dec(&mem_cache[cache_number].count);
		return mem_cache[cache_number].mem_cache_array[n - 1];
	}
	return NULL;
}

__visible_for_testing inline void *mem_cache_reclaim(int cache_number, void *ptr)
{
	int n;
	n = atomic_read(&mem_cache[cache_number].count);
	if (n < DEFEX_MEM_CACHE_SIZE) {
		atomic_inc(&mem_cache[cache_number].count);
		mem_cache[cache_number].mem_cache_array[n] = ptr;
		ptr = NULL;
	}
	return ptr;
}

__visible_for_testing void mem_cache_alloc(void)
{
	int mem_allocated = 0;
	int i, n;
	unsigned long flags;
	void *mem_block[DEFEX_MEM_CACHE_COUNT];

	for(i = 0; i < DEFEX_MEM_CACHE_COUNT; i++) {
		mem_block[i] = NULL;
		n = atomic_read(&mem_cache[i].count);
		if (n < (DEFEX_MEM_CACHE_SIZE / 2)) {
			mem_block[i] = kmem_cache_alloc(mem_cache[i].allocator, in_atomic() ? GFP_ATOMIC:GFP_KERNEL);
			mem_allocated++;
		}
	}

	if (!mem_allocated)
		return;

	spin_lock_irqsave(&creds_hash_update_lock, flags);
	for(i = 0; i < DEFEX_MEM_CACHE_COUNT; i++) {
		n = atomic_read(&mem_cache[i].count);
		if (mem_block[i] && n < DEFEX_MEM_CACHE_SIZE) {
			mem_cache[i].mem_cache_array[n] = mem_block[i];
			mem_block[i] = NULL;
			atomic_inc(&mem_cache[i].count);
			mem_allocated--;
		}
	}
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);

	if (!mem_allocated)
		return;

	for(i = 0; i < DEFEX_MEM_CACHE_COUNT; i++) {
		if (mem_block[i]) {
			kmem_cache_free(mem_cache[i].allocator, mem_block[i]);
		}
	}
}

__visible_for_testing struct proc_cred_data *get_cred_data(int id)
{
	struct proc_cred_data *cred_data = NULL;
	struct hash_item_struct *obj;

	if (id < 0)
		return NULL;
	if (id <= MAX_PID_32) {
		cred_data = creds_fast_hash[id];
	} else {
		hash_for_each_possible(creds_hash, obj, node, id) {
			if (obj->id == id) {
				cred_data = obj->cred_data;
				break;
			}
		}
	}
	return cred_data;
}

__visible_for_testing struct proc_cred_data **get_cred_ptr(int id)
{
	struct proc_cred_data **cred_ptr = NULL;
	struct hash_item_struct *obj;

	if (id < 0)
		return NULL;
	if (id <= MAX_PID_32) {
		cred_ptr = &creds_fast_hash[id];
	} else {
		hash_for_each_possible(creds_hash, obj, node, id) {
			if (obj->id == id) {
				cred_ptr = &obj->cred_data;
				break;
			}
		}
	}
	return cred_ptr;
}

__visible_for_testing void set_cred_data(int id, struct proc_cred_data **cred_ptr, struct proc_cred_data *cred_data)
{
	struct hash_item_struct *obj;

	if (id < 0)
		return;
	if (cred_ptr) {
		*cred_ptr = cred_data;
	} else {
		if (id > MAX_PID_32) {
			obj = mem_cache_get(CACHE_HTABLE_ITEM);
			if (!obj)
				return;
			obj->id = id;
			obj->cred_data = cred_data;
			hash_add(creds_hash, &obj->node, id);
		}
	}
}

void get_task_creds(struct task_struct *p, unsigned int *uid_ptr, unsigned int *fsuid_ptr, unsigned int *egid_ptr, unsigned short *cred_flags_ptr)
{
	struct proc_cred_data *cred_data, *thread_cred_data;
	struct id_set *ids_ptr;
	unsigned int uid = 0, fsuid = 0, egid = 0;
	unsigned short cred_flags = CRED_FLAGS_PROOT;
	unsigned long flags;
	int tgid = p->tgid, pid = p->pid;

	spin_lock_irqsave(&creds_hash_update_lock, flags);
	cred_data = get_cred_data(tgid);
	if (cred_data) {
		if (tgid == pid) {
			ids_ptr = (cred_data->cred_flags & CRED_FLAGS_MAIN_UPDATED) ? \
				(&cred_data->main_ids[0]) : (&cred_data->default_ids);
		} else {
			if (cred_data->cred_flags & CRED_FLAGS_SUB_UPDATED) {
				thread_cred_data = get_cred_data(pid);
				if (thread_cred_data)
					cred_data = thread_cred_data;
			}
			ids_ptr = &cred_data->default_ids;
		}
		GET_CREDS(ids_ptr, cred_data);
	}
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	*uid_ptr = uid;
	*fsuid_ptr = fsuid;
	*egid_ptr = egid;
	*cred_flags_ptr = cred_flags;
}

int set_task_creds(struct task_struct *p, unsigned int uid, unsigned int fsuid, unsigned int egid, unsigned short cred_flags)
{
	struct proc_cred_data *cred_data = NULL, *tmp_data, **cred_ptr;
	struct id_set *ids_ptr;
	unsigned long flags;
	int err = -1, tgid = p->tgid, pid = p->pid;
	void *free_buff = NULL;


	mem_cache_alloc();
	spin_lock_irqsave(&creds_hash_update_lock, flags);

	/* Search for main proces's data */
	cred_ptr = get_cred_ptr(tgid);
	cred_data = (cred_ptr) ? (*cred_ptr) : NULL;
	if (!cred_data) {
		/* Not found? Allocate a new data */
		cred_data = mem_cache_get(CACHE_CRED_DATA);
		if (!cred_data)
			goto set_finish;
		cred_data->cred_flags = 0;
		cred_data->tcnt = 1;
		set_cred_data(tgid, cred_ptr, cred_data);
	}
	ids_ptr = &cred_data->default_ids;

	if (cred_data->tcnt >= 2) {
		if (tgid == pid) {
			/* Allocate extended data for main process, copy and remove old data */
			if (!(cred_data->cred_flags & CRED_FLAGS_MAIN_UPDATED)) {
				cred_data->cred_flags |= CRED_FLAGS_MAIN_UPDATED;
				tmp_data = mem_cache_get(CACHE_CRED_DATA_ID);
				if (!tmp_data)
					goto set_finish;
				*tmp_data = *cred_data;
				free_buff = mem_cache_reclaim(CACHE_CRED_DATA, cred_data);
				cred_data = tmp_data;
				set_cred_data(tgid, cred_ptr, cred_data);
			}
			ids_ptr = &cred_data->main_ids[0];
		} else {
			cred_data->cred_flags |= CRED_FLAGS_SUB_UPDATED;
			/* Search for thread's data. Allocate, if not found */
			cred_ptr = get_cred_ptr(pid);
			cred_data = (cred_ptr) ? (*cred_ptr) : NULL;
			if (!cred_data) {
				cred_data = mem_cache_get(CACHE_CRED_DATA);
				if (!cred_data)
					goto set_finish;
				set_cred_data(pid, cred_ptr, cred_data);
			}
			cred_data->cred_flags = 0;
			ids_ptr = &cred_data->default_ids;
		}
	}
	SET_CREDS(ids_ptr, cred_data);
	err = 0;

set_finish:
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	/* Free the pending pointer */
	if (free_buff)
		kmem_cache_free(mem_cache[CACHE_CRED_DATA].allocator, free_buff);
	mem_cache_alloc();
	return err;
}

void set_task_creds_tcnt(struct task_struct *p, int addition)
{
	struct hash_item_struct *tgid_obj = NULL, *pid_obj = NULL;
	struct proc_cred_data **cred_ptr, *tgid_cred_data = NULL, *pid_cred_data = NULL;
	struct proc_cred_data *free_buff1 = NULL, *free_buff2 = NULL;
	int tgid = p->tgid, pid = p->pid;
	unsigned long flags;

	spin_lock_irqsave(&creds_hash_update_lock, flags);
	/* Remove the thread's data, if found */
	if (tgid != pid && addition == -1) {
		cred_ptr = get_cred_ptr(pid);
		pid_cred_data = (cred_ptr) ? (*cred_ptr) : NULL;
		if (pid_cred_data) {
			*cred_ptr = NULL;
			/* Return to pre-allocated pool, if possible */
			free_buff1 = mem_cache_reclaim(CACHE_CRED_DATA, pid_cred_data);
		}
		/* Remove the thread's hash container */
		if (cred_ptr && pid > MAX_PID_32) {
			pid_obj = container_of(cred_ptr, struct hash_item_struct, cred_data);
			hash_del(&pid_obj->node);
			/* Return to pre-allocated pool, if possible */
			pid_obj = mem_cache_reclaim(CACHE_HTABLE_ITEM, pid_obj);
		}
	}
	/* Search for the main process's data */
	cred_ptr = get_cred_ptr(tgid);
	tgid_cred_data = (cred_ptr) ? (*cred_ptr) : NULL;
	if (tgid_cred_data) {
		tgid_cred_data->tcnt += addition;
		/* No threads, remove process data */
		if (!tgid_cred_data->tcnt) {
			*cred_ptr = NULL;
			/* Return to pre-allocated pool, if possible */
			free_buff2 = mem_cache_reclaim((tgid_cred_data->cred_flags & CRED_FLAGS_MAIN_UPDATED) ? \
				CACHE_CRED_DATA_ID : CACHE_CRED_DATA, tgid_cred_data);
			/* Remove the process's hash container */
			if (tgid > MAX_PID_32) {
				tgid_obj = container_of(cred_ptr, struct hash_item_struct, cred_data);
				hash_del(&tgid_obj->node);
				/* Return to pre-allocated pool, if possible */
				tgid_obj = mem_cache_reclaim(CACHE_HTABLE_ITEM, tgid_obj);
			}
		}
	}
	spin_unlock_irqrestore(&creds_hash_update_lock, flags);
	/* Free all pending pointers */
	if (free_buff1)
		kmem_cache_free(mem_cache[CACHE_CRED_DATA].allocator, free_buff1);
	if (free_buff2)
		kmem_cache_free(mem_cache[(free_buff2->cred_flags & CRED_FLAGS_MAIN_UPDATED) ? \
			CACHE_CRED_DATA_ID : CACHE_CRED_DATA].allocator, free_buff2);
	if (pid_obj)
		kmem_cache_free(mem_cache[CACHE_HTABLE_ITEM].allocator, pid_obj);
	if (tgid_obj)
		kmem_cache_free(mem_cache[CACHE_HTABLE_ITEM].allocator, tgid_obj);
	return;
}

#else

int is_task_creds_ready(void)
{
	return 0;
}

void set_task_creds_tcnt(struct task_struct *p, int addition)
{
	(void)p;
	(void)addition;
}

#endif /* DEFEX_PED_ENABLE */
