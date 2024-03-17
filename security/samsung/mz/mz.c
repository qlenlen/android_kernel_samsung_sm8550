/*
 * Copyright (c) 2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/page-isolation.h>
#include <linux/workqueue.h>
#include <trace/hooks/mz.h>
#include "mz_internal.h"
#include "mz_log.h"
#include "mz_page.h"

static DEFINE_MUTEX(pid_list_lock);

struct mztarget_t mz_pt_list[PRLIMIT];
struct mutex crypto_list_lock;
struct mutex page_list_lock;
uint64_t *addr_list;
static int addr_list_count;
int addr_list_count_max;

#ifndef CONFIG_SEC_KUNIT
static bool is_mz_target(pid_t tgid);
static bool is_mz_all_zero_target(pid_t tgid);
static MzResult mz_add_new_target(pid_t tgid);
static MzResult remove_target_from_all_list(pid_t tgid);
static struct task_struct *findts(pid_t tgid);
static void compact_addr_list(void);
static void update_list(void);
#endif /* CONFIG_SEC_KUNIT */
static void unload_trusted_app_wq(struct work_struct *work);
static DECLARE_WORK(mz_ta_unload_work, unload_trusted_app_wq);

struct tgid_wk_t {
	pid_t tgid;
	struct work_struct remove_target_from_all_list_work;
};
static void remove_target_from_all_list_wq(struct work_struct *work);

static int add_count;

MzResult mz_exit(void)
{
	pid_t cur_tgid = current->pid;

	if (!is_mz_target(cur_tgid)) {
		mz_pt_list[cur_tgid].is_ta_fail_target = false;
		return MZ_SUCCESS;
	}

	MZ_LOG(err_level_debug, "[MZ DEBUG] %s %d %d\n", __func__, current->tgid, current->pid);

	mz_pt_list[cur_tgid].target = false;

	remove_target_from_all_list(cur_tgid);
#ifdef MZ_TA
	unload_trusted_app();
#endif /* MZ_TA */

	return MZ_SUCCESS;
}

static void vh_mz_exit(void *data, struct task_struct *p)
{
	pid_t cur_tgid = p->pid;
	bool ret;
	struct tgid_wk_t *wk;

	if (!is_mz_target(cur_tgid)) {
		mz_pt_list[cur_tgid].is_ta_fail_target = false;
		return;
	}

	MZ_LOG(err_level_debug, "[MZ DEBUG] %s %d %d\n", __func__, p->tgid, p->pid);

	mz_pt_list[cur_tgid].target = false;

	wk = kmalloc(sizeof(*wk), GFP_ATOMIC);
	if (!wk) {
		MZ_LOG(err_level_error, "%s wk kmalloc fail\n", __func__);
		return;
	}
	wk->tgid = cur_tgid;
	INIT_WORK(&(wk->remove_target_from_all_list_work), remove_target_from_all_list_wq);
	ret = schedule_work(&(wk->remove_target_from_all_list_work));
	if (!ret)
		MZ_LOG(err_level_error, "%s remove_target_from_all_list workqueue fail %d\n", __func__, ret);

#ifdef MZ_TA
	ret = queue_work(system_long_wq, &mz_ta_unload_work);
	if (!ret)
		MZ_LOG(err_level_error, "%s unload_trusted_app workqueue fail %d\n", __func__, ret);
#endif /* MZ_TA */
}

static void unload_trusted_app_wq(struct work_struct *work)
{
	unload_trusted_app();
}

static void remove_target_from_all_list_wq(struct work_struct *work)
{
	struct tgid_wk_t *wk = container_of(work, struct tgid_wk_t, remove_target_from_all_list_work);

	MZ_LOG(err_level_debug, "%s start\n", __func__);

	remove_target_from_all_list(wk->tgid);
	kfree(wk);
	MZ_LOG(err_level_debug, "%s end\n", __func__);
}

__visible_for_testing bool is_mz_target(pid_t tgid)
{
	if (tgid >= PRLIMIT || tgid <= 0)
		return false;

	if (mz_pt_list[tgid].target)
		return true;
	return false;
}

__visible_for_testing bool is_mz_all_zero_target(pid_t tgid)
{
	if (tgid >= PRLIMIT || tgid <= 0)
		return false;

	if (mz_pt_list[tgid].is_ta_fail_target)
		return true;
	return false;
}

MzResult mz_all_zero_set(pid_t tgid)
{
	MzResult mz_ret;

	mz_ret = mz_add_new_target(tgid);
	if (mz_ret != MZ_SUCCESS) {
		MZ_LOG(err_level_error, "MZ %s new target all zero set fail\n", __func__);
		return mz_ret;
	}

	mz_pt_list[tgid].is_ta_fail_target = true;
	return mz_ret;
}

static void compact_addr_list(void)
{
	uint64_t i = 1;
	struct pid_node_t *pid_node, *tp;
	struct pfn_node_encrypted_t *cur_encrypted, *t_e;

#ifdef MZ_DEBUG
	for (i = 3 ; i < addr_list_count ; i += 2)
		MZ_LOG(err_level_debug, "[MZ DEBUG] %s start %d %llx %d\n",
				__func__, addr_list[0], addr_list[i], addr_list[i+1]);
#endif /* MZ_DEBUG */

	for (i = 3 ; i < addr_list[0] ; i += 2) {
		if (addr_list[i] == 0) {
			addr_list[i] = addr_list[addr_list_count - 1];
			addr_list[i + 1] = addr_list[addr_list_count];

			mutex_lock(&pid_list_lock);
			list_for_each_entry_safe(pid_node, tp, &pid_list, list) {
				mutex_lock(&crypto_list_lock);

				list_for_each_entry_safe(cur_encrypted, t_e,
				&(mz_pt_list[pid_node->tgid].mz_list_head_crypto), list) {
					if (cur_encrypted->pa_index == addr_list_count - 1)
						cur_encrypted->pa_index = i;
				}

				mutex_unlock(&crypto_list_lock);
			}
			mutex_unlock(&pid_list_lock);

			memset(&(addr_list[addr_list_count - 1]), MZ_PAGE_POISON, sizeof(uint64_t) * 2);
			addr_list_count -= 2;
			i -= 2;
		}
	}
	addr_list[0] = addr_list_count;

#ifdef MZ_DEBUG
	for (i = 3 ; i < addr_list_count ; i += 2)
		MZ_LOG(err_level_debug, "[MZ DEBUG] %s end %d %llx %d\n",
				__func__, addr_list[0], addr_list[i], addr_list[i+1]);
#endif /* MZ_DEBUG */
}

MzResult remove_target_from_all_list(pid_t tgid)
{
	struct pid_node_t *curp, *tp;
	struct pfn_node_encrypted_t *cur_encrypted, *t_e;
	page_node *cur_page, *t_p;

	if (tgid >= PRLIMIT || tgid <= 0)
		return MZ_INVALID_INPUT_ERROR;

	mutex_lock(&crypto_list_lock);
	list_for_each_entry_safe(cur_encrypted, t_e, &(mz_pt_list[tgid].mz_list_head_crypto), list) {
		list_del(&(cur_encrypted->list));
		addr_list[cur_encrypted->pa_index] = 0;
		kfree(cur_encrypted);
		cur_encrypted = NULL;
	}
	mutex_unlock(&crypto_list_lock);

	mutex_lock(&page_list_lock);
	list_for_each_entry_safe(cur_page, t_p, &(mz_pt_list[tgid].mz_list_head_page), list) {
		list_del(&(cur_page->list));
		kfree(cur_page->mz_page);
		kfree(cur_page);
		cur_page = NULL;
	}
	mutex_unlock(&page_list_lock);

	mutex_lock( &pid_list_lock );
	list_for_each_entry_safe(curp, tp, &pid_list, list) {
		if (curp->tgid == tgid) {
			list_del(&(curp->list));
			kfree(curp);
			curp = NULL;
			MZ_LOG(err_level_debug, "%s %d\n", __func__, tgid);
		}
	}
	mutex_unlock( &pid_list_lock );

	compact_addr_list();

	return MZ_SUCCESS;
}

__visible_for_testing MzResult mz_add_new_target(pid_t tgid)
{
	struct pid_node_t *pid_node;
	MzResult mz_ret = MZ_SUCCESS;

	if (tgid >= PRLIMIT || tgid <= 0)
		return MZ_INVALID_INPUT_ERROR;

	if (is_mz_target(tgid)) {
		return mz_ret;
	}

	pid_node = kmalloc(sizeof(*pid_node), GFP_KERNEL);
#ifdef CONFIG_SEC_KUNIT
	if (tgid == MALLOC_FAIL_PID && pid_node) {
		kfree(pid_node);
		pid_node = NULL;
	}
#endif /* CONFIG_SEC_KUNIT */
	if (!pid_node) {
		MZ_LOG(err_level_error, "%s pid_node kmalloc fail\n", __func__);
		return MZ_MALLOC_ERROR;
	}

	mz_pt_list[tgid].target = true;
	mz_pt_list[tgid].is_ta_fail_target = false;

	pid_node->tgid = tgid;
	INIT_LIST_HEAD(&(pid_node->list));

	mutex_lock( &pid_list_lock );
	list_add(&(pid_node->list), &pid_list);
	mutex_unlock( &pid_list_lock );

	MZ_LOG(err_level_debug, "%s %d\n", __func__, tgid);

#ifdef MZ_TA
	mz_ret = load_trusted_app();
	if (mz_ret != MZ_SUCCESS) {
		MZ_LOG(err_level_info, "%s ta fail %d, free all memory\n", __func__, mz_ret);
		mz_pt_list[tgid].is_ta_fail_target = true;
	}
#endif /* MZ_TA */

	if (!isaddrset())
		set_mz_mem();

	return mz_ret;
}

static void update_list(void)
{
	uint64_t *new_addr_list;

	if (addr_list_count != addr_list_count_max - 2)
		return;

	addr_list_count_max *= 2;
	new_addr_list = kmalloc_array(addr_list_count_max, sizeof(uint64_t), GFP_KERNEL);
	if (!new_addr_list) {
		MZ_LOG(err_level_error, "%s new_addr_list kmalloc_array fail\n", __func__);
		return;
	}
	memcpy(new_addr_list, addr_list, (sizeof(uint64_t) * addr_list_count) + sizeof(uint64_t));
	memset(addr_list, MZ_PAGE_POISON, (sizeof(uint64_t) * addr_list_count) + sizeof(uint64_t));
	kfree(addr_list);
	addr_list = new_addr_list;
	set_mz_mem();
}

MzResult mz_add_target_pfn(pid_t tgid, unsigned long pfn, unsigned long offset,
							unsigned long len, unsigned long va, uint8_t __user *buf)
{
	struct pfn_node_encrypted_t *cur_encrypted;
	MzResult mz_ret = MZ_SUCCESS;
	struct page *target_page = pfn_to_page(pfn);
	uint64_t pa;
	uint64_t plain_pa_offset;
	unsigned long new_pfn = 0;
#ifdef MZ_TA
	uint64_t cipher_pa_offset;
	uint8_t *plain_pa_offset_8, cipher_pa_offset_8[8];
#endif

	if (pfn <= 0)
		return MZ_INVALID_INPUT_ERROR;

	mz_ret = mz_add_new_target(tgid);
	if (mz_ret != MZ_SUCCESS) {
		return mz_ret;
	}

	if (is_mz_all_zero_target(tgid)) {
		return mz_ret;
	}

	cur_encrypted = kmalloc(sizeof(*cur_encrypted), GFP_ATOMIC);
#ifdef CONFIG_SEC_KUNIT
	if (tgid == MALLOC_FAIL_CUR && cur_encrypted) {
		kfree(cur_encrypted);
		cur_encrypted = NULL;
	}
#endif /* CONFIG_SEC_KUNIT */
	if (!cur_encrypted) {
		MZ_LOG(err_level_error, "%s cur_encrypted kmalloc fail\n", __func__);
		return MZ_MALLOC_ERROR;
	}

#ifdef MZ_DEBUG
	pa = page_to_phys(target_page);
	MZ_LOG(err_level_debug, "%s original addr before migrate/gup %llx\n", __func__, pa + offset);
#endif

#ifndef CONFIG_SEC_KUNIT
	//Migration in case of CMA and pin
	mz_ret = mz_migrate_and_pin(target_page, va, buf, &new_pfn, tgid);
	if (mz_ret != MZ_SUCCESS)
		goto free_alloc;
#endif /* CONFIG_SEC_KUNIT */

	if (new_pfn != 0)
		target_page = pfn_to_page(new_pfn);
	pa = page_to_phys(target_page);
	MZ_LOG(err_level_debug, "%s original addr after migrate/gup %llx\n", __func__, pa + offset);

	update_list();

	plain_pa_offset = pa + offset;

#ifdef MZ_TA
	plain_pa_offset_8 = (uint8_t *)&plain_pa_offset;
	mz_ret = mz_wb_encrypt(plain_pa_offset_8, cipher_pa_offset_8);
	if (mz_ret != MZ_SUCCESS)
		goto free_alloc;
	cipher_pa_offset = *(uint64_t *)cipher_pa_offset_8;
	addr_list[++addr_list_count] = cipher_pa_offset;

	MZ_LOG(err_level_debug, "%s cipher (0x%llx)\n", __func__, (unsigned long long)cipher_pa_offset);
#else
	addr_list[++addr_list_count] = plain_pa_offset;
#endif

	addr_list[++addr_list_count] = len;
	addr_list[0] = addr_list_count;
	cur_encrypted->pa_index = addr_list_count - 1;

	INIT_LIST_HEAD(&(cur_encrypted->list));

	mutex_lock(&crypto_list_lock);
	list_add_tail(&(cur_encrypted->list), &(mz_pt_list[tgid].mz_list_head_crypto));
	mutex_unlock(&crypto_list_lock);

	MZ_LOG(err_level_debug, "%s %d %d %d (0x%llx) (0x%llx) %d\n",
			__func__, tgid, ++add_count, addr_list_count, (unsigned long long)pa, offset, len);

	return mz_ret;

free_alloc:
	kfree(cur_encrypted);
	return mz_ret;
}

MzResult mzinit(void)
{
	int i;
	for (i = 0 ; i < PRLIMIT ; i++) {
		mz_pt_list[i].target = false;
		mz_pt_list[i].is_ta_fail_target = false;
		INIT_LIST_HEAD(&(mz_pt_list[i].mz_list_head_crypto));
		INIT_LIST_HEAD(&(mz_pt_list[i].mz_list_head_page));
		mutex_init(&crypto_list_lock);
		mutex_init(&page_list_lock);
	}

	add_count = 0;
	addr_list_count = 2;
	addr_list_count_max = 0;

	if (mz_addr_init())
		set_mz_mem();

	register_trace_android_vh_mz_exit(vh_mz_exit, NULL);

	return MZ_SUCCESS;
}

//Util
MzResult mz_kget_process_name(pid_t tgid, char* name)
{
	MzResult result = MZ_SUCCESS;
	int cmdline_size;
	struct task_struct *task;

	if (tgid >= PRLIMIT || tgid <= 0)
		return MZ_INVALID_INPUT_ERROR;
	if (name == NULL)
		return MZ_INVALID_INPUT_ERROR;

	task = findts(tgid);
	if (!task)
		return MZ_GET_TS_ERROR;
	if (task->mm == NULL)
		return MZ_GET_TS_ERROR;
	cmdline_size = get_cmdline(task, name, MAX_PROCESS_NAME);
	if (cmdline_size == 0)
		result = MZ_PROC_NAME_GET_ERROR;
	name[cmdline_size] = 0;

	return result;
}

__visible_for_testing struct task_struct *findts(pid_t tgid)
{
	struct task_struct *task;

	if (tgid >= PRLIMIT || tgid <= 0)
		return NULL;
	task = pid_task(find_vpid(tgid), PIDTYPE_PID);
	return task;
}

MzResult (*load_trusted_app)(void) = NULL;
EXPORT_SYMBOL(load_trusted_app);
void (*unload_trusted_app)(void) = NULL;
EXPORT_SYMBOL(unload_trusted_app);

