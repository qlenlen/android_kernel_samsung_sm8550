// SPDX-License-Identifier: GPL-2.0
/*
 * sec_mm/
 *
 * Copyright (C) 2020 Samsung Electronics
 *
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/swap.h>
#include <linux/oom.h>
#include <linux/dma-buf.h>
#include <linux/fdtable.h>
#include "sec_mm.h"

#define USE_DUMP_DMABUF_TASKS

/* return true if the task is not adequate as candidate victim task. */
static bool oom_unkillable_task(struct task_struct *p)
{
	if (is_global_init(p))
		return true;
	if (p->flags & PF_KTHREAD)
		return true;
	return false;
}

/*
 * The process p may have detached its own ->mm while exiting or through
 * use_mm(), but one or more of its subthreads may still have a valid
 * pointer.  Return p, or any of its subthreads with a valid ->mm, with
 * task_lock() held.
 */
static struct task_struct *mm_debug_find_lock_task_mm(struct task_struct *p)
{
	struct task_struct *t;

	rcu_read_lock();

	for_each_thread(p, t) {
		task_lock(t);
		if (likely(t->mm))
			goto found;
		task_unlock(t);
	}
	t = NULL;
found:
	rcu_read_unlock();

	return t;
}

#ifdef USE_DUMP_DMABUF_TASKS
struct dmabuf_ifd_data {
	int cnt;
	size_t size;
};

static int dmabuf_iterate_fd(const void *t, struct file *file, unsigned fd)
{
	struct dmabuf_ifd_data *dmabuf_usage = (struct dmabuf_ifd_data*)t;
	struct dma_buf *dmabuf;

	if (!is_dma_buf_file(file))
		return 0;

	dmabuf = file->private_data;

	dmabuf_usage->cnt++;
	dmabuf_usage->size += dmabuf->size >> 10;

	return 0;
}

static void mm_debug_dump_dma_buf_tasks(void)
{
	struct task_struct *p;
	struct task_struct *task;
	long heaviest_dma_buf = 0;
	char heaviest_comm[TASK_COMM_LEN];
	pid_t heaviest_pid;

	static DEFINE_RATELIMIT_STATE(dma_buf_tasks_rs, 30 * HZ, 1);

	if (!__ratelimit(&dma_buf_tasks_rs))
		return;

	pr_info("mm_debug dma_buf tasks\n");
	pr_info("[  pid  ]   uid  tgid dmabufcnt dmabufsz(kb) name\n");
	rcu_read_lock();
	for_each_process(p) {
		struct dmabuf_ifd_data dmabuf_usage;

		if (oom_unkillable_task(p))
			continue;

		task = mm_debug_find_lock_task_mm(p);
		if (!task) {
			/*
			 * This is a kthread or all of p's threads have already
			 * detached their mm's.  There's no need to report
			 * them; they can't be oom killed anyway.
			 */
			continue;
		}

		dmabuf_usage.cnt = 0;
		dmabuf_usage.size = 0;
		iterate_fd(p->files, 0, dmabuf_iterate_fd, &dmabuf_usage);

		if (!dmabuf_usage.size) {
			task_unlock(task);
			continue;
		}

		pr_info("[%7d] %5d %5d %9d %12zu %s\n",
			task->pid, from_kuid(&init_user_ns, task_uid(task)),
			task->tgid, dmabuf_usage.cnt, dmabuf_usage.size,
			task->comm);

		if (dmabuf_usage.size > heaviest_dma_buf) {
			heaviest_dma_buf = dmabuf_usage.size;
			strncpy(heaviest_comm, task->comm, TASK_COMM_LEN);
			heaviest_pid = task->pid;
		}
		task_unlock(task);
	}
	rcu_read_unlock();
	if (heaviest_dma_buf)
		pr_info("heaviest_task_dma_buf:%s(%d) size:%luKB\n",
			heaviest_comm, heaviest_pid, heaviest_dma_buf);
}
#else
static void mm_debug_dump_dma_buf_tasks(void) {}
#endif

void mm_debug_dump_tasks(void)
{
	struct task_struct *p;
	struct task_struct *task;
	unsigned long cur_rss_sum;
	unsigned long heaviest_rss_sum = 0;
	char heaviest_comm[TASK_COMM_LEN];
	pid_t heaviest_pid;

	pr_info("mm_debug dump tasks\n");
	pr_info("[  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name\n");
	rcu_read_lock();
	for_each_process(p) {
		if (oom_unkillable_task(p))
			continue;

		task = mm_debug_find_lock_task_mm(p);
		if (!task) {
			/*
			 * This is a kthread or all of p's threads have already
			 * detached their mm's.  There's no need to report
			 * them; they can't be oom killed anyway.
			 */
			continue;
		}

		pr_info("[%7d] %5d %5d %8lu %8lu %8ld %8lu         %5hd %s\n",
			task->pid, from_kuid(&init_user_ns, task_uid(task)),
			task->tgid, task->mm->total_vm, get_mm_rss(task->mm),
			mm_pgtables_bytes(task->mm),
			get_mm_counter(task->mm, MM_SWAPENTS),
			task->signal->oom_score_adj, task->comm);
		cur_rss_sum = get_mm_rss(task->mm) +
					get_mm_counter(task->mm, MM_SWAPENTS);
		if (cur_rss_sum > heaviest_rss_sum) {
			heaviest_rss_sum = cur_rss_sum;
			strncpy(heaviest_comm, task->comm, TASK_COMM_LEN);
			heaviest_pid = task->pid;
		}
		task_unlock(task);
	}
	rcu_read_unlock();
	if (heaviest_rss_sum)
		pr_info("heaviest_task_rss:%s(%d) size:%luKB, totalram_pages:%luKB\n",
			heaviest_comm, heaviest_pid, K(heaviest_rss_sum),
			K(totalram_pages()));

	mm_debug_dump_dma_buf_tasks();
}

MODULE_LICENSE("GPL");
