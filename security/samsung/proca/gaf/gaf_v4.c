/*
 *  gaf_v4.c
 *
 */
#include "proca_gaf.h"

#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <asm/pgtable.h>
#include <linux/kernel_stat.h>
#include "../fs/mount.h"

#ifdef CONFIG_FIVE_GKI_10
#define OFFSETOF_INTEGRITY offsetof(struct task_struct, android_vendor_data1[2])
#define OFFSETOF_F_SIGNATURE offsetof(struct file, android_vendor_data1)
#else
#define OFFSETOF_INTEGRITY offsetof(struct task_struct, integrity)
#define OFFSETOF_F_SIGNATURE offsetof(struct file, f_signature)
#endif

static struct GAForensicINFO {
	unsigned short ver;
	unsigned int size;
	unsigned short task_struct_struct_state;
	unsigned short task_struct_struct_comm;
	unsigned short task_struct_struct_tasks;
	unsigned short task_struct_struct_pid;
	unsigned short task_struct_struct_stack;
	unsigned short task_struct_struct_mm;
	unsigned short mm_struct_struct_start_data;
	unsigned short mm_struct_struct_end_data;
	unsigned short mm_struct_struct_start_brk;
	unsigned short mm_struct_struct_brk;
	unsigned short mm_struct_struct_start_stack;
	unsigned short mm_struct_struct_arg_start;
	unsigned short mm_struct_struct_arg_end;
	unsigned short mm_struct_struct_pgd;
	unsigned short mm_struct_struct_mmap;
	unsigned short vm_area_struct_struct_vm_start;
	unsigned short vm_area_struct_struct_vm_end;
	unsigned short vm_area_struct_struct_vm_next;
	unsigned short vm_area_struct_struct_vm_flags;
	unsigned short vm_area_struct_struct_vm_file;
#ifndef CONFIG_ARM64
	unsigned short thread_info_struct_cpu_context;
	unsigned short cpu_context_save_struct_sp;
#endif
	unsigned short file_struct_f_path;
	unsigned short path_struct_mnt;
	unsigned short path_struct_dentry;
	unsigned short dentry_struct_d_parent;
	unsigned short dentry_struct_d_name;
	unsigned short qstr_struct_name;
	unsigned short vfsmount_struct_mnt_mountpoint;
	unsigned short vfsmount_struct_mnt_root;
	unsigned short vfsmount_struct_mnt_parent;
#ifdef CONFIG_ARM64
	unsigned long pgdir_shift;
	unsigned long ptrs_per_pte;
	unsigned long phys_offset;
	unsigned long page_offset;
	unsigned long page_shift;
	unsigned long page_size;
#else
	unsigned int pgdir_shift;
	unsigned int ptrs_per_pte;
	unsigned int phys_offset;
	unsigned int page_offset;
	unsigned int page_shift;
	unsigned int page_size;
#endif
	unsigned short task_struct_struct_thread_group;
#ifdef CONFIG_ARM64
	unsigned short task_struct_struct_thread;
#endif
	unsigned short task_struct_struct_utime;
	unsigned short task_struct_struct_stime;
	unsigned short list_head_struct_next;
	unsigned short list_head_struct_prev;
	unsigned short rq_struct_curr;
	unsigned short thread_info_struct_cpu;
	unsigned short task_struct_struct_prio;
	unsigned short task_struct_struct_static_prio;
	unsigned short task_struct_struct_normal_prio;
	unsigned short task_struct_struct_rt_priority;
	unsigned short task_struct_struct_se;
	unsigned short sched_entity_struct_exec_start;
	unsigned short sched_entity_struct_sum_exec_runtime;
	unsigned short sched_entity_struct_prev_sum_exec_runtime;
	unsigned short task_struct_struct_sched_info;
	unsigned short sched_info_struct_pcount;
	unsigned short sched_info_struct_run_delay;
	unsigned short sched_info_struct_last_arrival;
	unsigned short sched_info_struct_last_queued;
	unsigned short task_struct_struct_blocked_on;
	unsigned short mutex_waiter_struct_list;
	unsigned short mutex_waiter_struct_task;
	unsigned short sched_entity_struct_cfs_rq_struct;
	unsigned short cfs_rq_struct_rq_struct;
	unsigned short gaf_fp;
	unsigned short task_struct_integrity;
	unsigned short file_struct_f_signature;
	unsigned short mm_struct_struct_mm_rb;
	unsigned short vm_area_struct_struct_vm_rb;
	unsigned short qstr_struct_len;
	unsigned short mount_struct_mnt_mountpoint;
	unsigned short pid_struct_numbers;
	unsigned short upid_struct_pid_chain;
	unsigned short upid_struct_nr;
	unsigned short hlist_node_struct_next;
	unsigned short task_struct_pids;
	unsigned short pid_struct_first;
	signed short vfsmount_struct_bp_mount;
	unsigned short  GAFINFOCheckSum;
} GAFINFO = {
	.ver = 0x0400, /* by i.vorobiov 2017 08 25 */
	.size = sizeof(GAFINFO),
	.task_struct_struct_state = offsetof(struct task_struct, state),
	.task_struct_struct_comm = offsetof(struct task_struct, comm),
	.task_struct_struct_tasks = offsetof(struct task_struct, tasks),
	.task_struct_struct_pid = offsetof(struct task_struct, pid),
	.task_struct_struct_stack = offsetof(struct task_struct, stack),
	.task_struct_struct_mm = offsetof(struct task_struct, mm),
	.mm_struct_struct_start_data = offsetof(struct mm_struct, start_data),
	.mm_struct_struct_end_data = offsetof(struct mm_struct, end_data),
	.mm_struct_struct_start_brk = offsetof(struct mm_struct, start_brk),
	.mm_struct_struct_brk = offsetof(struct mm_struct, brk),
	.mm_struct_struct_start_stack = offsetof(struct mm_struct, start_stack),
	.mm_struct_struct_arg_start = offsetof(struct mm_struct, arg_start),
	.mm_struct_struct_arg_end = offsetof(struct mm_struct, arg_end),
	.mm_struct_struct_pgd = offsetof(struct mm_struct, pgd),
	.mm_struct_struct_mmap = offsetof(struct mm_struct, mmap),
	.mm_struct_struct_mm_rb = offsetof(struct mm_struct, mm_rb),
	.vm_area_struct_struct_vm_start =
		offsetof(struct vm_area_struct, vm_start),
	.vm_area_struct_struct_vm_end = offsetof(struct vm_area_struct, vm_end),
	.vm_area_struct_struct_vm_next =
		offsetof(struct vm_area_struct, vm_next),
	.vm_area_struct_struct_vm_flags =
		offsetof(struct vm_area_struct, vm_flags),
	.vm_area_struct_struct_vm_file =
		offsetof(struct vm_area_struct, vm_file),
	.vm_area_struct_struct_vm_rb
		= offsetof(struct vm_area_struct, vm_rb),
	.pid_struct_numbers = offsetof(struct pid, numbers[0]),
	.upid_struct_pid_chain = 0,
	.upid_struct_nr = 0,
	.hlist_node_struct_next = offsetof(struct hlist_node, next),
	.task_struct_pids = 0,
	.pid_struct_first
		= offsetof(struct pid, tasks[0])
		+ offsetof(struct hlist_head, first),
#ifndef CONFIG_ARM64
	.thread_info_struct_cpu_context =
		offsetof(struct thread_info, cpu_context),
	.cpu_context_save_struct_sp = offsetof(struct cpu_context_save, sp),
#endif
	.file_struct_f_path = offsetof(struct file, f_path),
	.path_struct_mnt = offsetof(struct path, mnt),
	.path_struct_dentry = offsetof(struct path, dentry),
	.dentry_struct_d_parent = offsetof(struct dentry, d_parent),
	.dentry_struct_d_name = offsetof(struct dentry, d_name),
	.qstr_struct_name = offsetof(struct qstr, name),
	.qstr_struct_len = offsetof(struct qstr, len),
	.vfsmount_struct_mnt_root = offsetof(struct vfsmount, mnt_root),
	.pgdir_shift = PGDIR_SHIFT,
	.ptrs_per_pte = PTRS_PER_PTE,
//TEMP	.phys_offset = PHYS_OFFSET,
	.page_offset = PAGE_OFFSET,
	.page_shift = PAGE_SHIFT,
	.page_size = PAGE_SIZE,
	.task_struct_struct_thread_group  =
		offsetof(struct task_struct, thread_group),
#ifdef CONFIG_ARM64
	.task_struct_struct_thread = offsetof(struct task_struct, thread),
#endif
	.task_struct_struct_utime =  offsetof(struct task_struct, utime),
	.task_struct_struct_stime =  offsetof(struct task_struct, stime),
	.list_head_struct_next = offsetof(struct list_head, next),
	.list_head_struct_prev = offsetof(struct list_head, prev),
	.rq_struct_curr = 0,
	.thread_info_struct_cpu = 0,
	.task_struct_struct_prio = offsetof(struct task_struct, prio),
	.task_struct_struct_static_prio =
		offsetof(struct task_struct, static_prio),
	.task_struct_struct_normal_prio =
		offsetof(struct task_struct, normal_prio),
	.task_struct_struct_rt_priority =
		offsetof(struct task_struct, rt_priority),
	.task_struct_struct_se = offsetof(struct task_struct, se),
	.sched_entity_struct_exec_start =
		offsetof(struct sched_entity, exec_start),
	.sched_entity_struct_sum_exec_runtime =
		offsetof(struct sched_entity, sum_exec_runtime),
	.sched_entity_struct_prev_sum_exec_runtime =
		offsetof(struct sched_entity, prev_sum_exec_runtime),
#if defined(CONFIG_SCHEDSTATS) || defined(CONFIG_TASK_DELAY_ACCT)
	.task_struct_struct_sched_info =
		offsetof(struct task_struct, sched_info),
	.sched_info_struct_pcount = offsetof(struct sched_info, pcount),
	.sched_info_struct_run_delay = offsetof(struct sched_info, run_delay),
	.sched_info_struct_last_arrival =
		offsetof(struct sched_info, last_arrival),
	.sched_info_struct_last_queued =
		offsetof(struct sched_info, last_queued),
#else
	.task_struct_struct_sched_info = 0x1223,
	.sched_info_struct_pcount = 0x1224,
	.sched_info_struct_run_delay = 0x1225,
	.sched_info_struct_last_arrival = 0x1226,
	.sched_info_struct_last_queued = 0x1227,
#endif
#ifdef CONFIG_DEBUG_MUTEXES
	.task_struct_struct_blocked_on =
		offsetof(struct task_struct, blocked_on),
	.mutex_waiter_struct_list = offsetof(struct mutex_waiter, list),
	.mutex_waiter_struct_task = offsetof(struct mutex_waiter, task),
#else
	.task_struct_struct_blocked_on = 0x1228,
	.mutex_waiter_struct_list = 0x1229,
	.mutex_waiter_struct_task = 0x122a,
#endif
#ifdef CONFIG_FAIR_GROUP_SCHED
	.sched_entity_struct_cfs_rq_struct =
		offsetof(struct sched_entity, cfs_rq),
#else
	.sched_entity_struct_cfs_rq_struct = 0x1223,
#endif
	.cfs_rq_struct_rq_struct = 0,
#ifdef CONFIG_FRAME_POINTER
	.gaf_fp = 1,
#else
	.gaf_fp = 0,
#endif
#ifdef CONFIG_FIVE
	.task_struct_integrity = OFFSETOF_INTEGRITY,
#if defined(CONFIG_FIVE_PA_FEATURE) || defined(CONFIG_PROCA)
	.file_struct_f_signature = OFFSETOF_F_SIGNATURE,
#endif
#endif
	.mount_struct_mnt_mountpoint = offsetof(struct mount, mnt_mountpoint),
#if defined(CONFIG_KDP_NS) || defined(CONFIG_RUSTUH_KDP_NS)
#if defined(CONFIG_SOC_EXYNOS2100) || defined(CONFIG_ARCH_LAHAINA)
	.vfsmount_struct_bp_mount = offsetof(struct kdp_vfsmount, bp_mount),
#else
	.vfsmount_struct_bp_mount = offsetof(struct vfsmount, bp_mount),
#endif
#else
	.vfsmount_struct_bp_mount =
		(short)(offsetof(struct mount, mnt_mountpoint)
		- offsetof(struct mount, mnt)),
#endif
	.GAFINFOCheckSum = 0
};

static int __init proca_init_gaf(void)
{
	const unsigned short size =
			offsetof(struct GAForensicINFO, GAFINFOCheckSum);
	unsigned char *memory = (unsigned char *)&GAFINFO;
	unsigned short i = 0;
	unsigned short checksum = 0;
	/*
	 *  Add GAForensic init for preventing symbol removal for optimization.
	 */
	GAFINFO.rq_struct_curr = 0;

	for (i = 0; i < size; i++) {
		if (checksum & 0x8000)
			checksum = ((checksum << 1) | 1) ^ memory[i];
		else
			checksum = (checksum << 1) ^ memory[i];
	}
	GAFINFO.GAFINFOCheckSum = checksum;

	return 0;
}
core_initcall(proca_init_gaf)
