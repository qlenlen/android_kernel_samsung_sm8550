/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sec_gmr

#if !defined(_TRACE_SEC_GMR_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SEC_GMR_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/mm.h>
#include <linux/page-flags.h>
#include <linux/sched.h>

DECLARE_EVENT_CLASS(gmr_class,
	TP_PROTO(struct task_struct *task, u64 nr_swap, u64 latency_us_jiffies, u64 latency_us_cputime),

	TP_ARGS(task, nr_swap, latency_us_jiffies, latency_us_cputime),

	TP_STRUCT__entry(
	__field(struct task_struct *, task)
		__field(u64, nr_swap)
		__field(u64, latency_us_cputime)
		__field(u64, latency_us_jiffies)
	),

	TP_fast_assign(
		__entry->task = task;
		__entry->nr_swap = nr_swap;
		__entry->latency_us_jiffies = latency_us_jiffies;
		__entry->latency_us_cputime = latency_us_cputime;
	),

	TP_printk("%d %s %llu %llu %llu",
		(__entry->task) ? __entry->task->pid : -1,
		(__entry->task) ? __entry->task->comm : "(unknown)",
		__entry->nr_swap,
		__entry->latency_us_jiffies,
		__entry->latency_us_cputime)
);

DEFINE_EVENT(gmr_class, gmr_swapout,
	TP_PROTO(struct task_struct *task, u64 nr_swap, u64 latency_us_jiffies, u64 latency_us_cputime),
	TP_ARGS(task, nr_swap, latency_us_jiffies, latency_us_cputime)
);

DEFINE_EVENT(gmr_class, gmr_swapin,
	TP_PROTO(struct task_struct *task, u64 nr_swap, u64 latency_us_jiffies, u64 latency_us_cputime),
	TP_ARGS(task, nr_swap, latency_us_jiffies, latency_us_cputime)
);

#endif /* _TRACE_SEC_GMR_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
