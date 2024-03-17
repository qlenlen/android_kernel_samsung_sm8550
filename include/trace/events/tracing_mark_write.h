/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM tracing_mark_write

#if !defined(_TRACE_TRACING_MARK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TRACING_MARK_H

#include <linux/tracepoint.h>

TRACE_EVENT(tracing_mark_write,
	TP_PROTO(int pid, const char *name, bool trace_begin),
	TP_ARGS(pid, name, trace_begin),
	TP_STRUCT__entry(
			__field(int, pid)
			__string(trace_name, name)
			__field(bool, trace_begin)
	),
	TP_fast_assign(
			__entry->pid = pid;
			__assign_str(trace_name, name);
			__entry->trace_begin = trace_begin;
	),
	TP_printk("%s|%d|%s", __entry->trace_begin ? "B" : "E",
		__entry->pid, __get_str(trace_name))
)
#endif /* _TRACE_TRACING_MARK_H */

#define TRACING_MARK_BUF_SIZE 256

#define tracing_mark_begin(fmt, args...)			\
do {								\
	char buf[TRACING_MARK_BUF_SIZE];			\
	if (!trace_tracing_mark_write_enabled())		\
		break;						\
	snprintf(buf, TRACING_MARK_BUF_SIZE, fmt, ##args);	\
	trace_tracing_mark_write(current->tgid, buf, true);	\
} while (0)
#define tracing_mark_end()					\
	trace_tracing_mark_write(current->tgid, "", false)

/* This part must be outside protection */
#include <trace/define_trace.h>

