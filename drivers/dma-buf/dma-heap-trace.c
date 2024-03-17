// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/mm.h>

#include <trace/hooks/mm.h>

extern long try_get_dma_heap_pool_size_kb(void);

static void dma_heap_pool_show_mem(void *data, unsigned int filter, nodemask_t *nodemask)
{
	long size_kb = try_get_dma_heap_pool_size_kb();

	if (size_kb < 0)
		return;

	pr_info("%s: %ld kB\n", "DmaHeapPool", size_kb);
}

static void dma_heap_pool_meminfo(void *data, struct seq_file *m)
{
	long size_kb = try_get_dma_heap_pool_size_kb();

	if (size_kb < 0)
		return;

	show_val_meminfo(m, "DmaHeapPool", size_kb);
}

void dma_heap_trace_init(void)
{
	register_trace_android_vh_show_mem(dma_heap_pool_show_mem, NULL);
	register_trace_android_vh_meminfo_proc_show(dma_heap_pool_meminfo, NULL);
}
