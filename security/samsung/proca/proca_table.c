/*
 * PROCA task descriptors table
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 * Hryhorii Tur, <hryhorii.tur@partner.samsung.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "proca_table.h"

#include <linux/hashtable.h>
#include <linux/string.h>

void proca_table_init(struct proca_table *table)
{
	BUG_ON(!table);

	memset(table, 0, sizeof(*table));

	spin_lock_init(&table->pid_map_lock);
	hash_init(table->pid_map);

	spin_lock_init(&table->app_name_map_lock);
	hash_init(table->app_name_map);

	table->hash_tables_shift = PROCA_TASKS_TABLE_SHIFT;
}

/*
 * Following hash functions and constants were taken from 4.9.59 kernel
 * in order to simplify porting to new devices.
 */

#define GOLDEN_RATIO_32 0x61C88647

static inline u32 proca_hash_32(u32 val)
{
	return val * GOLDEN_RATIO_32;
}

/* Hash courtesy of the R5 hash in reiserfs modulo sign bits */
#define proca_init_name_hash(salt)		(unsigned long)(salt)

/* partial hash update function. Assume roughly 4 bits per character */
static inline unsigned long
proca_partial_name_hash(unsigned long c, unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/*
 * Finally: cut down the number of bits to a int value (and try to avoid
 * losing bits).  This also has the property (wanted by the dcache)
 * that the msbits make a good hash table index.
 */
static inline unsigned long proca_end_name_hash(unsigned long hash)
{
	return proca_hash_32((unsigned int)hash);
}

static unsigned long calculate_app_name_hash(struct proca_table *table,
					     const char *app_name,
					     size_t app_name_size)
{
	size_t i;
	unsigned long hash = proca_init_name_hash(0);

	if (!app_name)
		return proca_end_name_hash(hash);

	for (i = 0; i < app_name_size; ++i)
		hash = proca_partial_name_hash(app_name[i], hash);
	return proca_end_name_hash(hash) % (1 << table->hash_tables_shift);
}

static unsigned long calculate_pid_hash(struct proca_table *table, pid_t pid)
{
	return proca_hash_32(pid) >> (32 - table->hash_tables_shift);
}

void proca_table_add_task_descr(struct proca_table *table,
				struct proca_task_descr *descr)
{
	unsigned long hash_key;
	unsigned long irqsave_flags;

	hash_key = calculate_pid_hash(table, descr->task->pid);
	spin_lock_irqsave(&table->pid_map_lock, irqsave_flags);
	hlist_add_head(&descr->pid_map_node,
		       &table->pid_map[hash_key]);
	spin_unlock_irqrestore(&table->pid_map_lock, irqsave_flags);

	if (descr->proca_identity.certificate) {
		hash_key = calculate_app_name_hash(table,
			descr->proca_identity.parsed_cert.app_name,
			descr->proca_identity.parsed_cert.app_name_size);
		spin_lock_irqsave(&table->app_name_map_lock, irqsave_flags);
		hlist_add_head(&descr->app_name_map_node,
			&table->app_name_map[hash_key]);
		spin_unlock_irqrestore(
			&table->app_name_map_lock, irqsave_flags);
	}
}

void proca_table_remove_task_descr(struct proca_table *table,
				struct proca_task_descr *descr)
{
	unsigned long irqsave_flags;

	if (!descr)
		return;

	spin_lock_irqsave(&table->pid_map_lock, irqsave_flags);
	hash_del(&descr->pid_map_node);
	spin_unlock_irqrestore(&table->pid_map_lock, irqsave_flags);

	spin_lock_irqsave(&table->app_name_map_lock, irqsave_flags);
	hash_del(&descr->app_name_map_node);
	spin_unlock_irqrestore(&table->app_name_map_lock, irqsave_flags);
}

struct proca_task_descr *proca_table_get_by_task(
					struct proca_table *table,
					const struct task_struct *task)
{
	struct proca_task_descr *descr;
	struct proca_task_descr *target_task_descr = NULL;
	unsigned long hash_key;
	unsigned long irqsave_flags;

	hash_key = calculate_pid_hash(table, task->pid);

	spin_lock_irqsave(&table->pid_map_lock, irqsave_flags);
	hlist_for_each_entry(descr, &table->pid_map[hash_key], pid_map_node) {
		if (task == descr->task) {
			target_task_descr = descr;
			break;
		}
	}
	spin_unlock_irqrestore(&table->pid_map_lock, irqsave_flags);

	return target_task_descr;
}

struct proca_task_descr *proca_table_remove_by_task(
				struct proca_table *table,
				const struct task_struct *task)
{
	struct proca_task_descr *target_task_descr = NULL;

	target_task_descr = proca_table_get_by_task(table, task);
	proca_table_remove_task_descr(table, target_task_descr);

	return target_task_descr;
}
