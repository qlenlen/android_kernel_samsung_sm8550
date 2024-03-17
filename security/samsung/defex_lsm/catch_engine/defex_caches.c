/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
*/

#include <linux/file.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/spinlock.h>
#include "include/defex_caches.h"

__visible_for_testing struct defex_file_cache_list file_cache;

DEFINE_SPINLOCK(defex_caches_lock);

void defex_file_cache_init(void)
{
	int i;
	struct defex_file_cache_entry *current_entry;
	unsigned long flags;

	spin_lock_irqsave(&defex_caches_lock, flags);
	for (i = 0; i < FILE_CACHE_SIZE; i++) {
		current_entry = &file_cache.entry[i];
		current_entry->next_entry = i + 1;
		current_entry->prev_entry = i - 1;
		current_entry->pid = -1;
		current_entry->file_addr = NULL;
	}

	file_cache.first_entry = 0;
	file_cache.last_entry = FILE_CACHE_SIZE - 1;

	file_cache.entry[file_cache.first_entry].prev_entry = file_cache.last_entry;
	file_cache.entry[file_cache.last_entry].next_entry = file_cache.first_entry;
	spin_unlock_irqrestore(&defex_caches_lock, flags);
}

void defex_file_cache_add(int pid, struct file *file_addr)
{
	struct defex_file_cache_entry *current_entry;
	struct file *old_file_addr;
	unsigned long flags;

	spin_lock_irqsave(&defex_caches_lock, flags);

	current_entry = &file_cache.entry[file_cache.last_entry];

	current_entry->pid = pid;

	old_file_addr = current_entry->file_addr;

	current_entry->file_addr = file_addr;
	current_entry->next_entry = file_cache.first_entry;

	file_cache.first_entry = file_cache.last_entry;
	file_cache.last_entry = current_entry->prev_entry;

	spin_unlock_irqrestore(&defex_caches_lock, flags);
	if (old_file_addr) {
		fput(old_file_addr);
	}
}

void defex_file_cache_update(struct file *file_addr)
{
	struct defex_file_cache_entry *current_entry;
	struct file *old_file_addr;
	unsigned long flags;

	spin_lock_irqsave(&defex_caches_lock, flags);
	current_entry = &file_cache.entry[file_cache.first_entry];
	old_file_addr = current_entry->file_addr;
	current_entry->file_addr = file_addr;
	spin_unlock_irqrestore(&defex_caches_lock, flags);
	if (old_file_addr)
		fput(old_file_addr);
}

void defex_file_cache_delete(int pid)
{
	int current_index, cache_found = 0;
	struct defex_file_cache_entry *current_entry;
	struct file *old_file_addr = NULL;
	unsigned long flags;

	spin_lock_irqsave(&defex_caches_lock, flags);

	current_index = file_cache.first_entry;
	do {
		current_entry = &file_cache.entry[current_index];
		if (current_entry->pid == pid) {

			if (current_index == file_cache.first_entry) {
				file_cache.first_entry = current_entry->next_entry;
				file_cache.last_entry = current_index;
				cache_found = 1;
				break;
			}
			if (current_index == file_cache.last_entry) {
				cache_found = 1;
				break;
			}
			file_cache.entry[current_entry->prev_entry].next_entry = current_entry->next_entry;
			file_cache.entry[current_entry->next_entry].prev_entry = current_entry->prev_entry;
			file_cache.entry[file_cache.first_entry].prev_entry = current_index;
			file_cache.entry[file_cache.last_entry].next_entry = current_index;

			current_entry->next_entry = file_cache.first_entry;
			current_entry->prev_entry = file_cache.last_entry;

			file_cache.last_entry = current_index;

			cache_found = 1;
			break;
		}
		current_index = current_entry->next_entry;
	} while (current_index != file_cache.first_entry);

	if (cache_found) {
		old_file_addr = current_entry->file_addr;
		current_entry->pid = -1;
		current_entry->file_addr = NULL;
	}

	spin_unlock_irqrestore(&defex_caches_lock, flags);
	if (old_file_addr)
		fput(old_file_addr);
	return;
}

struct file *defex_file_cache_find(int pid)
{
	int current_index, cache_found = 0;
	struct defex_file_cache_entry *current_entry;
	unsigned long flags;

	spin_lock_irqsave(&defex_caches_lock, flags);

	current_index = file_cache.first_entry;
	do {
		current_entry = &file_cache.entry[current_index];
		if (current_entry->pid == pid) {
			if (current_index == file_cache.first_entry) {
				cache_found = 1;
				break;
			}
			if (current_index == file_cache.last_entry) {
				current_entry->next_entry = file_cache.first_entry;
				file_cache.first_entry = file_cache.last_entry;
				file_cache.last_entry = current_entry->prev_entry;
				cache_found = 1;
				break;
			}
			file_cache.entry[current_entry->prev_entry].next_entry = current_entry->next_entry;
			file_cache.entry[current_entry->next_entry].prev_entry = current_entry->prev_entry;
			file_cache.entry[file_cache.first_entry].prev_entry = current_index;
			file_cache.entry[file_cache.last_entry].next_entry = current_index;

			current_entry->next_entry = file_cache.first_entry;
			current_entry->prev_entry = file_cache.last_entry;

			file_cache.first_entry = current_index;

			cache_found = 1;
			break;
		}
		current_index = current_entry->next_entry;
	} while (current_index != file_cache.first_entry);

	spin_unlock_irqrestore(&defex_caches_lock, flags);

	return (!cache_found)?NULL:current_entry->file_addr;
}
