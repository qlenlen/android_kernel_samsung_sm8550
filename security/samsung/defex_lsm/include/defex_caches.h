/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
*/

#ifndef __DEFEX_CACHES_H
#define __DEFEX_CACHES_H

#include "defex_config.h"
#include "defex_internal.h"

#define FILE_CACHE_SIZE 0x40

struct defex_file_cache_entry {
	int prev_entry;
	int next_entry;
	int pid;
	struct file *file_addr;
};

struct defex_file_cache_list {
	struct defex_file_cache_entry entry[FILE_CACHE_SIZE];
	int first_entry;
	int last_entry;
};

void defex_file_cache_init(void);
void defex_file_cache_add(int pid, struct file *file_addr);
void defex_file_cache_update(struct file *file_addr);
void defex_file_cache_delete(int pid);
struct file *defex_file_cache_find(int pid);

#endif /* __DEFEX_CACHES_H */
