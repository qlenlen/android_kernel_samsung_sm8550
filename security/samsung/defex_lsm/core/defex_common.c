/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */


#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "include/defex_caches.h"
#include "include/defex_catch_list.h"
#include "include/defex_config.h"
#include "include/defex_internal.h"
#include "include/defex_rules.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include "../security/integrity/integrity.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)

inline ssize_t __vfs_read(struct file *file, char __user *buf,
				 size_t count, loff_t *pos)
{
	ssize_t ret;

	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->aio_read)
		ret = do_sync_read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		ret = new_sync_read(file, buf, count, pos);
	else
		ret = -EINVAL;

	return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
#define	GET_KERNEL_DS KERNEL_DS
#else
#define	GET_KERNEL_DS get_ds()
#endif

struct file *local_fopen(const char *fname, int flags, umode_t mode)
{
	struct file *f;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	mm_segment_t old_fs;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	old_fs = get_fs();
	set_fs(GET_KERNEL_DS);
#endif
	f = filp_open(fname, flags, mode);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	set_fs(old_fs);
#endif
	return f;
}

int local_fread(struct file *f, loff_t offset, void *ptr, unsigned long bytes)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	mm_segment_t old_fs;
	char __user *buf = (char __user *)ptr;
#endif
	ssize_t ret;

	if (!(f->f_mode & FMODE_READ))
		return -EBADF;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	old_fs = get_fs();
	set_fs(GET_KERNEL_DS);
	ret = vfs_read(f, buf, bytes, &offset);
	set_fs(old_fs);
#else
	ret = (ssize_t)integrity_kernel_read(f, offset, ptr, bytes);
#endif

	return (int)ret;
}

const char unknown_file[] = "<unknown filename>";

__visible_for_testing bool check_slab_ptr(void *ptr)
{
	struct page *page;

	if (IS_ERR_OR_NULL(ptr) || ptr < (void *)PAGE_SIZE || !virt_addr_valid(ptr))
		return false;
	page = virt_to_head_page(ptr);
	return PageSlab(page);
}

int init_defex_context(struct defex_context *dc, int syscall, struct task_struct *p, struct file *f)
{
	memset(dc, 0, offsetof(struct defex_context, cred));
	if (check_slab_ptr(f)) {
		get_file(f);
		dc->target_file = f;
	}
	dc->syscall_no = syscall;
	dc->task = p;
	if (p == current)
		dc->cred = (struct cred *)current_cred();
	if (!dc->cred)
		return 0;
	return 1;
}

void release_defex_context(struct defex_context *dc)
{
	kfree(dc->process_name_buff);
	kfree(dc->target_name_buff);
	if (dc->target_file)
		fput(dc->target_file);
#ifndef DEFEX_CACHES_ENABLE
	if (dc->process_file)
		fput(dc->process_file);
#endif /* DEFEX_CACHES_ENABLE */
}

struct file *get_dc_process_file(struct defex_context *dc)
{
	if (!dc->process_file)
		dc->process_file = defex_get_source_file(dc->task);
	return dc->process_file;
}

const struct path *get_dc_process_dpath(struct defex_context *dc)
{
	const struct path *dpath;
	struct file *exe_file = NULL;

	if (dc->process_dpath)
		return dc->process_dpath;

	exe_file = get_dc_process_file(dc);
	if (!IS_ERR_OR_NULL(exe_file)) {
		dpath = &exe_file->f_path;
		if (dpath->dentry && dpath->dentry->d_inode) {
			dc->process_dpath = dpath;
			return dpath;
		}
	}
	return NULL;
}

char *get_dc_process_name(struct defex_context *dc)
{
	const struct path *dpath;
	char *path = NULL;

	if (!dc->process_name) {
		dpath = get_dc_process_dpath(dc);
		if (dpath) {
			dc->process_name_buff = kmalloc(PATH_MAX, GFP_KERNEL);
			if (dc->process_name_buff)
				path = d_path(dpath, dc->process_name_buff, PATH_MAX);
		}
		dc->process_name = (IS_ERR_OR_NULL(path)) ? (char *)unknown_file : path;
	}
	return dc->process_name;
}

const struct path *get_dc_target_dpath(struct defex_context *dc)
{
	const struct path *dpath;

	if (dc->target_dpath)
		return dc->target_dpath;

	if (dc->target_file) {
		dpath = &(dc->target_file->f_path);
		if (dpath->dentry && dpath->dentry->d_inode) {
			dc->target_dpath = dpath;
			return dpath;
		}
	}
	return NULL;
}

char *get_dc_target_name(struct defex_context *dc)
{
	const struct path *dpath;
	char *path = NULL;

	if (!dc->target_name) {
		dpath = get_dc_target_dpath(dc);
		if (dpath) {
			dc->target_name_buff = kmalloc(PATH_MAX, GFP_KERNEL);
			if (dc->target_name_buff)
				path = d_path(dpath, dc->target_name_buff, PATH_MAX);
		}
		dc->target_name = (IS_ERR_OR_NULL(path)) ? (char *)unknown_file : path;
	}
	return dc->target_name;
}

struct file *defex_get_source_file(struct task_struct *p)
{
	struct file *file_addr = NULL;
	struct mm_struct *proc_mm;

#ifdef DEFEX_CACHES_ENABLE
	bool self;
	file_addr = defex_file_cache_find(p->pid);

	if (!file_addr) {
		proc_mm = get_task_mm(p);
		if (!proc_mm)
			return NULL;
		file_addr = get_mm_exe_file(proc_mm);
		mmput(proc_mm);
		if (!file_addr)
			return NULL;
		defex_file_cache_add(p->pid, file_addr);
	} else {
		self = (p == current);
		proc_mm = (self)?p->mm:get_task_mm(p);
		if (!proc_mm)
			return NULL;
		if (self)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
			if (!down_read_trylock(&proc_mm->mmap_sem))
				return NULL;
#else
			if (!down_read_trylock(&proc_mm->mmap_lock))
				return NULL;
#endif
		if (file_addr != proc_mm->exe_file) {
			file_addr = proc_mm->exe_file;
			if (!file_addr)
				goto clean_mm;
			get_file(file_addr);
			defex_file_cache_update(file_addr);
		}
clean_mm:
		if (self)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
			up_read(&proc_mm->mmap_sem);
#else
			up_read(&proc_mm->mmap_lock);
#endif
		else
			mmput(proc_mm);
	}
#else

	proc_mm = get_task_mm(p);
	if (!proc_mm)
		return NULL;
	file_addr = get_mm_exe_file(proc_mm);
	mmput(proc_mm);
#endif /* DEFEX_CACHES_ENABLE */
	return file_addr;
}

char *defex_get_filename(struct task_struct *p)
{
	struct file *exe_file = NULL;
	const struct path *dpath = NULL;
	char *path = NULL, *buff = NULL;
	char *filename = NULL;

	exe_file = defex_get_source_file(p);
	if (IS_ERR_OR_NULL(exe_file))
		goto out_filename;

	dpath = &exe_file->f_path;
	if (!dpath->dentry || !dpath->dentry->d_inode) {
		fput(exe_file);
		goto out_filename;
	}
	path_get(dpath);

	buff = kmalloc(PATH_MAX, GFP_KERNEL);
	if (buff)
		path = d_path(dpath, buff, PATH_MAX);
	path_put(dpath);

#ifndef DEFEX_CACHES_ENABLE
	fput(exe_file);
#endif /* DEFEX_CACHES_ENABLE */

out_filename:
	if (path && !IS_ERR(path))
		filename = kstrdup(path, GFP_KERNEL);

	if (!filename)
		filename = (char *)unknown_file;

	if (buff)
		kfree(buff);
	return filename;
}

/* Resolve the filename to absolute path, follow the links
   name     - input file name
   out_buff - output pointer to the allocated buffer (should be freed)
   Returns:   pointer to resolved filename or NULL
 */
char* defex_resolve_filename(const char *name, char **out_buff)
{
	char *target_file = NULL, *buff = NULL;
	struct path path;

	if (*out_buff)
		buff = *out_buff;
	else
		buff = kmalloc(PATH_MAX, GFP_KERNEL);
	if (buff) {
		if (!kern_path(name, LOOKUP_FOLLOW, &path)) {
			target_file = d_path(&path, buff, PATH_MAX);
			path_put(&path);
		}
		if (IS_ERR_OR_NULL(target_file)) {
			kfree(buff);
			buff = NULL;
			target_file = NULL;
		}
	}
	*out_buff = buff;
	return target_file;
}

int defex_files_identical(const struct file *f1, const struct file *f2)
{
	const struct path *dpath1, *dpath2;
	const struct inode *inode1, *inode2;

	if (f1 && f2) {
		dpath1 = &f1->f_path;
		dpath2 = &f2->f_path;
		if (dpath1->dentry && dpath2->dentry) {
			inode1 = dpath1->dentry->d_inode;
			inode2 = dpath2->dentry->d_inode;
			return (inode1 == inode2);
		}
	}
	return 0;
}
