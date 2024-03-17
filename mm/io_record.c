#include <linux/export.h>
#include <linux/compiler.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hardirq.h> /* for BUG_ON(!in_atomic()) only */
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/cleancache.h>
#include <linux/rmap.h>
#include <linux/module.h>
#include <linux/io_record.h>
#include "internal.h"

struct io_info {
	struct file *file;
	struct inode *inode;
	int offset;
	int nr_pages;
};

#define NUM_IO_INFO_IN_BUF (64 * 1024) /* # of struct io_info */
#define RESULT_BUF_SIZE_IN_BYTES (512 * 1024) /* 512 KB */
#define RESULT_BUF_END_MAGIC (~0) /* -1 */

struct io_info *record_buf; /* array of struct io_info */
void *result_buf; /* buffer used for post processing result */

/*
 * format in result buf per file:
 * <A = length of "path", (size = sizeof(int))>
 * <"path" string, (size = A)>
 * <tuple array, (size = B * sizeof(int) * 2>
 * <end MAGIC, (val = -1, size = sizeof(int) * 2>
 */
#define MAX_FILEPATH_LEN 256

/* return bytes written to the path. if buffer full, return < 0 */
void *result_buf_cursor; /* this is touched by post processing only */
void write_to_result_buf(void *src, int size)
{
	memcpy(result_buf_cursor, src, size);
	result_buf_cursor = result_buf_cursor + size;
}

/* this assumes that start_idx~end_idx belong to the same inode */
int fill_result_buf(int start_idx, int end_idx)
{
	int ret = 0;
	int i;
	int size_expected;
	char strbuf[MAX_FILEPATH_LEN];
	char *path;
	int pathsize;
	int result_buf_used;
	int prev_offset = -1;
	int max_size = 0;
	void *buf_start;
	struct file *file;

	if (start_idx >= end_idx)
		BUG_ON(1); /* this case is not in consideration */

	file = record_buf[start_idx].file;
	path = d_path(&file->f_path, strbuf, MAX_FILEPATH_LEN);
	if (!path || IS_ERR(path))
		goto out;

	/* max size check (not strict) */
	result_buf_used = result_buf_cursor - result_buf;
	size_expected = sizeof(int) * 2 +                         /* end magic of this attempt */
			sizeof(int) + strlen(path) +              /* for path string */
			sizeof(int) * 2 * (end_idx - start_idx) + /* data */
			sizeof(int);                              /* end magic of post-processing */
	if (size_expected > (RESULT_BUF_SIZE_IN_BYTES - result_buf_used))
		return -EINVAL;

	buf_start = result_buf_cursor;
	pathsize = strlen(path);
	write_to_result_buf(&pathsize, sizeof(int));
	write_to_result_buf(path, pathsize);

	/* fill the result buf using the record buf */
	for (i = start_idx; i < end_idx; i++) {
		if (prev_offset == -1) {
			prev_offset = record_buf[i].offset;
			max_size = record_buf[i].nr_pages;
			continue;
		}
		/* in the last range */
		if ((prev_offset + max_size) >=
		    (record_buf[i].offset + record_buf[i].nr_pages)) {
			continue;
		} else {
			if ((prev_offset + max_size) >= record_buf[i].offset) {
				max_size = (record_buf[i].offset +
					   record_buf[i].nr_pages) -
					   prev_offset;
			} else {
				write_to_result_buf(&prev_offset,
						    sizeof(int));
				write_to_result_buf(&max_size,
						    sizeof(int));
				prev_offset = record_buf[i].offset;
				max_size = record_buf[i].nr_pages;
			}
		}
	}
	/* fill the record buf */
	write_to_result_buf(&prev_offset, sizeof(int));
	write_to_result_buf(&max_size, sizeof(int));

	/* fill the record buf with final magic */
	prev_offset = RESULT_BUF_END_MAGIC;
	max_size = RESULT_BUF_END_MAGIC;
	write_to_result_buf(&prev_offset, sizeof(int));
	write_to_result_buf(&max_size, sizeof(int));

	/* return # of bytes written to result buf */
	ret = result_buf_cursor - buf_start;
out:
	return ret;
}

/* idx record_buf_cursor of the array (record_buf) */
static atomic_t record_buf_cursor = ATOMIC_INIT(-1);

static DEFINE_RWLOCK(record_rwlock);
int record_target; /* pid # of group leader */
bool record_enable;

static DEFINE_MUTEX(status_lock);
enum  io_record_cmd_types current_status = IO_RECORD_INIT;

static inline void set_record_status(bool enable)
{
	write_lock(&record_rwlock);
	record_enable = enable;
	write_unlock(&record_rwlock);
}

/* assume caller has read lock of record_rwlock */
static inline bool __get_record_status(void)
{
	return record_enable;
}

static inline void set_record_target(int pid)
{
	write_lock(&record_rwlock);
	record_target = pid;
	write_unlock(&record_rwlock);
}

void release_records(void);

/* change the current status, and do the init jobs for the status */
static void change_current_status(enum io_record_cmd_types status)
{
	switch (status) {
	case IO_RECORD_INIT:
		set_record_status(false);
		set_record_target(-1);
		release_records();
		atomic_set(&record_buf_cursor, 0);
		result_buf_cursor = result_buf;
		break;
	case IO_RECORD_START:
		set_record_status(true);
		break;
	case IO_RECORD_STOP:
		set_record_status(false);
		break;
	case IO_RECORD_POST_PROCESSING:
		break;
	case IO_RECORD_POST_PROCESSING_DONE:
		break;
	}
	current_status = status;
}

/* Only this function contains the status change rules */
/* Assume that the caller has the status lock */
static inline bool change_status_if_valid(enum io_record_cmd_types next_status)
{
	bool ret = false;

	if (!record_buf)
		return false;

	if (next_status == IO_RECORD_INIT &&
	    current_status != IO_RECORD_POST_PROCESSING)
		ret = true;
	else if (next_status == (current_status + 1))
		ret = true;
	if (ret)
		change_current_status(next_status);

	return ret;
}

/*
 * control :
 *  - record start
 *  - record end
 *  - data read
 * hook :
 *  - syscall, or pagecache add or ...
 *  - filemap fault
 * buffer : (to store records between record start and record end)
 * post-processing : merge, etc.
 * output : return post processing result to userspace...
 */

/* return 0 on success */
bool start_record(int pid)
{
	bool ret = false;

	mutex_lock(&status_lock);
	if (!change_status_if_valid(IO_RECORD_START))
		goto out;

	set_record_target(pid);

	ret = true;
out:
	mutex_unlock(&status_lock);
	return ret;
}

bool stop_record(void)
{
	bool ret = false;

	mutex_lock(&status_lock);
	if (!change_status_if_valid(IO_RECORD_STOP))
		goto out;

	ret = true;
out:
	mutex_unlock(&status_lock);
	return ret;
}

#include <linux/sort.h>

static void io_info_swap(void *lhs, void *rhs, int size)
{
	struct io_info tmp;
	struct io_info *linfo = (struct io_info *)lhs;
	struct io_info *rinfo = (struct io_info *)rhs;

	memcpy(&tmp, linfo, sizeof(struct io_info));
	memcpy(linfo, rinfo, sizeof(struct io_info));
	memcpy(rinfo, &tmp, sizeof(struct io_info));
}

static int io_info_compare(const void *lhs, const void *rhs)
{
	struct io_info *linfo = (struct io_info *)lhs;
	struct io_info *rinfo = (struct io_info *)rhs;

	if ((unsigned long)linfo->inode > (unsigned long)rinfo->inode) {
		return 1;
	} else if ((unsigned long)linfo->inode < (unsigned long)rinfo->inode) {
		return -1;
	} else {
		if ((unsigned long)linfo->offset > (unsigned long)rinfo->offset)
			return 1;
		else if ((unsigned long)linfo->offset <
			 (unsigned long)rinfo->offset)
			return -1;
		else
			return 0;
	}
}

bool post_processing_records(void)
{
	bool ret = false;
	int i;
	struct inode *prev_inode = NULL;
	int start_idx = -1, end_idx = -1;
	int last_magic = RESULT_BUF_END_MAGIC;

	mutex_lock(&status_lock);
	if (!change_status_if_valid(IO_RECORD_POST_PROCESSING))
		goto out;

	/* From this point, we assume that no one touches record buf */
	/* sort based on inode pointer address */
	sort(record_buf, atomic_read(&record_buf_cursor),
	     sizeof(struct io_info), &io_info_compare, &io_info_swap);

	/* fill the result buf per inode */
	for (i = 0; i < atomic_read(&record_buf_cursor); i++) {
		if (prev_inode != record_buf[i].inode) {
			end_idx = i;
			if (prev_inode && (fill_result_buf(start_idx,
							  end_idx) < 0))
				/* if result buf full, break without write */
				break;
			prev_inode = record_buf[i].inode;
			start_idx = i;
		}
	}

	if (start_idx != -1)
		fill_result_buf(start_idx, i);

	/* fill the last magic to indicate end of result */
	write_to_result_buf(&last_magic, sizeof(int));

	if (!change_status_if_valid(IO_RECORD_POST_PROCESSING_DONE))
		BUG_ON(1); /* this is the case not in consideration */

	ret = true;
out:
	mutex_unlock(&status_lock);
	return ret;
}

ssize_t read_record(char __user *buf, size_t count, loff_t *ppos)
{
	int result_buf_size;
	int ret;

	mutex_lock(&status_lock);
	if (current_status != IO_RECORD_POST_PROCESSING_DONE) {
		ret = -EFAULT;
		goto out;
	}

	result_buf_size = result_buf_cursor - result_buf;
	if (*ppos >= result_buf_size) {
		ret = 0;
		goto out;
	}

	ret = (*ppos + count < result_buf_size) ? count :
			 (result_buf_size - *ppos);
	if (copy_to_user(buf, result_buf + *ppos, ret)) {
		ret = -EFAULT;
		goto out;
	}

	*ppos = *ppos + ret;
out:
	mutex_unlock(&status_lock);
	return ret;
}

/*
 * if this is not called explicitly by user processes, kernel should call this
 * at some point.
 */
bool init_record(void)
{
	bool ret = false;

	mutex_lock(&status_lock);
	if (!change_status_if_valid(IO_RECORD_INIT))
		goto out;
	ret = true;
out:
	mutex_unlock(&status_lock);
	return ret;
}

bool forced_init_record(void)
{
	bool ret = false;
	int loopnum = 0;

	if (!record_buf)
		goto out;
retry:
	loopnum++;
	ret = init_record();
	if (!ret)
		goto retry;

	if (loopnum > 1)
		pr_err("%s,%d: loopnum %d\n", __func__, __LINE__, loopnum);
	ret = true;
out:
	return ret;
}

void record_io_info(struct file *file, pgoff_t offset,
		    unsigned long req_size)
{
	struct io_info *info;
	int cnt;

	/* check without lock */
	if ((int)task_tgid_nr(current) != record_target)
		return;

	if (offset >= INT_MAX || req_size >= INT_MAX)
		return;

	cnt = atomic_read(&record_buf_cursor);
	if (cnt < 0 || cnt >= NUM_IO_INFO_IN_BUF || !file || req_size == 0)
		return;

	if (!read_trylock(&record_rwlock))
		return;

	if (!__get_record_status())
		goto out;

	/* strict check */
	if ((int)task_tgid_nr(current) != record_target)
		goto out;

	cnt = atomic_inc_return(&record_buf_cursor) - 1;

	/* buffer is full */
	if (cnt >= NUM_IO_INFO_IN_BUF) {
		atomic_dec(&record_buf_cursor);
		goto out;
	}

	info = record_buf + cnt;

	get_file(file); /* will be put in release_records */
	info->file = file;
	info->inode = file_inode(file);
	info->offset = (int)offset;
	info->nr_pages = (int)req_size;
out:
	read_unlock(&record_rwlock);
}

void release_records(void)
{
	int i;
	struct io_info *info;

	for (i = 0; i < atomic_read(&record_buf_cursor); i++) {
		info = record_buf + i;
		fput(info->file);
	}
}

static int __init io_record_init(void)
{
	record_buf = vzalloc(sizeof(struct io_info) * NUM_IO_INFO_IN_BUF);
	if (!record_buf)
		goto record_buf_fail;

	result_buf = vzalloc(RESULT_BUF_SIZE_IN_BYTES);
	if (!result_buf)
		goto result_buf_fail;

	mutex_lock(&status_lock);
	if (!change_status_if_valid(IO_RECORD_INIT))
		BUG_ON(1); /* should success at boot time */

	mutex_unlock(&status_lock);
	return 0;
result_buf_fail:
	vfree(record_buf);
record_buf_fail:
	return -1;
}

module_init(io_record_init);
