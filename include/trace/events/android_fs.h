#undef TRACE_SYSTEM
#define TRACE_SYSTEM android_fs

#if !defined(_TRACE_ANDROID_FS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ANDROID_FS_H

#include <linux/fs.h>
#include <linux/tracepoint.h>
#include <trace/events/android_fs_template.h>

DEFINE_EVENT(android_fs_data_start_template, android_fs_dataread_start,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes,
		 pid_t pid, char *pathname, char *command),
	TP_ARGS(inode, offset, bytes, pid, pathname, command));

DEFINE_EVENT(android_fs_data_end_template, android_fs_dataread_end,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes),
	TP_ARGS(inode, offset, bytes));

DEFINE_EVENT(android_fs_data_start_template, android_fs_datawrite_start,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes,
		 pid_t pid, char *pathname, char *command),
	TP_ARGS(inode, offset, bytes, pid, pathname, command));

DEFINE_EVENT(android_fs_data_end_template, android_fs_datawrite_end,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes),
	     TP_ARGS(inode, offset, bytes));

#ifdef CONFIG_F2FS_ML_BASED_STREAM_SEPARATION
DEFINE_EVENT(android_fs_separation_template,
			android_fs_separation_start,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes,
		pid_t pid, char *pathname, char *command, long long *arr,
		long long calculate_cold),
	TP_ARGS(inode, offset, bytes, pid, pathname, command, arr,
		calculate_cold));


DEFINE_EVENT(android_fs_data_wb_template, android_fs_datawrite_start_wb,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes,
		 pid_t pid, char *pathname, char *command, unsigned long long time,
		 int is_cache, int is_file, int is_fuse,
		 unsigned long long write_chunk, long long *arr),
	TP_ARGS(inode, offset, bytes, pid, pathname, command, time, is_cache,
	is_file, is_fuse, write_chunk, arr));
#endif
#endif /* _TRACE_ANDROID_FS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

#ifndef ANDROID_FSTRACE_GET_PATHNAME
#define ANDROID_FSTRACE_GET_PATHNAME

/* Sizes an on-stack array, so careful if sizing this up ! */
#define MAX_TRACE_PATHBUF_LEN	256

static inline char *
android_fstrace_get_pathname(char *buf, int buflen, struct inode *inode)
{
	char *path;
	struct dentry *d;

	/*
	 * d_obtain_alias() will either iput() if it locates an existing
	 * dentry or transfer the reference to the new dentry created.
	 * So get an extra reference here.
	 */
	ihold(inode);
	d = d_obtain_alias(inode);
	if (likely(!IS_ERR(d))) {
		path = dentry_path_raw(d, buf, buflen);
		if (unlikely(IS_ERR(path))) {
			strcpy(buf, "ERROR");
			path = buf;
		}
		dput(d);
	} else {
		strcpy(buf, "ERROR");
		path = buf;
	}
	return path;
}
#endif
