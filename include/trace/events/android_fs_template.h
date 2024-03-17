#if !defined(_TRACE_ANDROID_FS_TEMPLATE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ANDROID_FS_TEMPLATE_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(android_fs_data_start_template,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes,
		 pid_t pid, char *pathname, char *command),
	TP_ARGS(inode, offset, bytes, pid, pathname, command),
	TP_STRUCT__entry(
		__string(pathbuf, pathname)
		__field(loff_t,	offset)
		__field(int,	bytes)
		__field(loff_t,	i_size)
		__string(cmdline, command)
		__field(pid_t,	pid)
		__field(ino_t,	ino)
	),
	TP_fast_assign(
		{
			/*
			 * Replace the spaces in filenames and cmdlines
			 * because this screws up the tooling that parses
			 * the traces.
			 */
			__assign_str(pathbuf, pathname);
			(void)strreplace(__get_str(pathbuf), ' ', '_');
			__entry->offset		= offset;
			__entry->bytes		= bytes;
			__entry->i_size		= i_size_read(inode);
			__assign_str(cmdline, command);
			(void)strreplace(__get_str(cmdline), ' ', '_');
			__entry->pid		= pid;
			__entry->ino		= inode->i_ino;
		}
	),
	TP_printk("entry_name %s, offset %llu, bytes %d, cmdline %s,"
		  " pid %d, i_size %llu, ino %lu",
		  __get_str(pathbuf), __entry->offset, __entry->bytes,
		  __get_str(cmdline), __entry->pid, __entry->i_size,
		  (unsigned long) __entry->ino)
);



#ifdef CONFIG_F2FS_ML_BASED_STREAM_SEPARATION
DECLARE_EVENT_CLASS(android_fs_data_wb_template,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes,
		pid_t pid, char *pathname, char *command, unsigned long long time,
		int is_cache, int is_file, int is_fuse, unsigned long long write_chunk,
		long long *arr),
	TP_ARGS(inode, offset, bytes, pid, pathname, command, time, is_cache,
		is_file, is_fuse, write_chunk, arr),
	TP_STRUCT__entry(
		__string(pathbuf, pathname)
		__field(loff_t,	offset)
		__field(int,	bytes)
		__field(loff_t,	i_size)
		__string(cmdline, command)
		__field(pid_t,	pid)
		__field(ino_t,	ino)
		__field(unsigned long long, time)
		__field(int,	is_cache)
		__field(int,	is_file)
		__field(int,	is_fuse)
		__field(unsigned long long,	write_chunk)
		__field(int,	mtime_cnt)
		__field(int,	overwrite_cnt)
		__field(unsigned long long, mtime)
		__field(unsigned long long, current_time)
		__field(int,	append_cnt)
	),
	TP_fast_assign(
		{
			/*
			 * Replace the spaces in filenames and cmdlines
			 * because this screws up the tooling that parses
			 * the traces.
			 */
			__assign_str(pathbuf, pathname);
			(void)strreplace(__get_str(pathbuf), ' ', '_');
			__entry->offset		= offset;
			__entry->bytes		= bytes;
			__entry->i_size		= i_size_read(inode);
			__assign_str(cmdline, command);
			(void)strreplace(__get_str(cmdline), ' ', '_');
			__entry->pid		= pid;
			__entry->ino		= inode->i_ino;
			__entry->time       = arr[2];
			__entry->is_cache	= is_cache;
			__entry->is_file	= is_file;
			__entry->is_fuse	= is_fuse;
			__entry->write_chunk = write_chunk;
			__entry->mtime_cnt	= arr[3];
			__entry->overwrite_cnt = arr[7];
			__entry->mtime		= arr[2];
			__entry->current_time = time;
			__entry->append_cnt	= arr[8];
		}
	),
	TP_printk("entry_name %s, offset %llu, bytes %d, cmdline %s, pid %d,"
		"i_size %llu, ino %lu, time %llu, mtime %llu, current_time %llu,"
		"mtime_cnt %d, is_cache %d, is_file %d, is_fuse %d, write_chunk %lld,"
		"overwrite_cnt %d, append_cnt %d",
		__get_str(pathbuf), __entry->offset, __entry->bytes,
		__get_str(cmdline), __entry->pid, __entry->i_size,
		(unsigned long) __entry->ino, __entry->time, __entry->mtime,
		__entry->current_time, __entry->mtime_cnt, __entry->is_cache,
		__entry->is_file, __entry->is_fuse,
		__entry->write_chunk, __entry->overwrite_cnt, __entry->append_cnt
	)
);

DECLARE_EVENT_CLASS(android_fs_separation_template,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes, pid_t pid,
		char *pathname, char *command, long long *arr, long long calculate_cold),
	TP_ARGS(inode, offset, bytes, pid, pathname, command, arr,
		calculate_cold),
	TP_STRUCT__entry(
		__string(pathbuf, pathname)
		__field(loff_t,	offset)
		__field(int,	bytes)
		__field(loff_t,	i_size)
		__string(cmdline, command)
		__field(pid_t,	pid)
		__field(ino_t,	ino)
		__field(unsigned long long, time)
		__field(int,	is_cache)
		__field(int,	is_fuse)
		__field(unsigned long long, write_chunk)
		__field(int,	mtime_cnt)
		__field(int,	overwrite_cnt)
		__field(unsigned long long, mtime)
		__field(unsigned long long, current_time)
		__field(int,	append_cnt)
		__field(long long,	overwrite_ratio)
		__field(long long,	append_ratio)
		__field(long long,	calculate_cold)
	),
	TP_fast_assign(
		{
			/*
			 * Replace the spaces in filenames and cmdlines
			 * because this screws up the tooling that parses
			 * the traces.
			 */
			__assign_str(pathbuf, pathname);
			(void)strreplace(__get_str(pathbuf), ' ', '_');
			__entry->offset		= offset;
			__entry->bytes		= arr[0];
			__entry->i_size		= arr[1];
			__assign_str(cmdline, command);
			(void)strreplace(__get_str(cmdline), ' ', '_');
			__entry->pid		= pid;
			__entry->ino		= inode->i_ino;
			__entry->time       = arr[2];
			__entry->is_cache	= arr[4];
			__entry->is_fuse	= arr[5];
			__entry->write_chunk = arr[6];
			__entry->mtime_cnt	= arr[3];
			__entry->overwrite_cnt = arr[7];
			__entry->mtime		= arr[2];
			__entry->current_time = 0;
			__entry->append_cnt	= arr[8];
			__entry->calculate_cold = calculate_cold;
			__entry->overwrite_ratio = arr[9];
			__entry->append_ratio = arr[10];
		}
	),
	TP_printk("entry_name %s, offset %llu, bytes %d, cmdline %s, pid %d, "
		"i_size %llu, ino %lu, time %llu, mtime %llu, current_time %llu, "
		"mtime_cnt %d, is_cache %d, is_fuse %d, write_chunk %lld, "
		"overwrite_cnt %d, append_cnt %d, overwrite_ratio %d, append_ratio %d, "
		"calculate_cold %lld",
		__get_str(pathbuf), __entry->offset, __entry->bytes, __get_str(cmdline),
		__entry->pid, __entry->i_size, (unsigned long) __entry->ino,
		__entry->time, __entry->mtime, __entry->current_time, __entry->mtime_cnt,
		__entry->is_cache,  __entry->is_fuse, __entry->write_chunk,
		__entry->overwrite_cnt, __entry->append_cnt, __entry->overwrite_ratio,
		__entry->append_ratio, __entry->calculate_cold
	)

);
#endif
DECLARE_EVENT_CLASS(android_fs_data_end_template,
	TP_PROTO(struct inode *inode, loff_t offset, int bytes),
	TP_ARGS(inode, offset, bytes),
	TP_STRUCT__entry(
		__field(ino_t,	ino)
		__field(loff_t,	offset)
		__field(int,	bytes)
	),
	TP_fast_assign(
		{
			__entry->ino		= inode->i_ino;
			__entry->offset		= offset;
			__entry->bytes		= bytes;
		}
	),
	TP_printk("ino %lu, offset %llu, bytes %d",
		  (unsigned long) __entry->ino,
		  __entry->offset, __entry->bytes)
);

#endif /* _TRACE_ANDROID_FS_TEMPLATE_H */
