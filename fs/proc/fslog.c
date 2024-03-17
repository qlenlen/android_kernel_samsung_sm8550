/*
 *  linux/fs/proc/fslog.c
 *
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched/clock.h>
#include <linux/sched/cputime.h>
#include <linux/sched/types.h>

/* For compatibility */
#include <linux/fslog.h>

#define FSLOG_ACTION_CLOSE          	0
#define FSLOG_ACTION_OPEN           	1
#define FSLOG_ACTION_READ		2
#define FSLOG_ACTION_READ_ALL		3
#define FSLOG_ACTION_WRITE    		4
#define FSLOG_ACTION_SIZE_BUFFER   	5

#define S_PREFIX_MAX			32
#define FSLOG_BUF_LINE_MAX		(1024 - S_PREFIX_MAX)

#define FSLOG_BUF_ALIGN			__alignof__(struct fslog_metadata)

#ifdef CONFIG_PROC_FSLOG_LOWMEM
#define FSLOG_BUFLEN_STLOG		(32 * 1024)
#define FSLOG_BUFLEN_RECLAIMER_LOG	(1024 * 1024)
#define FSLOG_BUFLEN_PSI_LOG		(1024 * 1024)
#define FSLOG_BUFLEN_DLOG_EFS		(16 * 1024)
#define FSLOG_BUFLEN_DLOG_RMDIR		(16 * 1024)
#define FSLOG_BUFLEN_DLOG_ETC		(64 * 1024)
#define FSLOG_BUFLEN_DLOG_MM		(128 * 1024)
#else /* device has DRAM of high capacity */
#define FSLOG_BUFLEN_STLOG		(32 * 1024)
#define FSLOG_BUFLEN_RECLAIMER_LOG	(4 * 1024 * 1024)
#define FSLOG_BUFLEN_PSI_LOG		(4 * 1024 * 1024)
#define FSLOG_BUFLEN_DLOG_EFS		(16 * 1024)
#define FSLOG_BUFLEN_DLOG_RMDIR		(16 * 1024)
#define FSLOG_BUFLEN_DLOG_ETC		(192 * 1024)
#define FSLOG_BUFLEN_DLOG_MM		(256 * 1024)
#endif

#define FSLOG_FILE_MODE_VERSION		(S_IRUSR | S_IRGRP | S_IROTH)
#define FSLOG_FILE_MODE_DIR \
	(S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define FSLOG_FILE_MODE_STLOG \
	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define FSLOG_FILE_MODE_RECLAIMER_LOG \
	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
#define FSLOG_FILE_MODE_PSI_LOG \
	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
#define FSLOG_FILE_MODE_DLOG		(S_IRUSR | S_IRGRP)

struct fslog_sequence {
	u64 fslog_seq;
	u32 fslog_idx;
	u64 fslog_first_seq;
	u32 fslog_first_idx;
	u64 fslog_next_seq;
	u32 fslog_next_idx;
	u64 fslog_clear_seq;
	u32 fslog_clear_idx;
	u64 fslog_end_seq;
};

struct fslog_metadata {
	u64 ts_nsec;
	u16 len;
	u16 text_len;
	pid_t pid;
	pid_t tgid;
	char comm[TASK_COMM_LEN];
	char tgid_comm[TASK_COMM_LEN];
};

struct fslog_data {
	struct fslog_sequence fslog_seq;
	struct fslog_metadata fslog_meta;
	spinlock_t fslog_spinlock;
	wait_queue_head_t fslog_wait_queue;
	u32 fslog_buf_len;
	char *fslog_cbuf;
	bool need_detail;
};

static struct proc_dir_entry *fslog_dir;

static int do_fslog(int type, struct fslog_data *fl_data, char __user *buf, int count);
static int do_fslog_write(struct fslog_data *fl_data, const char __user *buf, int len);
static int vfslog(struct fslog_data *fl_data, const char *fmt, va_list args);

#define DEFINE_FSLOG_VARIABLE(_name, size) \
static char fslog_cbuf_##_name[size]; \
\
static struct fslog_data fslog_data_##_name = { \
	.fslog_seq = { \
		.fslog_seq = 0, \
		.fslog_idx = 0, \
		.fslog_first_seq = 0, \
		.fslog_first_idx = 0, \
		.fslog_next_seq = 0, \
		.fslog_next_idx = 0, \
		.fslog_clear_seq = 0, \
		.fslog_clear_idx = 0, \
		.fslog_end_seq = -1 \
	}, \
	.fslog_meta = { \
		.ts_nsec = 0, \
		.len = 0, \
		.text_len = 0, \
		.pid = 0, \
		.tgid = 0, \
		.comm = {0, }, \
		.tgid_comm = {0, } \
	}, \
	.fslog_spinlock = __SPIN_LOCK_INITIALIZER(fslog_data_##_name.fslog_spinlock), \
	.fslog_wait_queue = __WAIT_QUEUE_HEAD_INITIALIZER(fslog_data_##_name.fslog_wait_queue), \
	.fslog_buf_len = size, \
	.fslog_cbuf = fslog_cbuf_##_name, \
}

#define DEFINE_FSLOG_VARIABLE_DYNAMIC(_name, size) \
static char *fslog_cbuf_##_name; \
\
static struct fslog_data fslog_data_##_name = { \
	.fslog_seq = { \
		.fslog_seq = 0, \
		.fslog_idx = 0, \
		.fslog_first_seq = 0, \
		.fslog_first_idx = 0, \
		.fslog_next_seq = 0, \
		.fslog_next_idx = 0, \
		.fslog_clear_seq = 0, \
		.fslog_clear_idx = 0, \
		.fslog_end_seq = -1 \
	}, \
	.fslog_meta = { \
		.ts_nsec = 0, \
		.len = 0, \
		.text_len = 0, \
		.pid = 0, \
		.tgid = 0, \
		.comm = {0, }, \
		.tgid_comm = {0, } \
	}, \
	.fslog_spinlock = __SPIN_LOCK_INITIALIZER(fslog_data_##_name.fslog_spinlock), \
	.fslog_wait_queue = __WAIT_QUEUE_HEAD_INITIALIZER(fslog_data_##_name.fslog_wait_queue), \
	.fslog_buf_len = size, \
}

#define ALLOC_FSLOG_VARIABLE_DYNAMIC(_name, size) \
fslog_cbuf_##_name = vmalloc(size); \
fslog_data_##_name.fslog_cbuf = fslog_cbuf_##_name

#define SET_FSLOG_VARIABLE_NEED_DETAILED(_name) \
fslog_data_##_name.need_detail = true

static int fslog_release(struct inode *inode, struct file *file)
{
	struct fslog_data *fl_data = (struct fslog_data *)(file->private_data);
	return do_fslog(FSLOG_ACTION_CLOSE, fl_data, NULL, 0);
}

static ssize_t fslog_read(struct file *file, char __user *buf,
		                         size_t count, loff_t *ppos)
{
	struct fslog_data *fl_data = (struct fslog_data *)(file->private_data);
	return do_fslog(FSLOG_ACTION_READ_ALL, fl_data, buf, count);
}

static ssize_t fslog_write(struct file *file, const char __user *buf,
		                         size_t count, loff_t *ppos)
{
	struct fslog_data *fl_data = (struct fslog_data *)(file->private_data);
	return do_fslog(FSLOG_ACTION_WRITE, fl_data, (char __user *)buf, count);
}

loff_t fslog_llseek(struct file *file, loff_t offset, int whence)
{
	struct fslog_data *fl_data = (struct fslog_data *)(file->private_data);
	return (loff_t)do_fslog(FSLOG_ACTION_SIZE_BUFFER, fl_data, 0, 0);
}

#define DEFINE_FSLOG_OPERATION(_name) \
static int fslog_open_##_name(struct inode *inode, struct file *file) \
{ \
	file->f_flags |= O_NONBLOCK; \
	file->private_data = &fslog_data_##_name; \
	return do_fslog(FSLOG_ACTION_OPEN, &fslog_data_##_name, NULL, 0); \
} \
\
static const struct proc_ops fslog_##_name##_operations = { \
	.proc_read           = fslog_read, \
	.proc_write          = fslog_write, \
	.proc_open           = fslog_open_##_name, \
	.proc_release        = fslog_release, \
	.proc_lseek         = fslog_llseek, \
};

DEFINE_FSLOG_VARIABLE(dlog_mm, FSLOG_BUFLEN_DLOG_MM);
DEFINE_FSLOG_VARIABLE(dlog_efs, FSLOG_BUFLEN_DLOG_EFS);
DEFINE_FSLOG_VARIABLE(dlog_etc, FSLOG_BUFLEN_DLOG_ETC);
DEFINE_FSLOG_VARIABLE(dlog_rmdir, FSLOG_BUFLEN_DLOG_RMDIR);
DEFINE_FSLOG_VARIABLE(stlog, FSLOG_BUFLEN_STLOG);

DEFINE_FSLOG_OPERATION(dlog_mm);
DEFINE_FSLOG_OPERATION(dlog_efs);
DEFINE_FSLOG_OPERATION(dlog_etc);
DEFINE_FSLOG_OPERATION(dlog_rmdir);
DEFINE_FSLOG_OPERATION(stlog);

static const char FSLOG_VERSION_STR[] = "1.1.0\n";

static int fslog_version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", FSLOG_VERSION_STR);
	return 0;
}

static int fslog_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, fslog_version_show, NULL);
}

static const struct proc_ops fslog_ver_operations = {
	.proc_open           = fslog_version_open,
	.proc_read           = seq_read,
	.proc_lseek         = seq_lseek,
	.proc_release        = single_release,
};

#define DEFINE_FSLOG_CREATE(_name, log_name, file_mode) \
static void fslog_create_##_name(struct proc_dir_entry *fslog_dir) \
{ \
	proc_create(#log_name, file_mode, \
			fslog_dir, &fslog_##_name##_operations); \
}

DEFINE_FSLOG_CREATE(dlog_mm, dlog_mm, FSLOG_FILE_MODE_DLOG);
DEFINE_FSLOG_CREATE(dlog_efs, dlog_efs, FSLOG_FILE_MODE_DLOG);
DEFINE_FSLOG_CREATE(dlog_etc, dlog_etc, FSLOG_FILE_MODE_DLOG);
DEFINE_FSLOG_CREATE(dlog_rmdir, dlog_rmdir, FSLOG_FILE_MODE_DLOG);
DEFINE_FSLOG_CREATE(stlog, stlog, FSLOG_FILE_MODE_STLOG);

#ifdef CONFIG_PROC_RECLAIMER_LOG
DEFINE_FSLOG_VARIABLE_DYNAMIC(reclaimer_log, FSLOG_BUFLEN_RECLAIMER_LOG);
DEFINE_FSLOG_OPERATION(reclaimer_log);
DEFINE_FSLOG_CREATE(reclaimer_log, reclaimer_log, FSLOG_FILE_MODE_RECLAIMER_LOG);
static void __init reclaimer_log_init(void)
{
	ALLOC_FSLOG_VARIABLE_DYNAMIC(reclaimer_log, FSLOG_BUFLEN_RECLAIMER_LOG);
	SET_FSLOG_VARIABLE_NEED_DETAILED(reclaimer_log);
	fslog_create_reclaimer_log(fslog_dir);
	proc_symlink("reclaimer_log", NULL, "/proc/fslog/reclaimer_log");
}
#else
static void __init reclaimer_log_init(void)
{
}
#endif

#ifdef CONFIG_PROC_PSI_LOG
DEFINE_FSLOG_VARIABLE_DYNAMIC(psi_log, FSLOG_BUFLEN_PSI_LOG);
DEFINE_FSLOG_OPERATION(psi_log);
DEFINE_FSLOG_CREATE(psi_log, psi_log, FSLOG_FILE_MODE_PSI_LOG);
static void __init psi_log_init(void)
{
	ALLOC_FSLOG_VARIABLE_DYNAMIC(psi_log, FSLOG_BUFLEN_PSI_LOG);
	fslog_create_psi_log(fslog_dir);
	proc_symlink("psi_log", NULL, "/proc/fslog/psi_log");
}
#else
static void __init psi_log_init(void)
{
}
#endif

static int __init fslog_init(void)
{
	fslog_dir = proc_mkdir_mode("fslog", FSLOG_FILE_MODE_DIR, NULL);

	proc_create("version", FSLOG_FILE_MODE_VERSION, fslog_dir, &fslog_ver_operations);

	fslog_create_dlog_mm(fslog_dir);
	fslog_create_dlog_efs(fslog_dir);
	fslog_create_dlog_etc(fslog_dir);
	fslog_create_dlog_rmdir(fslog_dir);
	fslog_create_stlog(fslog_dir);

	/* To ensure sub-compatibility in versions below O OS */
	proc_symlink("stlog", NULL, "/proc/fslog/stlog");
	proc_symlink("stlog_version", NULL, "/proc/fslog/version");

	reclaimer_log_init();
	psi_log_init();

	return 0;
}
module_init(fslog_init);

/* human readable text of the record */
static char *fslog_text(const struct fslog_metadata *msg)
{
	return (char *)msg + sizeof(struct fslog_metadata);
}

static struct fslog_metadata *fslog_buf_from_idx(char *fslog_cbuf, u32 idx)
{
	struct fslog_metadata *msg = (struct fslog_metadata *)(fslog_cbuf + idx);

	if (!msg->len)
		return (struct fslog_metadata *)fslog_cbuf;
	return msg;
}

static u32 fslog_next(char *fslog_cbuf, u32 idx)
{
	struct fslog_metadata *msg = (struct fslog_metadata *)(fslog_cbuf + idx);

	if (!msg->len) {
		msg = (struct fslog_metadata *)fslog_cbuf;
		return msg->len;
	}
	return idx + msg->len;
}

static inline void fslog_find_task_by_vpid(struct fslog_metadata *msg,
						struct task_struct *owner)
{
	struct task_struct *p;

	rcu_read_lock();
	p = find_task_by_vpid(owner->tgid);
	if (p) {
		msg->tgid = owner->tgid;
		memcpy(msg->tgid_comm, p->comm, TASK_COMM_LEN);
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	msg->tgid = 0;
	msg->tgid_comm[0] = 0;
}

static void fslog_buf_store(const char *text, u16 text_len,
					struct fslog_data *fl_data,
					struct task_struct *owner)
{
	struct fslog_metadata *msg;
	struct fslog_sequence *fslog_seq = &(fl_data->fslog_seq);
	wait_queue_head_t *fslog_wait_queue = &(fl_data->fslog_wait_queue);
	char *fslog_cbuf = fl_data->fslog_cbuf;
	u32 size, pad_len, fslog_buf_len = fl_data->fslog_buf_len;

	/* number of '\0' padding bytes to next message */
	size = sizeof(struct fslog_metadata) + text_len;
	pad_len = (-size) & (FSLOG_BUF_ALIGN - 1);
	size += pad_len;

	while (fslog_seq->fslog_first_seq < fslog_seq->fslog_next_seq) {
		u32 free;

		if (fslog_seq->fslog_next_idx > fslog_seq->fslog_first_idx)
			free = max(fslog_buf_len - fslog_seq->fslog_next_idx,
							fslog_seq->fslog_first_idx);
		else
			free = fslog_seq->fslog_first_idx - fslog_seq->fslog_next_idx;

		if (free > size + sizeof(struct fslog_metadata))
			break;

		/* drop old messages until we have enough space */
		fslog_seq->fslog_first_idx = fslog_next(fslog_cbuf, fslog_seq->fslog_first_idx);
		fslog_seq->fslog_first_seq++;
	}

	if (fslog_seq->fslog_next_idx + size + sizeof(struct fslog_metadata) >= fslog_buf_len) {
		memset(fslog_cbuf + fslog_seq->fslog_next_idx, 0, sizeof(struct fslog_metadata));
		fslog_seq->fslog_next_idx = 0;
	}

	/* fill message */
	msg = (struct fslog_metadata *)(fslog_cbuf + fslog_seq->fslog_next_idx);
	memcpy(fslog_text(msg), text, text_len);
	msg->text_len = text_len;
	msg->pid = owner->pid;
	memcpy(msg->comm, owner->comm, TASK_COMM_LEN);
	fslog_find_task_by_vpid(msg, owner);
	msg->ts_nsec = local_clock();
	msg->len = sizeof(struct fslog_metadata) + text_len + pad_len;

	/* insert message */
	fslog_seq->fslog_next_idx += msg->len;
	fslog_seq->fslog_next_seq++;
	wake_up_interruptible(fslog_wait_queue);

}

static size_t fslog_print_time(u64 ts, char *buf)
{
	unsigned long rem_nsec;

	rem_nsec = do_div(ts, 1000000000);

	if (!buf)
		return snprintf(NULL, 0, "[%5lu.000000] ", (unsigned long)ts);

	return sprintf(buf, "[%5lu.%06lu] ",
			(unsigned long)ts, rem_nsec / 1000);
}

static size_t fslog_print_pid(const struct fslog_metadata *msg, char *buf)
{
	if (!buf) {
		if (msg->pid == msg->tgid)
			return snprintf(NULL, 0, "[%15s, %5d] ",
					msg->comm, msg->pid);

		return snprintf(NULL, 0, "[%s(%d)|%s(%d)] ",
				msg->comm, msg->pid, msg->tgid_comm, msg->tgid);

	}

	if (msg->pid == msg->tgid)
		return sprintf(buf, "[%15s, %5d] ", msg->comm, msg->pid);

	return sprintf(buf, "[%s(%d)|%s(%d)] ",
			msg->comm, msg->pid, msg->tgid_comm, msg->tgid);
}

static size_t fslog_print_prefix(const struct fslog_metadata *msg, char *buf)
{
	size_t len = 0;

	len += fslog_print_time(msg->ts_nsec, buf ? buf + len : NULL);
	len += fslog_print_pid(msg, buf ? buf + len : NULL);
	return len;
}

static size_t fslog_print_text(const struct fslog_metadata *msg, char *buf, size_t size)
{
	const char *text = fslog_text(msg);
	size_t text_size = msg->text_len;
	bool prefix = true;
	bool newline = true;
	size_t len = 0;

	do {
		const char *next = memchr(text, '\n', text_size);
		size_t text_len;

		if (next) {
			text_len = next - text;
			next++;
			text_size -= next - text;
		} else {
			text_len = text_size;
		}

		if (buf) {
			if (fslog_print_prefix(msg, NULL) + text_len + 1 >= size - len)
				break;

			if (prefix)
				len += fslog_print_prefix(msg, buf + len);
			memcpy(buf + len, text, text_len);
			len += text_len;
			if (next || newline)
				buf[len++] = '\n';
		} else {
			/*  buffer size only calculation */
			if (prefix)
				len += fslog_print_prefix(msg, NULL);
			len += text_len;
			if (next || newline)
				len++;
		}

		prefix = true;
		text = next;
	} while (text);

	return len;
}

static int fslog_print_all(struct fslog_data *fl_data, char __user *buf, int size)
{
	char *text;
	int len = 0;
	struct fslog_sequence *fslog_seq = &(fl_data->fslog_seq);
	spinlock_t *fslog_spinlock = &(fl_data->fslog_spinlock);
	char *fslog_cbuf = fl_data->fslog_cbuf;
	u64 seq = fslog_seq->fslog_next_seq;
	u32 idx = fslog_seq->fslog_next_idx;

	text = kmalloc(FSLOG_BUF_LINE_MAX + S_PREFIX_MAX, GFP_KERNEL);
	if (!text)
		return -ENOMEM;
	spin_lock_irq(fslog_spinlock);

	if (fslog_seq->fslog_end_seq == -1)
		fslog_seq->fslog_end_seq = fslog_seq->fslog_next_seq;

	if (buf) {

		if (fslog_seq->fslog_clear_seq < fslog_seq->fslog_first_seq) {
			/* messages are gone, move to first available one */
			fslog_seq->fslog_clear_seq = fslog_seq->fslog_first_seq;
			fslog_seq->fslog_clear_idx = fslog_seq->fslog_first_idx;
		}

		seq = fslog_seq->fslog_clear_seq;
		idx = fslog_seq->fslog_clear_idx;

		while (seq < fslog_seq->fslog_end_seq) {
			struct fslog_metadata *msg =
					fslog_buf_from_idx(fslog_cbuf, idx);
			int textlen;

			textlen = fslog_print_text(msg, text,
						 FSLOG_BUF_LINE_MAX + S_PREFIX_MAX);
			if (textlen < 0) {
				len = textlen;
				break;
			} else if(len + textlen > size) {
				break;
			}
			idx = fslog_next(fslog_cbuf, idx);
			seq++;

			spin_unlock_irq(fslog_spinlock);
			if (copy_to_user(buf + len, text, textlen))
				len = -EFAULT;
			else
				len += textlen;
			spin_lock_irq(fslog_spinlock);

			if (seq < fslog_seq->fslog_first_seq) {
				/* messages are gone, move to next one */
				seq = fslog_seq->fslog_first_seq;
				idx = fslog_seq->fslog_first_idx;
			}
		}
	}

	fslog_seq->fslog_clear_seq = seq;
	fslog_seq->fslog_clear_idx = idx;

	spin_unlock_irq(fslog_spinlock);

	kfree(text);
	return len;
}

static int do_fslog(int type, struct fslog_data *fl_data, char __user *buf, int len)
{
	int error = 0;
	u32 fslog_buf_len = fl_data->fslog_buf_len;
	struct fslog_sequence *fslog_seq = &(fl_data->fslog_seq);

	switch (type) {
	case FSLOG_ACTION_CLOSE:	/* Close log */
		break;
	case FSLOG_ACTION_OPEN:	/* Open log */
		break;
	case FSLOG_ACTION_READ_ALL: /* cat /proc/fslog */ /* dumpstate */
		error = -EINVAL;
		if (!buf || len < 0)
			goto out;
		error = 0;
		if (!len)
			goto out;
		if (!access_ok(buf, len)) {
			error = -EFAULT;
			goto out;
		}

		error = fslog_print_all(fl_data, buf, len);
		if (error == 0) {
			fslog_seq->fslog_clear_seq = fslog_seq->fslog_first_seq;
			fslog_seq->fslog_clear_idx = fslog_seq->fslog_first_idx;
			fslog_seq->fslog_end_seq = -1;
		}

		break;
	/* Size of the log buffer */
	case FSLOG_ACTION_WRITE:
		error = do_fslog_write(fl_data, (const char __user *)buf, len);
		break;
	case FSLOG_ACTION_SIZE_BUFFER:
		error = fslog_buf_len;
		break;
	default:
		error = -EINVAL;
		break;
	}
out:
	return error;
}

static int fslog(struct fslog_data *fl_data, const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vfslog(fl_data, fmt, args);

	va_end(args);

	return r;
}

static int do_fslog_write(struct fslog_data *fl_data, const char __user *buf, int len)
{
	int error = 0;
	char *kern_buf = 0;
	char *line = 0;

	if (!buf || len < 0)
		goto out;
	if (!len)
		goto out;
	if (len > FSLOG_BUF_LINE_MAX)
		return -EINVAL;

	kern_buf = kmalloc(len+1, GFP_KERNEL);
	if (kern_buf == NULL)
		return -ENOMEM;

	line = kern_buf;
	if (copy_from_user(line, buf, len)) {
		error = -EFAULT;
		goto out;
	}

	line[len] = '\0';
	error = fslog(fl_data, "%s", line);
	if ((line[len-1] == '\n') && (error == (len-1)))
		error++;
out:
	kfree(kern_buf);
	return error;

}

static int vfslog(struct fslog_data *fl_data, const char *fmt, va_list args)
{
	static char textbuf[FSLOG_BUF_LINE_MAX];
	char *text = textbuf;
	size_t text_len = 0;
	unsigned long flags;
	int printed_len = 0;
	bool stored = false;
	spinlock_t *fslog_spinlock = &(fl_data->fslog_spinlock);
	unsigned long long exec_runtime;

	if (unlikely(!fl_data->fslog_cbuf))
		return 0;

	local_irq_save(flags);

	spin_lock(fslog_spinlock);

	if (fl_data->need_detail) {
		exec_runtime = task_sched_runtime(current);
		text_len = sprintf(text, "[%llu"
#ifdef CONFIG_TASK_HAS_ALLOC_FREE_STAT
				" %llu"
				" %llu"
#endif
				"] "
				,exec_runtime / 1000
#ifdef CONFIG_TASK_HAS_ALLOC_FREE_STAT
				,current->alloc_sum
				,current->free_sum
#endif
				);
	}

	text_len += vscnprintf(&text[text_len], sizeof(textbuf) - text_len, fmt, args);

	/* mark and strip a trailing newline */
	if (text_len && text[text_len-1] == '\n')
		text_len--;

	if (!stored)
		fslog_buf_store(text, text_len, fl_data, current);

	printed_len += text_len;

	spin_unlock(fslog_spinlock);
	local_irq_restore(flags);

	return printed_len;
}

/*
 * fslog - print a deleted entry message
 * @fmt: format string
 */
#define DEFINE_FSLOG_FUNC(_name)\
int fslog_##_name(const char *fmt, ...)\
{\
	va_list args;\
	int r;\
\
	va_start(args, fmt);\
	r = vfslog(&fslog_data_##_name, fmt, args); \
\
	va_end(args);\
\
	return r;\
}

DEFINE_FSLOG_FUNC(dlog_mm);
DEFINE_FSLOG_FUNC(dlog_efs);
DEFINE_FSLOG_FUNC(dlog_etc);
DEFINE_FSLOG_FUNC(dlog_rmdir);
DEFINE_FSLOG_FUNC(stlog);
#ifdef CONFIG_PROC_RECLAIMER_LOG
DEFINE_FSLOG_FUNC(reclaimer_log);
#endif
#ifdef CONFIG_PROC_PSI_LOG
DEFINE_FSLOG_FUNC(psi_log);
#endif
