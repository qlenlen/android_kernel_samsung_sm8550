/*
 *  linux/fs/proc/proc_avc.c
 *
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/syslog.h>
#include <linux/export.h>

#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/slab.h>

#ifdef CONFIG_PROC_AVC
#include <linux/proc_avc.h>
#endif

#define LOG_MAGIC 0x4d474f4c	/* "LOGM" */

static unsigned int *sec_avc_log_ptr;
static char *sec_avc_log_buf;
static unsigned int sec_avc_log_size;

int __init sec_avc_log_init(void)
{
	unsigned int size = SZ_256K;
	unsigned int *sec_avc_log_mag;

	sec_avc_log_size = size;
	sec_avc_log_mag = kzalloc(sec_avc_log_size, GFP_NOWAIT);
	pr_info("allocating %u bytes at %p (%llx physical) for avc log\n",
		sec_avc_log_size, sec_avc_log_mag, __pa(sec_avc_log_buf));

	sec_avc_log_ptr = sec_avc_log_mag + 4;
	sec_avc_log_buf = (char *)(sec_avc_log_mag + 8);

	
	if (*sec_avc_log_mag != LOG_MAGIC) {
		pr_info("%s: no old log found\n", __func__);
		*sec_avc_log_ptr = 0;
		*sec_avc_log_mag = LOG_MAGIC;
	}

	return 1;
}

#define BUF_SIZE 512
void sec_avc_log(char *fmt, ...)
{
	va_list args;
	char buf[BUF_SIZE];
	int len = 0;
	unsigned int idx;
	unsigned int size;

	/* In case of sec_avc_log_setup is failed */
	if (!sec_avc_log_size)
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	idx = *sec_avc_log_ptr;
	size = strlen(buf);

	if (idx + (size * 2) > sec_avc_log_size - 1) {
		len = scnprintf(&sec_avc_log_buf[0], size + 1, "%s\n", buf);
		*sec_avc_log_ptr = len;
	} else {
		len = scnprintf(&sec_avc_log_buf[idx], size + 1, "%s\n", buf);
		*sec_avc_log_ptr += len;
	}
}

static ssize_t sec_avc_log_write(struct file *file,
					     const char __user *buf,
					     size_t count, loff_t *ppos)
{
	char *page = NULL;
	ssize_t ret;
	int new_value;

	if (!sec_avc_log_buf)
		return 0;

	ret = -ENOMEM;
	if (count >= PAGE_SIZE)
		return ret;

	ret = -ENOMEM;
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return ret;

	ret = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

	ret = -EINVAL;
	if (sscanf(page, "%u", &new_value) != 1) {
		pr_info("%s\n", page);
		/* print avc_log to sec_avc_log_buf */
		sec_avc_log("%s", page);
	}
	ret = count;
out:
	free_page((unsigned long)page);
	return ret;
}
static ssize_t sec_avc_log_read(struct file *file, char __user *buf,
				size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;

	if (pos >= (*sec_avc_log_ptr & (sec_avc_log_size - 1)))
		return 0;

	count = min(len,
		(size_t)((*sec_avc_log_ptr & (sec_avc_log_size - 1)) - pos));
	if (copy_to_user(buf, sec_avc_log_buf + pos, count))
		return -EFAULT;

	*offset += count;
	return count;
}

static const struct proc_ops avc_msg_file_ops = {
	//.owner = THIS_MODULE,
	.proc_read = sec_avc_log_read,
	.proc_write = sec_avc_log_write,
	.proc_lseek = generic_file_llseek,
};

/*
static const struct proc_ops alignment_proc_ops = {
	.proc_open	= alignment_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= alignment_proc_write,
};
*/
static int __init sec_avc_log_late_init(void)
{
	struct proc_dir_entry *entry;
	
	if (sec_avc_log_buf == NULL) {
		pr_err("%s: sec_avc_log_buf not initialized.\n", __func__);
		return 0;
	}

	entry = proc_create_data("avc_msg", S_IFREG | 0x444, NULL, &avc_msg_file_ops, NULL);
	if (!entry) {
		pr_err("%s: failed to create proc entry\n", __func__);
		return 0;
	}

	proc_set_size(entry, sec_avc_log_size);
	
	return 0;
}

late_initcall(sec_avc_log_late_init);

int __init sec_log_init(void)
{
#ifdef CONFIG_PROC_AVC
	sec_avc_log_init();
#endif
	return 0;
}
fs_initcall(sec_log_init);
