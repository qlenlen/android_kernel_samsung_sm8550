#include <linux/cpufreq.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/namei.h>


static ssize_t proc_caches_reclaim_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	int ret = -EFAULT;
	struct path path;
	unsigned int lookup_flags = LOOKUP_FOLLOW;

retry:
	ret = user_path_at(AT_FDCWD, buf, lookup_flags, &path);
	if (!ret) {
		ret = invalidate_inode_pages2(d_backing_inode(path.dentry)->i_mapping);
		path_put(&path);
	}
	if (retry_estale(ret, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}

	return ret < 0 ? ret : count;
}

static const struct proc_ops proc_caches_reclaim_ops = {
    .proc_write	= proc_caches_reclaim_write,
};

static int __init proc_caches_reclaim_init(void)
{
	proc_create("proc_caches_reclaim", 0660, NULL, &proc_caches_reclaim_ops);
	return 0;
}
fs_initcall(proc_caches_reclaim_init);
