/*
 *  Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/hashtable.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/magic.h>
#include "mount.h"

#define DEFINE_DLOG(_name) extern int fslog_##_name(const char *fmt, ...)
DEFINE_DLOG(dlog_mm);
DEFINE_DLOG(dlog_efs);
DEFINE_DLOG(dlog_etc);
DEFINE_DLOG(dlog_rmdir);

#define EXT_SHIFT		7
#define MAX_EXT			(1 << 7)
#define MAX_DEPTH		2
#define MEDIA_MIN_SIZE		(512 * 1024)

struct dlog_keyword {
	struct hlist_node hlist;
	const char *keyword;
};

struct dlog_keyword_hash_tbl {
	DECLARE_HASHTABLE(table, 7);
};

enum {
	DLOG_HT_EXTENSION = 0,
	DLOG_HT_EXCEPTION,
	DLOG_HT_MAX
};

enum {
	DLOG_SUPP_PART_DATA = 0,
	DLOG_SUPP_PART_EFS,
	DLOG_SUPP_PART_FUSE,
	DLOG_SUPP_PART_MAX
};

enum {
	DLOG_MM = 0,
	DLOG_EFS,
	DLOG_ETC,
	DLOG_RMDIR
};

static struct dlog_keyword_hash_tbl ht[DLOG_HT_MAX];

static const char *support_part[] = {
	"data", "efs", "emulated", NULL,
};

static const char *extensions[] = {
	/* image */
	"arw", "bmp", "cr2", "dng", "gif",
	"jpeg", "jpg", "nef", "nrw", "orf",
	"pef", "png", "raf", "rw2", "srw",
	"wbmp", "webp",
	/* audio */
	"3ga", "aac", "amr",
	"awb", "dff", "dsf", "flac", "imy",
	"m4a", "mid", "midi", "mka", "mp3",
	"mpga",	"mxmf", "oga", "ogg", "ota",
	"rtttl", "rtx", "smf", "wav", "wma",
	"xmf", "dcf",
	/* video */
	"3g2", "3gp", "3gpp", "3gpp2",
	"ak3g", "asf", "avi", "divx", "flv",
	"m2t", "m2ts", "m4v", "mkv", "mp4",
	"mpeg",	"mpg", "mts", "skm", "tp",
	"trp", "ts", "webm", "wmv",
	/* document */
	"asc",
	"csv", "doc", "docm", "docx", "dot",
	"dotx",	"htm", "html", "hwdt", "hwp",
	"hwpx",	"hwt", "memo", "pdf", "pot",
	"potx",	"pps", "ppsx", "ppt", "pptm",
	"pptx",	"rtf", "sdoc", "snb", "spd",
	"xls", "xlsm", "xlsx", "xlt", "xltx",
	"xml",
	NULL,
};

static const char *exceptions[] = {
	/* exception extension */
	"db-shm", "shm", "bak", "mbak", "gz",
	"log", "swap", "dcs", "tmp", "temp",
	"txt", NULL,
};

static const char **dlog_keyword_tbl[DLOG_HT_MAX] = {
	extensions, exceptions
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
static inline unsigned int dlog_full_name_hash(const char *name, unsigned int len)
{
	return full_name_hash((void *)0x0, name, len);
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0) */
static inline unsigned int dlog_full_name_hash(const char *name, unsigned int len)
{
	return full_name_hash(name, len);
}
#endif

bool is_ext(const char *name, const char token, struct dlog_keyword_hash_tbl *hash_tbl)
{
	char *ext = strrchr(name, token);
	struct dlog_keyword *hash_cur;
	unsigned hash;
	int i;
	bool ret = false;

	if (!ext || !ext[1])
		return false;

	ext = kstrdup(&ext[1], GFP_KERNEL);
	if (!ext)
		return false;

	for (i = 0; ext[i]; i++)
		ext[i] = tolower(ext[i]);
	hash = dlog_full_name_hash(ext, strlen(ext));

	hash_for_each_possible(hash_tbl->table, hash_cur, hlist, hash) {
		if (!strcmp(ext, hash_cur->keyword)) {
			ret = true;
			break;
		}
	}
	kfree(ext);

	return ret;
}

int __init dlog_keyword_hash_init(void)
{
	int i;
	int tbl_idx = 0;

	do {
		hash_init(ht[tbl_idx].table);
		for (i = 0; dlog_keyword_tbl[tbl_idx][i]; i++) {
			struct dlog_keyword *hte;

			hte = kzalloc(sizeof(struct dlog_keyword), GFP_KERNEL);
			if (!hte)
				return -ENOMEM;

			INIT_HLIST_NODE(&hte->hlist);
			hte->keyword = dlog_keyword_tbl[tbl_idx][i];
			hash_add(ht[tbl_idx].table, &hte->hlist,
					dlog_full_name_hash(hte->keyword, strlen(hte->keyword)));
		}
		tbl_idx++;
	} while(tbl_idx < DLOG_HT_MAX);

	return 0;
}
module_init(dlog_keyword_hash_init);

void __exit dlog_keyword_hash_exit(void)
{
	int i;
	int num_ht = 0;
	struct dlog_keyword *hash_cur;

	do {
		hash_for_each(ht[num_ht].table, i, hash_cur, hlist)
			kfree(hash_cur);
	} while(++num_ht < DLOG_HT_MAX);

}
module_exit(dlog_keyword_hash_exit);

static int get_support_part_id(struct vfsmount *mnt)
{
	int idx = 0;
	struct mount *mount = real_mount(mnt);

	/* check partition which need register delete log */
	do {
		if (!strcmp(mount->mnt_mountpoint->d_name.name, support_part[idx]))
			return idx;
	} while(support_part[++idx]);

	return -1;
}

#ifndef SDFAT_SUPER_MAGIC
#define SDFAT_SUPER_MAGIC       0x5EC5DFA4
#endif
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC	0x65735546
#endif
static int is_sdcard(struct vfsmount *mnt)
{
	/* internal storage (external storage after Andorid 11.x)
	sdcardfs is deleted at this kernel branch
	 */
	if (mnt->mnt_sb->s_magic == FUSE_SUPER_MAGIC)
		return true;
	/* external storage from Android 9.x */
	else if (mnt->mnt_sb->s_magic == SDFAT_SUPER_MAGIC)
		return true;
	else if (mnt->mnt_sb->s_magic == MSDOS_SUPER_MAGIC)
		return true;

	return false;
}

static void make_prefix(int part_id, char *prefix)
{
	if (part_id == DLOG_SUPP_PART_DATA)
		*prefix = 'd';
	else
		*prefix = 's';
}

static void store_log(struct dentry *dentry, struct inode *inode,
		struct path *path, int type, int part_id)
{
	kuid_t euid = current->cred->euid;
	unsigned long ino = inode ? inode->i_ino : 0;
	loff_t isize = inode ? inode->i_size : 0;
	char prefix = 0;
	char *buf, *full_path;
	char unit = 'B';

	buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "%s memory alloc failed : ENOMEM\n", __func__);
		return;
	}

	full_path = dentry_path_raw(dentry, buf, PATH_MAX);
	if (IS_ERR(full_path))
		goto out;

	make_prefix(part_id, &prefix);
	if (isize >> 10) {
		isize >>= 10;
		unit = 'K';
	}

	if (type == DLOG_MM) {
		fslog_dlog_mm("[%c]\"%s\" (%u, %lu, %lu, %lld%c)\n", prefix, full_path,
				euid, path->dentry->d_inode->i_ino, ino, isize, unit);
		goto out;
	}

	if (type == DLOG_ETC) {
		fslog_dlog_etc("[%c]\"%s\" (%u, %lu, %lu, %lld%c)\n", prefix, full_path,
				euid, path->dentry->d_inode->i_ino, ino, isize, unit);
		goto out;
	}

	if (type == DLOG_EFS) {
		fslog_dlog_efs("\"%s\" (%lu, %lu, %lld%c)\n", full_path,
				path->dentry->d_inode->i_ino, ino, isize, unit);
		goto out;
	}

	if (type == DLOG_RMDIR)
		fslog_dlog_rmdir("[%c]\"%s\" (%u, %lu)\n", prefix, full_path,
				euid, path->dentry->d_inode->i_ino);
out:
	kfree(buf);
}

void dlog_hook(struct dentry *dentry, struct inode *inode, struct path *path)
{
	int part_id = get_support_part_id(path->mnt);

	if ((part_id < 0) && !is_sdcard(path->mnt))
		return;

	/* for efs partition */
	if (part_id == DLOG_SUPP_PART_EFS) {
		store_log(dentry, inode, path, DLOG_EFS, part_id);
		goto out;
	}

	/* for data partition`s only multimedia file */
	if (is_ext(dentry->d_name.name, '.', &ht[DLOG_HT_EXTENSION])) {
		if (i_size_read(inode) >= MEDIA_MIN_SIZE)
			store_log(dentry, inode, path, DLOG_MM, part_id);
		goto out;
	}

	/* for data partition except multimedia file */
	if (!is_ext(dentry->d_name.name, '.', &ht[DLOG_HT_EXCEPTION])
		&& !is_ext(dentry->d_name.name, '-', &ht[DLOG_HT_EXCEPTION]))
		store_log(dentry, inode, path, DLOG_ETC, part_id);

out:
	return;
}

static int get_dentry_depth(struct dentry *dentry)
{
	int depth = 0;
	struct dentry *tmp_de = dentry;

	while (!IS_ROOT(tmp_de)) {
		struct dentry *parent = tmp_de->d_parent;

		depth++;
		if (depth > MAX_DEPTH)
			return -1;
		tmp_de = parent;
	}

	return depth;
}

void dlog_hook_rmdir(struct dentry *dentry, struct path *path)
{
	int depth = 0;
	int part_id = get_support_part_id(path->mnt);

	if (part_id != DLOG_SUPP_PART_DATA)
		return;

	depth = get_dentry_depth(dentry);
	if (depth < 0)
		return;

	store_log(dentry, NULL, path, DLOG_RMDIR, part_id);

	return;
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Logging unlink file path");
