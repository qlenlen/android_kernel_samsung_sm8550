/*
 * This code is based on IMA's code
 *
 * Copyright (C) 2016 Samsung Electronics, Inc.
 *
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
 * Viacheslav Vovchenko <v.vovchenko@samsung.com>
 * Yevgen Kopylov <y.kopylov@samsung.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __LINUX_FIVE_H
#define __LINUX_FIVE_H

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/security.h>
#include <linux/hash.h>
#include <linux/audit.h>
#include <linux/workqueue.h>

#include "five_cert.h"
#include "five_crypto.h"

/* set during initialization */
extern int five_hash_algo;
struct worker_context {
	struct work_struct data_work;
	struct task_integrity *tint;
};

struct f_signature_task {
	struct task_integrity *tint;
	struct file *file;
};

struct f_signature_context {
	struct work_struct data_work;
	struct f_signature_task payload;
};

struct five_stat {
	u64 inode_iversion;
	u64 cache_iversion;
	u32 cache_status;
	u32 is_dm_verity;
};

/* Internal FIVE function definitions */
int five_init(void);

/* FIVE policy related functions */
enum five_hooks {
	FILE_CHECK = 1,
	MMAP_CHECK,
	BPRM_CHECK,
	POST_SETATTR
};

struct file_verification_result {
	struct task_struct *task;
	struct file *file;
	struct integrity_iint_cache *iint;
	enum five_hooks fn;
	int five_result;
	void *xattr;
	size_t xattr_len;
};

static inline void file_verification_result_init(
		struct file_verification_result *result)
{
	memset(result, 0, sizeof(*result));
}

static inline void file_verification_result_deinit(
		struct file_verification_result *result)
{
	kfree(result->xattr);
	memset(result, 0, sizeof(*result));
}

int five_appraise_measurement(struct task_struct *task, int func,
			      struct integrity_iint_cache *iint,
			      struct file *file,
			      struct five_cert *cert);

int five_read_xattr(struct dentry *dentry, char **xattr_value);
int five_check_params(struct task_struct *task, struct file *file);
const char *five_d_path(const struct path *path, char **pathbuf,
			char *namebuf);

int five_digsig_verify(struct five_cert *cert,
			    const char *digest, int digestlen);
int five_reboot_notifier(struct notifier_block *nb,
			       unsigned long action, void *unused);
int __init five_load_built_x509(void);
int __init five_keyring_init(void);
int __init five_task_integrity_cache_init(void);

const char *five_get_string_fn(enum five_hooks fn);
#endif
