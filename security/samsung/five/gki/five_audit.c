/*
 * Audit calls for FIVE audit subsystem.
 *
 * Copyright (C) 2017 Samsung Electronics, Inc.
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
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

#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/audit.h>
#include <linux/task_integrity.h>
#include "five.h"
#include "five_audit.h"
#include "five_cache.h"
#include "five_porting.h"
#include "five_dsms.h"

static void five_audit_msg(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result);

#ifdef CONFIG_FIVE_AUDIT_VERBOSE
void five_audit_verbose(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result)
{
	five_audit_msg(task, file, op, prev, tint, cause, result);
}
#else
void five_audit_verbose(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result)
{
}
#endif

void five_audit_info(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result)
{
	five_audit_msg(task, file, op, prev, tint, cause, result);
}

/**
 * There are two kind of event that can come to the function: error
 * and tampering attempt. 'result' is for identification of error type
 * and it should be non-zero in case of error but is always zero in
 * case of tampering.
 */
void five_audit_err(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result)
{
	five_audit_msg(task, file, op, prev, tint, cause, result);

	if (!result) {
		char comm[TASK_COMM_LEN];
		struct task_struct *tsk = task ? task : current;

		five_dsms_reset_integrity(get_task_comm(comm, tsk), 0, op);
	}
}

void five_audit_sign_err(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result)
{
	char comm[TASK_COMM_LEN];
	struct task_struct *tsk = task ? task : current;

	get_task_comm(comm, tsk);
	five_dsms_sign_err(comm, result);
}

static void five_audit_msg(struct task_struct *task, struct file *file,
		const char *op, enum task_integrity_value prev,
		enum task_integrity_value tint, const char *cause, int result)
{
	struct audit_buffer *ab;
	struct inode *inode = NULL;
	const char *fname = NULL;
	char *pathbuf = NULL;
	char filename[NAME_MAX];
	char comm[TASK_COMM_LEN];
	const char *name = "";
	struct task_struct *tsk = task ? task : current;
	struct integrity_iint_cache *iint = NULL;

	if (file) {
		inode = file_inode(file);
		fname = five_d_path(&file->f_path, &pathbuf, filename);
	}

	ab = audit_log_start(current->audit_context, GFP_KERNEL,
			AUDIT_INTEGRITY_DATA);
	if (unlikely(!ab)) {
		pr_err("Can't get a context of audit logs\n");
		goto exit;
	}

	audit_log_format(ab, " pid=%d", task_pid_nr(tsk));
	audit_log_format(ab, " tgid=%d", task_tgid_nr(tsk));
	audit_log_task_context(ab);
	audit_log_format(ab, " op=");
	audit_log_string(ab, op);
	audit_log_format(ab, " cint=0x%x", tint);
	audit_log_format(ab, " pint=0x%x", prev);
	audit_log_format(ab, " cause=");
	audit_log_string(ab, cause);
	audit_log_format(ab, " comm=");
	audit_log_untrustedstring(ab, get_task_comm(comm, tsk));
	if (fname) {
		audit_log_format(ab, " name=");
		audit_log_untrustedstring(ab, fname);
		name = fname;
	}
	if (inode) {
		audit_log_format(ab, " dev=");
		audit_log_untrustedstring(ab, inode->i_sb->s_id);
		audit_log_format(ab, " ino=%lu", inode->i_ino);
		audit_log_format(ab, " i_version=%llu ",
				inode_query_iversion(inode));
		iint = integrity_inode_get(inode);
		if (iint) {
			audit_log_format(ab, " five_status=%d ",
					five_get_cache_status(iint));
			audit_log_format(ab, " version=%llu ",
					(unsigned long long)iint->version);
		}
	}
	audit_log_format(ab, " res=%d", result);
	audit_log_end(ab);

exit:
	if (pathbuf)
		__putname(pathbuf);
}

void five_audit_tee_msg(const char *func, const char *cause, int rc,
							uint32_t origin)
{
	struct audit_buffer *ab;

	ab = audit_log_start(current->audit_context, GFP_KERNEL,
			AUDIT_INTEGRITY_DATA);
	if (unlikely(!ab)) {
		pr_err("Can't get a context of audit logs\n");
		return;
	}

	audit_log_format(ab, " func=");
	audit_log_string(ab, func);
	audit_log_format(ab, " cause=");
	audit_log_string(ab, cause);
	audit_log_format(ab, " rc=0x%x, ", rc);
	audit_log_format(ab, " origin=0x%x", origin);
	audit_log_end(ab);
}

void five_audit_hexinfo(struct file *file, const char *msg, char *data,
		size_t data_length)
{
	struct audit_buffer *ab;
	struct inode *inode = NULL;
	const unsigned char *fname = NULL;
	char filename[NAME_MAX];
	char *pathbuf = NULL;
	struct integrity_iint_cache *iint = NULL;

	if (file) {
		fname = five_d_path(&file->f_path, &pathbuf, filename);
		inode = file_inode(file);
	}

	ab = audit_log_start(current->audit_context, GFP_KERNEL,
			AUDIT_INTEGRITY_DATA);
	if (unlikely(!ab)) {
		pr_err("Can't get a context of audit logs\n");
		goto exit;
	}

	if (fname) {
		audit_log_format(ab, " name=");
		audit_log_untrustedstring(ab, fname);
	}
	if (inode) {
		audit_log_format(ab, " i_version=%llu ",
				inode_query_iversion(inode));

		iint = integrity_inode_get(inode);
		if (iint) {
			audit_log_format(ab, " cache_value=%lu ",
							iint->five_flags);
			audit_log_format(ab, " five_status=%d ",
					five_get_cache_status(iint));
			audit_log_format(ab, " version=%llu ",
					(unsigned long long)iint->version);
		}
	}

	audit_log_string(ab, msg);
	audit_log_n_hex(ab, data, data_length);
	audit_log_end(ab);
exit:
	if (pathbuf)
		__putname(pathbuf);
}
