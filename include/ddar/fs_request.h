/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *
 * Sensitive Data Protection
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef FS_REQUEST_H_
#define FS_REQUEST_H_

#include <linux/slab.h>

#define FSOP_SDP_SET_SENSITIVE 10
#define FSOP_SDP_SET_PROTECTED 11

#define FSOP_DLP_FILE_OPENED   21
#define FSOP_DLP_FILE_CLOSED   22
#define FSOP_DLP_FILE_INIT     23
#define FSOP_DLP_FILE_INIT_RESTRICTED     24
#define FSOP_DLP_FILE_REMOVE     25
#define FSOP_DLP_FILE_RENAME     26
#define FSOP_DLP_FILE_ACCESS_DENIED     27
#define FSOP_DLP_FILE_OPENED_CREATOR    28
#define FSOP_DLP_FILE_REMOVE_MEDIA     29

#define FSOP_AUDIT_FAIL_ENCRYPT		51
#define FSOP_AUDIT_FAIL_DECRYPT		52
#define FSOP_AUDIT_FAIL_ACCESS		53
#define FSOP_AUDIT_FAIL_DE_ACCESS	54

// opcode, ret, inode
typedef void (*fs_request_cb_t)(int, int, unsigned long);

typedef struct sdp_fs_command {
	int req_id;

	int opcode;
	int user_id;
	int part_id;
	unsigned long ino;
	int pid;
	int err;
} sdp_fs_command_t;

extern int sdp_fs_request(sdp_fs_command_t *sdp_req, fs_request_cb_t callback);

static inline sdp_fs_command_t *sdp_fs_command_alloc(int opcode, int pid,
		int userid, int partid, unsigned long ino, int err, gfp_t gfp) {
	sdp_fs_command_t *cmd;

	cmd = kmalloc(sizeof(sdp_fs_command_t), gfp);

	if (cmd == NULL) {
		printk(KERN_ERR "sdp_fs_command_alloc is failed\n");
		return NULL;
	}

	cmd->opcode = opcode;
	cmd->pid = pid;
	cmd->user_id = userid;
	cmd->part_id = partid;
	cmd->ino = ino;
	cmd->err = err;

	return cmd;
}

static inline void sdp_fs_command_free(sdp_fs_command_t *cmd)
{
	kfree_sensitive(cmd);
}

#endif /* FS_REQUEST_H_ */
