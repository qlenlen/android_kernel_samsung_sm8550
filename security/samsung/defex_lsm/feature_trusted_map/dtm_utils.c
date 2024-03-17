/*
 * Copyright (c) 2020-2022 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#endif

#include "include/dtm.h"
#include "include/dtm_log.h"
#include "include/dtm_utils.h"

const char * const DTM_UNKNOWN = "<unknown>";

static inline int dtm_get_file_attr(struct path *path, struct kstat *stat)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	return vfs_getattr(path, stat, STATX_BASIC_STATS, 0);
#else
	return vfs_getattr(path, stat);
#endif
}

/*
 * Gets mode bit value for a file status.
 */
int dtm_get_stat_mode_bit(struct kstat *stat)
{
	int mode, mode_bit;

	if (!stat)
		return DTM_FD_MODE_ERROR;

	mode = (stat->mode) & S_IFMT;
	switch (mode) {
	case S_IFBLK:
		mode_bit = DTM_FD_MODE_BLK;
		break;
	case S_IFCHR:
		mode_bit = DTM_FD_MODE_CHR;
		break;
	case S_IFDIR:
		mode_bit = DTM_FD_MODE_DIR;
		break;
	case S_IFIFO:
		mode_bit = DTM_FD_MODE_FIFO;
		break;
	case S_IFLNK:
		mode_bit = DTM_FD_MODE_LNK;
		break;
	case S_IFREG:
		mode_bit = DTM_FD_MODE_REG;
		break;
	case S_IFSOCK:
		mode_bit = DTM_FD_MODE_SOCK;
		break;
	default:
		mode_bit = DTM_FD_MODE_UNKNOWN;
		DTM_LOG_ERROR("Unknown stat mode %d", mode);
	}
	return mode_bit;
}

/*
 * Gets mode bit value for a file descriptor.
 */
int dtm_get_fd_mode_bit(int fd)
{
	struct kstat stat;
	struct fd sf;
	int error;

	if (fd < 0)
		return DTM_FD_MODE_ERROR;

	sf = fdget_raw(fd);
	if (unlikely(!sf.file))
		return DTM_FD_MODE_CLOSED;

	error = dtm_get_file_attr(&sf.file->f_path, &stat);
	fdput(sf);
	if (unlikely(error < 0))
		return DTM_FD_MODE_ERROR;

	return dtm_get_stat_mode_bit(&stat);
}

/*
 * Gets printable name for a fd mode bit value.
 */
const char *dtm_get_fd_mode_bit_name(int mode_bit)
{
	switch (mode_bit) {
	case DTM_FD_MODE_NONE:
		return "NONE";
	case DTM_FD_MODE_BLK:
		return "BLK";
	case DTM_FD_MODE_CHR:
		return "CHR";
	case DTM_FD_MODE_DIR:
		return "DIR";
	case DTM_FD_MODE_FIFO:
		return "FIFO";
	case DTM_FD_MODE_LNK:
		return "LNK";
	case DTM_FD_MODE_REG:
		return "REG";
	case DTM_FD_MODE_SOCK:
		return "SOCK";
	case DTM_FD_MODE_CLOSED:
		return "CLOSED";
	case DTM_FD_MODE_ERROR:
		return "ERROR";
	case DTM_FD_MODE_UNKNOWN:
		return "UNKNOWN";
	}
	DTM_LOG_ERROR("Unexpected mode bit %d", mode_bit);
	return "INVALID";
}
