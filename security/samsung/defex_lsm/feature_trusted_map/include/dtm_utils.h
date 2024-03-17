/*
 * Copyright (c) 2020-2022 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _INCLUDE_DTM_UTILS_H
#define _INCLUDE_DTM_UTILS_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/string.h>

#include "../../include/defex_internal.h"

enum dtm_stdin_descriptor_allow {
	DTM_FD_MODE_NONE = 0,
	DTM_FD_MODE_BLK = 1,
	DTM_FD_MODE_CHR = 2,
	DTM_FD_MODE_DIR = 4,
	DTM_FD_MODE_FIFO = 8,
	DTM_FD_MODE_LNK = 16,
	DTM_FD_MODE_REG = 32,
	DTM_FD_MODE_SOCK = 64,
	DTM_FD_MODE_CLOSED = 128,
	DTM_FD_MODE_ERROR = 256,
	DTM_FD_MODE_UNKNOWN = 512,
};

extern const char * const DTM_UNKNOWN;

/* Gets mode bit value for a file status */
int dtm_get_stat_mode_bit(struct kstat *stat);

/* Gets mode bit value for a file descriptor */
extern int dtm_get_fd_mode_bit(int fd);

/* Gets printable name for a fd mode bit value */
const char *dtm_get_fd_mode_bit_name(int mode_bit);

#endif /* _INCLUDE_DTM_UTILS_H */
