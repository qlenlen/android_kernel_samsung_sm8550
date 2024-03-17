/*
 * PROCA identity
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 * Ivan Vorobiov, <i.vorobiov@samsung.com>
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

#ifndef _LINUX_PROCA_IDENTITY_H
#define _LINUX_PROCA_IDENTITY_H

#include <linux/file.h>

#include "proca_certificate.h"

struct proca_identity {
	void *certificate;
	size_t certificate_size;
	struct proca_certificate parsed_cert;
	struct file *file;
};

int init_proca_identity(struct proca_identity *identity,
			struct file *file,
			char *xattr_value,
			const size_t xattr_size,
			struct proca_certificate *parsed_cert);

void deinit_proca_identity(struct proca_identity *identity);

int proca_identity_copy(struct proca_identity *dst, struct proca_identity *src);

#endif /* _LINUX_PROCA_IDENTITY_H */
