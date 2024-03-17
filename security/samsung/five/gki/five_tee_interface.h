/*
 * Interface for TEE Driver
 *
 * Copyright (C) 2016 Samsung Electronics, Inc.
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

#ifndef INTEGRITY_TEE_DRIVER_H
#define INTEGRITY_TEE_DRIVER_H

#include <linux/types.h>
#include <crypto/hash_info.h>

struct tee_iovec {
	enum hash_algo algo;

	const void *hash;
	size_t hash_len;

	const void *label;
	size_t label_len;

	void *signature;
	size_t signature_len;

	int rc;
};

struct five_tee_driver_fns {
	int (*verify_hmac)(const struct tee_iovec *verify_args);
	int (*sign_hmac)(struct tee_iovec *sign_args);
};

int register_five_tee_driver(
		struct five_tee_driver_fns *tee_driver_fns);
void unregister_five_tee_driver(void);

#endif
