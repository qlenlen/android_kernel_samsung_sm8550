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

#include <linux/module.h>
#include <linux/slab.h>
#include <crypto/hash_info.h>
#include "five_tee_interface.h"
#include "five_tee_api.h"

static struct five_tee_driver_fns *g_tee_driver_fn;
static char is_registered;
static DECLARE_RWSEM(usage_lock);

int register_five_tee_driver(
			struct five_tee_driver_fns *tee_driver_fns)
{
	int rc = 0;

	if (!tee_driver_fns)
		return -EINVAL;

	down_write(&usage_lock);
	if (is_registered) {
		rc = -EACCES;
		goto exit;
	}

	g_tee_driver_fn = kmalloc(sizeof(*g_tee_driver_fn), GFP_KERNEL);
	if (!g_tee_driver_fn) {
		rc = -ENOMEM;
		goto exit;
	}

	g_tee_driver_fn->verify_hmac = tee_driver_fns->verify_hmac;
	g_tee_driver_fn->sign_hmac = tee_driver_fns->sign_hmac;
	is_registered = 1;

exit:
	up_write(&usage_lock);

	return rc;
}
EXPORT_SYMBOL_GPL(register_five_tee_driver);

void unregister_five_tee_driver(void)
{
	down_write(&usage_lock);
	if (is_registered) {
		kfree(g_tee_driver_fn);
		g_tee_driver_fn = NULL;
		is_registered = 0;
	}
	up_write(&usage_lock);
}
EXPORT_SYMBOL_GPL(unregister_five_tee_driver);

int verify_hash(enum hash_algo algo, const void *hash, size_t hash_len,
		const void *label, size_t label_len,
		const void *signature, size_t signature_len)
{
	int rc = -ENODEV;
	struct tee_iovec args = {
		.algo = algo,
		.hash = hash,
		.hash_len = hash_len,
		.label = label,
		.label_len = label_len,
		.signature = (void *)signature,
		.signature_len = signature_len
	};

	down_read(&usage_lock);
	if (is_registered)
		rc = g_tee_driver_fn->verify_hmac(&args);
	up_read(&usage_lock);

	return rc;
}

int sign_hash(enum hash_algo algo, const void *hash, size_t hash_len,
		const void *label, size_t label_len,
		void *signature, size_t *signature_len)
{
	int rc = -ENODEV;
	struct tee_iovec args = {
		.algo = algo,
		.hash = hash,
		.hash_len = hash_len,
		.label = label,
		.label_len = label_len,
		.signature = signature,
		.signature_len = *signature_len
	};

	down_read(&usage_lock);
	if (is_registered)
		rc = g_tee_driver_fn->sign_hmac(&args);
	up_read(&usage_lock);

	*signature_len = args.signature_len;

	return rc;
}
