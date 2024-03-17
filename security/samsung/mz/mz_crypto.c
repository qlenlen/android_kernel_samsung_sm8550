/*
 * Copyright (c) 2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include "mz_internal.h"
#include "mz_log.h"

struct mz_tee_driver_fns *g_tee_driver_fn;

MzResult mz_wb_encrypt(uint8_t *pt, uint8_t *ct)
{
	MzResult mz_ret = MZ_SUCCESS;
	uint8_t *iv;

	if (!addr_list) {
		MZ_LOG(err_level_error, "%s addr_list null\n", __func__);
		return MZ_CRYPTO_FAIL;
	}

	iv = (uint8_t *)(&(addr_list[1]));

#ifdef MZ_TA
	//Get key from ta
	mz_ret = g_tee_driver_fn->encrypt(pt, ct, iv);
#endif /* MZ_TA */

	if (mz_ret != MZ_SUCCESS)
		MZ_LOG(err_level_error, "%s ta encrypt fail, ta error %d\n", __func__, mz_ret);

	return mz_ret;
}

//Crypto tee driver
static char is_registered;

MzResult register_mz_tee_crypto_driver(struct mz_tee_driver_fns *tee_driver_fns)
{
	MzResult mz_ret = MZ_SUCCESS;
	g_tee_driver_fn = kmalloc(sizeof(*g_tee_driver_fn), GFP_KERNEL);
	if (!g_tee_driver_fn) {
		MZ_LOG(err_level_error, "%s kmalloc fail\n", __func__);
		mz_ret = MZ_DRIVER_FAIL;
		goto exit;
	}

	g_tee_driver_fn->encrypt = tee_driver_fns->encrypt;
	is_registered = 1;

exit:
	return mz_ret;
}

void unregister_mz_tee_crypto_driver(void)
{
	if (is_registered) {
		kfree(g_tee_driver_fn);
		g_tee_driver_fn = NULL;
		is_registered = 0;
	}
}

EXPORT_SYMBOL(register_mz_tee_crypto_driver);
EXPORT_SYMBOL(unregister_mz_tee_crypto_driver);
