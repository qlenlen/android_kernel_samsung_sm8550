/*
 * FIVE crypto API
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

#ifndef __LINUX_FIVE_CRYPTO_H
#define __LINUX_FIVE_CRYPTO_H

#include <linux/file.h>

int five_init_crypto(void);
int five_calc_file_hash(struct file *file, u8 hash_algo, u8 *hash,
		size_t *hash_len);

int five_calc_data_hash(const uint8_t *data, size_t data_len,
			uint8_t hash_algo, uint8_t *hash, size_t *hash_len);

#endif // __LINUX_FIVE_CRYPTO_H
