/*
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This code is originated from Samsung Electronics proprietary sources.
 * Author: Viacheslav Vovchenko, <v.vovchenko@samsung.com>
 * Created: 10 Jul 2017
 *
 * Copyright (C) 2016 Samsung Electronics, Inc.
 */

#ifndef __FIVE_LV_H__
#define __FIVE_LV_H__

#include <linux/types.h>

/**
 * Length/Value structure
 */
struct lv {
	uint16_t length;
	uint8_t value[];
} __packed;

/**
 * Returns the next element from the chain of LV (length/value) data.
 * Returns NULL in a case of memory limits violation
 */
struct lv *lv_get_next(struct lv *field, const void *end);

/**
 * Sets value of LV data and checks memory bounds.
 * Returns 0 on success, otherwise - error.
 */
int lv_set(struct lv *field, const void *data, uint16_t data_len,
	   const void *end);

#endif /* __FIVE_LV_H__ */
