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

#include <linux/module.h>
#include "five_lv.h"

struct lv *lv_get_next(struct lv *field, const void *end)
{
	size_t lv_len;
	uint8_t *pbegin = (uint8_t *)field;
	const uint8_t *pend = (const uint8_t *)end;

	if (unlikely(!pbegin || !pend || pbegin >= pend))
		return NULL;

	/* Check if we can read 'length' field */
	if (unlikely(pend - pbegin < sizeof(field->length)))
		return NULL;

	lv_len = sizeof(field->length) + field->length;
	/* Check if we can read the value */
	if (unlikely(pend - pbegin < lv_len))
		return NULL;

	return (struct lv *)(pbegin + lv_len);
}

int lv_set(struct lv *field, const void *data, uint16_t data_len,
	   const void *end)
{
	size_t lv_len;
	uint8_t *pbegin = (uint8_t *)field;
	const uint8_t *pend = (const uint8_t *)end;

	if (unlikely(!pbegin || !pend))
		return -EINVAL;

	lv_len = sizeof(field->length) + data_len;

	if (unlikely(pbegin >= pend || (pend - pbegin < lv_len) ||
			(data_len > 0 && !data)))
		return -EINVAL;

	field->length = data_len;

	if (data)
		memcpy(field->value, data, data_len);

	return 0;
}
