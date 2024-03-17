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
#include <linux/slab.h>
#include "five_crypto.h"
#include "five_cert.h"

int five_cert_body_alloc(struct five_cert_header *header,
			 uint8_t *hash, size_t hash_len,
			 uint8_t *label, size_t label_len,
			 uint8_t **raw_cert, size_t *raw_cert_len)
{
	size_t data_len;
	uint8_t *data;
	struct lv *next;
	const void *end;
	int rc = 0;
	struct five_cert_body body_cert = {0};

	if (unlikely(!header || !raw_cert || !raw_cert_len))
		return -EINVAL;

	data_len = sizeof(*body_cert.header) + sizeof(*header) +
		sizeof(*body_cert.hash) + hash_len +
		sizeof(*body_cert.label) + label_len;

	if (unlikely(data_len > FIVE_MAX_CERTIFICATE_SIZE))
		return -EINVAL;

	data = kzalloc(data_len, GFP_NOFS);
	if (unlikely(!data))
		return -ENOMEM;

	next = body_cert.header = (struct lv *)data;
	end = data + data_len;

	/* Fill header data */
	rc = lv_set(next, header, sizeof(*header), end);
	if (unlikely(rc))
		goto exit;
	next = body_cert.hash = lv_get_next(next, end);
	if (unlikely(!next))
		goto exit;

	/* Fill hash data */
	rc = lv_set(next, hash, hash_len, end);
	if (unlikely(rc))
		goto exit;
	next = body_cert.label = lv_get_next(next, end);
	if (unlikely(!next))
		goto exit;

	/* Fill label data */
	rc = lv_set(next, label, label_len, end);
	if (unlikely(rc))
		goto exit;

exit:
	if (likely(!rc)) {
		*raw_cert = data;
		*raw_cert_len = data_len;
	} else {
		kfree(data);
	}

	return rc;
}

void five_cert_free(void *raw_cert)
{
	kfree(raw_cert);
}

int five_cert_append_signature(void **raw_cert, size_t *raw_cert_len,
			       void *signature, size_t signature_len)
{
	int rc = 0;
	void *new_raw_cert;
	size_t new_raw_cert_len;
	const void *end;
	struct five_cert cert = { {0} };

	if (unlikely(!raw_cert || !raw_cert_len || !signature))
		return -EINVAL;

	new_raw_cert_len = *raw_cert_len + sizeof(cert.signature->length) +
			signature_len;
	if (unlikely(new_raw_cert_len > FIVE_MAX_CERTIFICATE_SIZE))
		return -EINVAL;

	new_raw_cert = krealloc(*raw_cert, new_raw_cert_len, GFP_NOFS);
	if (unlikely(!new_raw_cert))
		return -ENOMEM;

	*raw_cert = new_raw_cert;
	*raw_cert_len = new_raw_cert_len;
	end = (uint8_t *)new_raw_cert + new_raw_cert_len;

	rc = five_cert_fillout(&cert, new_raw_cert, new_raw_cert_len);
	if (unlikely(rc))
		return rc;

	rc = lv_set(cert.signature, signature, signature_len, end);

	return rc;
}

int five_cert_body_fillout(struct five_cert_body *body_cert,
			   const void *raw_cert, size_t raw_cert_len)
{
	struct lv *next;
	const void *end;
	struct five_cert_header *hdr;

	if (unlikely(!body_cert || !raw_cert ||
			raw_cert_len > FIVE_MAX_CERTIFICATE_SIZE))
		return -EINVAL;

	next = body_cert->header = (struct lv *)raw_cert;
	end = (uint8_t *)raw_cert + raw_cert_len;

	/* Check if we had an error at the previous step */
	if (!lv_get_next(next, end))
		return -EINVAL;

	if (sizeof(*hdr) != body_cert->header->length)
		return -EINVAL;

	hdr = (struct five_cert_header *)body_cert->header->value;
	if (hdr->version != FIVE_CERT_VERSION1)
		return -EINVAL;

	next = body_cert->hash = lv_get_next(next, end);
	if (unlikely(!next))
		return -EINVAL;

	next = body_cert->label = lv_get_next(next, end);
	if (unlikely(!next))
		return -EINVAL;

	return 0;
}

int five_cert_fillout(struct five_cert *cert, const void *raw_cert,
		      size_t raw_cert_len)
{
	int rc;
	struct lv *next;
	const void *end;

	if (unlikely(!cert || !raw_cert))
		return -EINVAL;

	if (unlikely(raw_cert_len > FIVE_MAX_CERTIFICATE_SIZE))
		return -EINVAL;

	rc = five_cert_body_fillout(&cert->body, raw_cert, raw_cert_len);
	if (unlikely(rc))
		return rc;

	next = cert->body.label;
	end = (uint8_t *)raw_cert + raw_cert_len;

	if (!lv_get_next(next, end))
		return -EINVAL;

	next = cert->signature = lv_get_next(next, end);
	if (unlikely(!next))
		return -EINVAL;

	return 0;
}

int five_cert_calc_hash(struct five_cert_body *body_cert, uint8_t *out_hash,
			size_t *out_hash_len)
{
	int rc;
	size_t hash_len, body_len;
	struct five_cert_header *header;

	if (unlikely(!body_cert || !out_hash || !out_hash_len))
		return -EINVAL;

	hash_len = *out_hash_len;
	header = (struct five_cert_header *)body_cert->header->value;
	body_len = sizeof(*body_cert->header) + body_cert->header->length +
		   sizeof(*body_cert->hash) + body_cert->hash->length +
		   sizeof(*body_cert->label) + body_cert->label->length;

	if (unlikely(body_len > FIVE_MAX_CERTIFICATE_SIZE))
		return -EINVAL;

	rc = five_calc_data_hash((const uint8_t *)body_cert->header, body_len,
				 header->hash_algo, out_hash, &hash_len);
	if (unlikely(rc))
		return rc;

	*out_hash_len = hash_len;

	return 0;
}
