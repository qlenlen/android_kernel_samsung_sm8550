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

#ifndef __FIVE_CERT_H__
#define __FIVE_CERT_H__

#include "five_lv.h"

#define FIVE_MAX_DIGEST_SIZE 64
#define FIVE_MAX_CERTIFICATE_SIZE 4096

enum five_signature_type {
	FIVE_XATTR_NONE   = 0x00,
	FIVE_XATTR_DIGSIG = 0x01,
	FIVE_XATTR_HMAC   = 0x02,
	FIVE_XATTR_END
};

enum five_version {
	FIVE_CERT_VERSION1 = 1
};

enum five_privilege {
	FIVE_PRIV_DEFAULT = 0,
	FIVE_PRIV_ALLOW_SIGN
};

struct five_cert_header {
	uint8_t version; /* signature format version */
	uint8_t signature_type; /* signature type, e.g. HMAC, RSA */
	uint8_t privilege; /* privilege of file saved in certificate */
	uint8_t hash_algo; /* use hash algorithm for file and signature */
	uint32_t key_id; /* use for find key in keyrings */
} __packed;

/*
 * ---------------------------------------------
 * | Raw data of certificate FIVE in memory    |
 * ---------------------------------------------
 * |                     u16 | header_len      |
 * | struct five_cert_header | header_value    |
 * |                     u16 | hash_len        |
 * |                   array | hash_value      |
 * |                     u16 | label_len       |
 * |                   array | label_value     |
 * |                     u16 | signature_len   |
 * |                   array | signature_value |
 * ---------------------------------------------
 */
struct five_cert {
	struct five_cert_body {
		struct lv *header;
		struct lv *hash;
		struct lv *label;
	} body;
	struct lv *signature;
};

/**
 * Allocates and fills raw certificate buffer without signature.
 * Call five_cert_free() to release the allocated buffer.
 * Returns 0 on success, otherwise - error.
 */
int five_cert_body_alloc(struct five_cert_header *header,
			 uint8_t *hash, size_t hash_len,
			 uint8_t *label, size_t label_len,
			 uint8_t **raw_cert, size_t *raw_cert_len);

/**
 * Releases raw certificate buffer allocated previously by five_cert_alloc().
 */
void five_cert_free(void *raw_cert);

/**
 * Appends signature to raw certificate buffer. raw_cert memory will be
 * re-allocated to contain the signature.
 * Returns 0 on success, otherwise - error
 */
int five_cert_append_signature(void **raw_cert, size_t *raw_cert_len,
			       void *signature, size_t signature_len);

/**
 * Parse certificate raw data and fill items helper body_cert structure.
 * Notice, body_cert object is reference to data of raw_cert. It will valid
 * until raw_cert memory is valid.
 * In case of raw_cert is changed we should be update body_cert again.
 * Returns 0 on success, otherwise - error.
 */
int five_cert_body_fillout(struct five_cert_body *body_cert,
			   const void *raw_cert, size_t raw_cert_len);

/**
 * Parse certificate raw data and fill items helper cert structure.
 * Notice, cert object is reference to data of raw_cert. It will valid until
 * raw_cert memory is valid.
 * In case of raw_cert is changed we should be update cert again.
 * Returns 0 on success, otherwise - error.
 */
int five_cert_fillout(struct five_cert *cert, const void *raw_cert,
		      size_t raw_cert_len);

/**
 * Calculates hash of certificate, that contains header structure,
 * hash and label.
 * Returns 0 on success, otherwise - error.
 */
int five_cert_calc_hash(struct five_cert_body *body_cert, uint8_t *out_hash,
			size_t *out_hash_len);

#endif /* __FIVE_CERT_H__ */
