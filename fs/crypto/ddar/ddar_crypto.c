/*
 *  Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <crypto/hash.h>
#include <crypto/rng.h>
#include <keys/encrypted-type.h>
#include <keys/user-type.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kern_levels.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/types.h>
#include <uapi/linux/keyctl.h>

#include "ddar_crypto.h"

int __init ddar_crypto_init(void)
{
	// Defer effective initialization until the time /dev/random is ready.
	printk(KERN_INFO "ddar_crypto: initialized!\n");
	return 0;
}

/* Codes are extracted from fs/crypto/crypto_sec.c */
#ifdef CONFIG_CRYPTO_SKC_FIPS
static struct crypto_rng *ddar_crypto_rng = NULL;
#endif
static struct crypto_shash *sha512_tfm = NULL;

#ifdef CONFIG_CRYPTO_SKC_FIPS
static int ddar_crypto_init_rng(void)
{
	struct crypto_rng *jitter_rng = NULL;
	struct crypto_rng *rng = NULL;
	unsigned char *rng_seed = NULL;
	int res = 0;

	/* already initialized */
	if (ddar_crypto_rng) {
		printk(KERN_ERR "ddar_crypto: ddar_crypto_rng already initialized\n");
		return 0;
	}

	rng_seed = kmalloc(DDAR_CRYPTO_RNG_SEED_SIZE, GFP_KERNEL);
	if (!rng_seed) {
		printk(KERN_ERR "ddar_crypto: failed to allocate rng_seed memory\n");
		res = -ENOMEM;
		goto out;
	}
	memset((void *)rng_seed, 0, DDAR_CRYPTO_RNG_SEED_SIZE);

	jitter_rng = crypto_alloc_rng("jitterentropy_rng", 0, 0);
	if (IS_ERR(jitter_rng)) {
		printk(KERN_ERR "ddar_crypto: failed to allocate jitter_rng, "
				"not available (%ld)\n", PTR_ERR(jitter_rng));
		res = PTR_ERR(jitter_rng);
		jitter_rng = NULL;
		goto out;
	}

	res = crypto_rng_get_bytes(jitter_rng, rng_seed, DDAR_CRYPTO_RNG_SEED_SIZE);
	if (res < 0)
		printk(KERN_ERR "ddar_crypto: get rng seed fail (%d)\n", res);

	// create drbg for random number generation
	rng = crypto_alloc_rng("stdrng", 0, 0);
	if (IS_ERR(rng)) {
		printk(KERN_ERR "ddar_crypto: failed to allocate rng, "
			"not available (%ld)\n", PTR_ERR(rng));
		res = PTR_ERR(rng);
		rng = NULL;
		goto out;
	}

	// push seed to drbg
	res = crypto_rng_reset(rng, rng_seed, DDAR_CRYPTO_RNG_SEED_SIZE);
	if (res < 0)
		printk(KERN_ERR "ddar_crypto: rng reset fail (%d)\n", res);
out:
	if (res && rng) {
		crypto_free_rng(rng);
		rng = NULL;
	}
	kfree(rng_seed);
	if (jitter_rng) {
		printk(KERN_DEBUG "ddar_crypto: release jitter rng!\n");
		crypto_free_rng(jitter_rng);
		jitter_rng = NULL;
	}

	// save rng on global variable
	ddar_crypto_rng = rng;
	return res;
}
#endif

int ddar_crypto_generate_key(void *raw_key, int nbytes)
{
#ifdef CONFIG_CRYPTO_SKC_FIPS
	int res;
	int trial = 10;

	if (likely(ddar_crypto_rng)) {
again:
		BUG_ON(!ddar_crypto_rng);
		return crypto_rng_get_bytes(ddar_crypto_rng,
			raw_key, nbytes);
	}

	do {
		res = ddar_crypto_init_rng();
		if (!res)
			goto again;

		printk(KERN_DEBUG "ddar_crypto: try to sdp_crypto_init_rng(%d)\n", trial);
		msleep(500);
		trial--;

	} while (trial > 0);

	printk(KERN_ERR "ddar_crypto: failed to initialize "
			"ddar crypto rng handler again (err:%d)\n", res);
	return res;
#else
	get_random_bytes(raw_key, nbytes);
	return 0;
#endif
}

static void ddar_crypto_exit_rng(void)
{
#ifdef CONFIG_CRYPTO_SKC_FIPS
	if (!ddar_crypto_rng)
		return;

	printk(KERN_DEBUG "ddar_crypto: release ddar crypto rng!\n");
	crypto_free_rng(ddar_crypto_rng);
	ddar_crypto_rng = NULL;
#else
	return;
#endif
}

static void __exit ddar_crypto_exit_sha512(void)
{
	crypto_free_shash(sha512_tfm);
	sha512_tfm = NULL;
}

void __exit ddar_crypto_exit(void)
{
	ddar_crypto_exit_rng();
	ddar_crypto_exit_sha512();
}

int sdp_crypto_hash_sha512(const u8 *data, u32 data_len, u8 *hashed)
{
	struct crypto_shash *tfm = READ_ONCE(sha512_tfm);

	/* init hash transform on demand */
	if (unlikely(!tfm)) {
		struct crypto_shash *prev_tfm;

		tfm = crypto_alloc_shash("sha512", 0, 0);
		if (IS_ERR(tfm)) {
			printk(KERN_ERR
				"sdp_crypto_sha512: error allocating SHA-512 transform: %ld",
				PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}
		prev_tfm = cmpxchg(&sha512_tfm, NULL, tfm);
		if (prev_tfm) {
			crypto_free_shash(tfm);
			tfm = prev_tfm;
		}
	}

	{
		SHASH_DESC_ON_STACK(desc, tfm);
		desc->tfm = tfm;
		//desc->flags = 0;

		return crypto_shash_digest(desc, data, data_len, hashed);
	}
}

int sdp_crypto_aes_gcm_encrypt(struct crypto_aead *tfm,
					u8 *data, size_t data_len, u8 *auth, u8 *iv)
{
	struct scatterlist sg[3];
	struct aead_request *aead_req;
	int reqsize;
	int err;
	u8 *__aad;

	if (tfm == NULL || iv == NULL || data == NULL || auth == NULL) {
		printk(KERN_ERR
			"sdp_crypto_aes_gcm_encrypt: failed due to invalid input\n");
		return -EINVAL;
	}

	reqsize = sizeof(*aead_req) + crypto_aead_reqsize(tfm);
	aead_req = kzalloc(reqsize + SDP_CRYPTO_GCM_AAD_LEN, GFP_ATOMIC);
	if (!aead_req)
		return -ENOMEM;

	__aad = (u8 *)aead_req + reqsize;
	memcpy(__aad, SDP_CRYPTO_GCM_DEFAULT_AAD, SDP_CRYPTO_GCM_AAD_LEN);

	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], __aad, SDP_CRYPTO_GCM_AAD_LEN);
	sg_set_buf(&sg[1], data, data_len);
	sg_set_buf(&sg[2], auth, SDP_CRYPTO_GCM_AUTH_LEN);

	aead_request_set_tfm(aead_req, tfm);
	aead_request_set_crypt(aead_req, sg, sg, data_len, iv);
	aead_request_set_ad(aead_req, SDP_CRYPTO_GCM_AAD_LEN);

	err = crypto_aead_encrypt(aead_req);
	kfree_sensitive(aead_req);
	return err;
}

int sdp_crypto_aes_gcm_encrypt_pack(struct crypto_aead *tfm, gcm_pack *pack)
{
	struct scatterlist sg[3];
	struct aead_request *aead_req;
	int reqsize;
	int err;
	u8 *__aad;
	u8 *__data;
	u8 *__auth;
	size_t __aad_len = SDP_CRYPTO_GCM_AAD_LEN;
	size_t __auth_len = SDP_CRYPTO_GCM_AUTH_LEN;
	size_t __data_len = CONV_TYPE_TO_DLEN(pack->type);

	if (unlikely(tfm == NULL || pack == NULL || __data_len == 0)) {
		printk(KERN_ERR
			"sdp_crypto_aes_gcm_encrypt_pack: failed due to invalid input\n");
		return -EINVAL;
	}

	reqsize = sizeof(*aead_req) + crypto_aead_reqsize(tfm);
	aead_req = kzalloc(reqsize + __aad_len + __data_len + __auth_len, GFP_ATOMIC);
	if (!aead_req)
		return -ENOMEM;

	__aad = (u8 *)aead_req + reqsize;
	__data = __aad + __aad_len;
	__auth = __data + __data_len;
	memcpy(__aad, SDP_CRYPTO_GCM_DEFAULT_AAD, __aad_len);
	memcpy(__data, pack->data, __data_len);
	memcpy(__auth, pack->auth, __auth_len);

	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], __aad, __aad_len);
	sg_set_buf(&sg[1], __data, __data_len);
	sg_set_buf(&sg[2], __auth, __auth_len);

	aead_request_set_tfm(aead_req, tfm);
	aead_request_set_crypt(aead_req, sg, sg, __data_len, pack->iv);
	aead_request_set_ad(aead_req, __aad_len);

	err = crypto_aead_encrypt(aead_req);
	if (!err) {
		memcpy(pack->data, __data, __data_len + __auth_len);
	}
	kfree_sensitive(aead_req);
	return err;
}

int sdp_crypto_aes_gcm_decrypt(struct crypto_aead *tfm,
					u8 *data, size_t data_len, u8 *auth, u8 *iv)
{
	struct scatterlist sg[3];
	struct aead_request *aead_req;
	int reqsize;
	int err;
	u8 *__aad;

	if (tfm == NULL || iv == NULL || data == NULL || auth == NULL) {
		printk(KERN_ERR
			"sdp_crypto_aes_gcm_decrypt: failed due to invalid input\n");
		return -EINVAL;
	}
	reqsize = sizeof(*aead_req) + crypto_aead_reqsize(tfm);
	aead_req = kzalloc(reqsize + SDP_CRYPTO_GCM_AAD_LEN, GFP_ATOMIC);
	if (!aead_req)
		return -ENOMEM;

	__aad = (u8 *)aead_req + reqsize;
	memcpy(__aad, SDP_CRYPTO_GCM_DEFAULT_AAD, SDP_CRYPTO_GCM_AAD_LEN);

	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], __aad, SDP_CRYPTO_GCM_AAD_LEN);
	sg_set_buf(&sg[1], data, data_len);
	sg_set_buf(&sg[2], auth, SDP_CRYPTO_GCM_AUTH_LEN);

	aead_request_set_tfm(aead_req, tfm);
	aead_request_set_crypt(aead_req, sg, sg, data_len + SDP_CRYPTO_GCM_AUTH_LEN, iv);
	aead_request_set_ad(aead_req, SDP_CRYPTO_GCM_AAD_LEN);

	err = crypto_aead_decrypt(aead_req);
	kfree_sensitive(aead_req);
	return err;
}

int sdp_crypto_aes_gcm_decrypt_pack(struct crypto_aead *tfm, gcm_pack *pack)
{
	struct scatterlist sg[3];
	struct aead_request *aead_req;
	int reqsize;
	int err;
	u8 *__aad;
	u8 *__data;
	u8 *__auth;
	size_t __aad_len = SDP_CRYPTO_GCM_AAD_LEN;
	size_t __auth_len = SDP_CRYPTO_GCM_AUTH_LEN;
	size_t __data_len = CONV_TYPE_TO_DLEN(pack->type);

	if (unlikely(tfm == NULL || pack == NULL || __data_len == 0)) {
		printk(KERN_ERR
			"sdp_crypto_aes_gcm_decrypt_pack: failed due to invalid input\n");
		return -EINVAL;
	}
	reqsize = sizeof(*aead_req) + crypto_aead_reqsize(tfm);
	aead_req = kzalloc(reqsize + __aad_len + __data_len + __auth_len, GFP_ATOMIC);
	if (!aead_req)
		return -ENOMEM;

	__aad = (u8 *)aead_req + reqsize;
	__data = __aad + __aad_len;
	__auth = __data + __data_len;
	memcpy(__aad, SDP_CRYPTO_GCM_DEFAULT_AAD, __aad_len);
	memcpy(__data, pack->data, __data_len);
	memcpy(__auth, pack->auth, __auth_len);

	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], __aad, __aad_len);
	sg_set_buf(&sg[1], __data, __data_len);
	sg_set_buf(&sg[2], __auth, __auth_len);

	aead_request_set_tfm(aead_req, tfm);
	aead_request_set_crypt(aead_req, sg, sg, __data_len + __auth_len, pack->iv);
	aead_request_set_ad(aead_req, __aad_len);

	err = crypto_aead_decrypt(aead_req);
	if (!err) {
		memcpy(pack->data, __data, __data_len);
	}
	kfree_sensitive(aead_req);
	return err;
}

struct crypto_aead *sdp_crypto_aes_gcm_key_setup(const u8 key[], size_t key_len)
{
	struct crypto_aead *tfm;
	int err;

	tfm = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "ddar_crypto: failed to allocate aead handle\n");
		return tfm;
	}

	err = crypto_aead_setkey(tfm, key, key_len);
	if (err) {
		printk(KERN_ERR "ddar_crypto: failed to set key for aead (err:%d)\n", err);
		goto free_aead;
	}

	err = crypto_aead_setauthsize(tfm, SDP_CRYPTO_GCM_AUTH_LEN);
	if (err) {
		printk(KERN_ERR "ddar_crypto: failed to set auth size for aead (err:%d)\n", err);
		goto free_aead;
	}

	return tfm;

free_aead:
	crypto_free_aead(tfm);
	return ERR_PTR(err);
}

void sdp_crypto_aes_gcm_key_free(struct crypto_aead *tfm)
{
	crypto_free_aead(tfm);
}
