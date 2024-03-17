/*
 * dd_kernel_crypto.c
 *
 *  Created on: Sep 24, 2018
 *      Author: olic.moon
 */

#include <linux/random.h>
#include <keys/user-type.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/skcipher.h>
#include <linux/bio.h>
#include <linux/file.h>

#include "dd_common.h"
#include "../../fs/crypto/ddar/ddar_crypto.h"

#define DD_XTS_TWEAK_SIZE       16

#define DD_AES_256_GCM_KEY_SIZE 32
#define DD_AES_256_GCM_TAG_SIZE 16
#define DD_AES_256_GCM_IV_SIZE  12
#define DD_AES_256_GCM_AAD      "DDAR_ADDITIONAL_AUTHENTICATION_DATA"

static int get_dd_file_key(struct dd_crypt_context *crypt_context,
		struct fscrypt_key *dd_master_key, unsigned char *raw_key);

#define DD_CRYPT_MODE_INVALID     0
#define DD_CRYPT_MODE_AES_256_XTS 1
#define DD_CRYPT_MODE_AES_256_CBC 2

static struct dd_crypt_mode {
	const char *cipher_str;
	int keysize;
} available_modes[] = {
	[DD_CRYPT_MODE_AES_256_XTS] = {
		.cipher_str = "xts(aes)",
		.keysize = 64,
	},
	[DD_CRYPT_MODE_AES_256_CBC] = {
		.cipher_str = "cbc(aes)",
		.keysize = 32,
	},
};

static struct dd_crypt_mode *dd_get_crypt_mode(const struct dd_policy *policy)
{
	char version;
	if (policy == NULL)
		return &available_modes[DD_CRYPT_MODE_INVALID];

	version = policy->version;
	switch (version) {
	case DDAR_DRIVER_VERSION_0:
	case DDAR_DRIVER_VERSION_1:
		return &available_modes[DD_CRYPT_MODE_AES_256_XTS];
	case DDAR_DRIVER_VERSION_2:
		return &available_modes[DD_CRYPT_MODE_AES_256_CBC];
	default:
		return &available_modes[DD_CRYPT_MODE_INVALID];
	}
}

int dd_generate_file_key(char userId, struct dd_crypt_context *crypt_context)
{
	int rc = 0;
	// generate file key and encrypt it with master key
	struct fscrypt_key master_key;
	struct crypto_aead *key_aead = NULL;
	struct aead_request *aead_req = NULL;
	struct scatterlist src_sg[3], dst_sg[3];
	char *aad = NULL;
	unsigned char iv[DD_AES_256_GCM_IV_SIZE];
	unsigned char *tag;
	unsigned char *file_encryption_key;
	unsigned char *cipher_file_encryption_key;
	struct dd_crypt_mode *mode = dd_get_crypt_mode(&crypt_context->policy);
	dd_verbose("%s - cipher : %s, keysize : %d\n", __func__, mode->cipher_str, mode->keysize);

	rc = get_dd_master_key(userId, &master_key);
	if (rc) {
		dd_error("failed to retrieve master key user:%d rc:%d\n", userId, rc);
		return -ENOKEY;
	}

	file_encryption_key = kzalloc(mode->keysize, GFP_KERNEL);
	cipher_file_encryption_key = kzalloc(mode->keysize, GFP_KERNEL);
	aad = kzalloc(strlen(DD_AES_256_GCM_AAD)+1, GFP_KERNEL);
	tag = kzalloc(DD_AES_256_GCM_TAG_SIZE, GFP_KERNEL);
	if (!file_encryption_key || !cipher_file_encryption_key || !tag || !aad) {
		rc = -ENOMEM;
		goto out;
	}

	memcpy(aad, DD_AES_256_GCM_AAD, strlen(DD_AES_256_GCM_AAD));
	aad[strlen(DD_AES_256_GCM_AAD)] = '\0';
	memset(iv, 0, DD_AES_256_GCM_IV_SIZE);
	memset(tag, 0, DD_AES_256_GCM_TAG_SIZE);

	dd_dump("ddar master key", master_key.raw, master_key.size);

	rc = ddar_crypto_generate_key(file_encryption_key, mode->keysize);
	if (rc)
		memset(file_encryption_key, 0, mode->keysize);

	dd_dump("ddar file key", file_encryption_key, mode->keysize);

	key_aead = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(key_aead)) {
		rc = PTR_ERR(key_aead);
		key_aead = NULL;
		goto out;
	}

	rc = crypto_aead_setauthsize(key_aead, DD_AES_256_GCM_TAG_SIZE);
	if (rc < 0) {
		dd_error("can't set crypto auth tag len: %d\n", rc);
		goto out;
	}

	aead_req = aead_request_alloc(key_aead, GFP_KERNEL);
	if (!aead_req) {
		rc = -ENOMEM;
		goto out;
	}

	sg_init_table(src_sg, 3);
	sg_set_buf(&src_sg[0], aad, strlen(aad));
	sg_set_buf(&src_sg[1], file_encryption_key, mode->keysize);
	sg_set_buf(&src_sg[2], tag, DD_AES_256_GCM_TAG_SIZE);

	sg_init_table(dst_sg, 3);
	sg_set_buf(&dst_sg[0], aad, strlen(aad));
	sg_set_buf(&dst_sg[1], cipher_file_encryption_key, mode->keysize);
	sg_set_buf(&dst_sg[2], tag, DD_AES_256_GCM_TAG_SIZE);

	aead_request_set_ad(aead_req, strlen(aad));
	aead_request_set_crypt(aead_req, src_sg, dst_sg, mode->keysize, iv);
	if (crypto_aead_setkey(key_aead, master_key.raw, DD_AES_256_GCM_KEY_SIZE)) {
		rc = -EAGAIN;
		goto out;
	}

	rc = crypto_aead_encrypt(aead_req);
	if (rc) {
		dd_error("failed to encrypt file key\n");
		goto out;
	}

	memcpy(crypt_context->cipher_file_encryption_key, cipher_file_encryption_key, mode->keysize);
	memcpy(crypt_context->tag, tag, DD_AES_256_GCM_TAG_SIZE);
	dd_dump("ddar file key (cipher)", crypt_context->cipher_file_encryption_key, mode->keysize);
	dd_dump("ddar tag ", crypt_context->tag, DD_AES_256_GCM_TAG_SIZE);

	dd_verbose("crypt context created (kernel crypto)\n");

out:
	crypto_free_aead(key_aead);

	if (file_encryption_key) {
		memzero_explicit(file_encryption_key, mode->keysize);
		kfree(file_encryption_key);
	}
	if (cipher_file_encryption_key)
		kfree(cipher_file_encryption_key);
	if (aad)
		kfree(aad);
	if (tag)
		kfree(tag);
	if (aead_req)
		aead_request_free(aead_req);
	secure_zeroout(__func__, master_key.raw, master_key.size);

	return rc;
}
int dd_create_crypt_context(struct inode *inode, const struct dd_policy *policy, void *fs_data)
{
	struct dd_crypt_context crypt_context;
	int rc = 0;

	memset(&crypt_context, 0, sizeof(struct dd_crypt_context));
	memcpy(&crypt_context.policy, policy, sizeof(struct dd_policy));

	dd_verbose("ino:%ld applying policy user:%d flags:%x\n",
			inode->i_ino, policy->userid, policy->flags);
	if (dd_policy_kernel_crypto(policy->flags) && S_ISREG(inode->i_mode)) {
		rc = dd_generate_file_key(policy->userid, &crypt_context);
	}

	if (rc) {
		dd_error("failed to create crypt context rc:%d\n", rc);
		return rc;
	}
	return dd_write_crypt_context(inode, &crypt_context, fs_data);
}

#if USE_KEYRING
int get_dd_master_key(int userid, void *key)
{
	struct fscrypt_key *dd_master_key = (struct fscrypt_key *)key;
	int key_desc_len = DD_KEY_DESC_PREFIX_LEN + 3;
	unsigned char key_desc[key_desc_len];
	struct key *keyring_key = NULL;
	const struct user_key_payload *ukp;

	int rc = 0;

	memcpy(key_desc, DD_KEY_DESC_PREFIX, DD_KEY_DESC_PREFIX_LEN);
	sprintf(key_desc + DD_KEY_DESC_PREFIX_LEN, "%03d", userid);
	keyring_key = request_key(&key_type_logon, key_desc, NULL);

	if (IS_ERR(keyring_key)) {
		rc = PTR_ERR(keyring_key);
		dd_error("error get keyring! (%s): err:%d\n",
				key_desc, rc);
		keyring_key = NULL;
		goto out;
	}

	if (keyring_key->type != &key_type_logon) {
		dd_error("key type must be logon\n");
		rc = -ENOKEY;
		goto out;
	}

	down_read(&keyring_key->sem);
	ukp = user_key_payload_locked(keyring_key);
	if (ukp->datalen != sizeof(struct fscrypt_key)) {
		dd_error("payload size mismatch:%d (expected:%ld)\n",
				ukp->datalen, sizeof(struct fscrypt_key));
		rc = -EINVAL;
		goto out_free;
	}

	memcpy(dd_master_key, ukp->data, sizeof(struct fscrypt_key));
	BUG_ON(dd_master_key->mode != FS_ENCRYPTION_MODE_AES_256_GCM);
	BUG_ON(dd_master_key->size != DD_AES_256_GCM_KEY_SIZE);

out_free:
	up_read(&keyring_key->sem);
out:
	return rc;
}
#else

static LIST_HEAD(dd_master_key_head);
static DEFINE_SPINLOCK(dd_master_key_lock);

struct dd_master_key {
	struct list_head list;

	int userid;
	struct fscrypt_key key;
};

int dd_add_master_key(int userid, void *key, int len)
{
	struct dd_master_key *mk = NULL;
	struct list_head *entry;

	if (len != sizeof(struct fscrypt_key)) {
		dd_error("failed to add master key: len error");
		return -EINVAL;
	}

	list_for_each(entry, &dd_master_key_head) {
		struct dd_master_key *k = list_entry(entry, struct dd_master_key, list);

		if (k->userid == userid) {
			dd_error("failed to add master key: exists");
			return -EEXIST;
		}
	}

	mk = kmalloc(sizeof(struct dd_master_key), GFP_ATOMIC);
	if (!mk) {
		dd_error("failed to add master key: no memory");
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&mk->list);
	mk->userid = userid;

	memcpy(&mk->key, key, sizeof(struct fscrypt_key));
	if (mk->key.size > FSCRYPT_MAX_KEY_SIZE) {
		//handle wrong size
		dd_error("failed to add master key: size error");
		kfree_sensitive(mk);
		return -EINVAL;
	}
	spin_lock(&dd_master_key_lock);
	list_add_tail(&mk->list, &dd_master_key_head);
	spin_unlock(&dd_master_key_lock);

	return 0;
}

void dd_evict_master_key(int userid)
{
	struct dd_master_key *mk = NULL;
	struct list_head *entry;

	spin_lock(&dd_master_key_lock);
	list_for_each(entry, &dd_master_key_head) {
		struct dd_master_key *k = list_entry(entry, struct dd_master_key, list);

		if (k->userid == userid) {
			mk = k;
		}
	}

	if (mk) {
		secure_zeroout("dd_evict_master_key", mk->key.raw, mk->key.size);
		list_del(&mk->list);
		kfree_sensitive(mk);
	}
	spin_unlock(&dd_master_key_lock);
}

int get_dd_master_key(int userid, void *key)
{
	struct list_head *entry;
	int rc = -ENOENT;

	spin_lock(&dd_master_key_lock);
	list_for_each(entry, &dd_master_key_head) {
		struct dd_master_key *k = list_entry(entry, struct dd_master_key, list);

		if (k->userid == userid) {
			memcpy(key, (void *)&k->key, sizeof(struct fscrypt_key));
			rc = 0;
			break;
		}
	}
	spin_unlock(&dd_master_key_lock);

	return rc;
}

#ifdef CONFIG_SDP_KEY_DUMP
int dd_dump_key(int userid, int fd)
{
	struct fscrypt_key dd_inner_master_key;
	struct fscrypt_key dd_outer_master_key;
	struct fscrypt_key dd_outer_file_encryption_key;
	struct dd_crypt_context crypt_context;
	struct fd f = {NULL, 0};
	struct inode *inode;
	unsigned char *dd_inner_file_encryption_key = NULL;
	int rc = 0;
	struct dd_crypt_mode *mode;

	dd_error("########## DUALDAR_DUMP - START ##########\n");
	f = fdget(fd);
	if (unlikely(f.file == NULL)) {
		dd_error("[DUALDAR_DUMP] invalid fd : %d\n", fd);
		rc = -EINVAL;
		goto out;
	}
	inode = f.file->f_path.dentry->d_inode;
	if (dd_read_crypt_context(inode, &crypt_context) != sizeof(struct dd_crypt_context)) {
		dd_error("[DUALDAR_DUMP] failed to read dd crypt context ino:%ld\n", inode->i_ino);
		rc = -EINVAL;
		goto out;
	}

	mode = dd_get_crypt_mode(&(crypt_context.policy));

	/**
	 * DUMP KEY FOR INNER LAYER
	 */
	if (dd_policy_kernel_crypto(crypt_context.policy.flags) && S_ISREG(inode->i_mode)) {
		dd_error("[DUALDAR_DUMP] DUMP KEYS FOR KERNEL CRYPTO\n");

		dd_inner_file_encryption_key = kzalloc(mode->keysize, GFP_KERNEL);
		if (!dd_inner_file_encryption_key) {
			rc = -ENOMEM;
			goto out;
		}

		rc = get_dd_master_key(userid, &dd_inner_master_key);
		if (rc) {
			dd_error("[DUALDAR_DUMP] failed to retrieve dualdar master key, rc:%d\n", rc);
			rc = -ENOKEY;
			goto out;
		}
		dd_hex_key_dump("[DUALDAR_DUMP] INNER LAYER MASTER KEY", dd_inner_master_key.raw, dd_inner_master_key.size);

		rc = get_dd_file_key(&crypt_context, &dd_inner_master_key, dd_inner_file_encryption_key);
		if (rc) {
			dd_error("[DUALDAR_DUMP] failed to retrieve inner fek, rc:%d\n", rc);
			goto out;
		}
		dd_hex_key_dump("[DUALDAR_DUMP] INNER LAYER FILE ENCRYPTION KEY", dd_inner_file_encryption_key, mode->keysize);

	} else {
		dd_error("[DUALDAR_DUMP] DUMP KEYS FOR THIRD-PARTY CRYPTO\n");
		dd_error("[DUALDAR_DUMP] INNER LAYER MASTER KEY : SKIP FOR THRID-PARTY CRYPTO\n");
		dd_error("[DUALDAR_DUMP] INNER LAYER FILE ENCRYPTION KEY : SKIP FOR THRID-PARTY CRYPTO\n");
	}

	/**
	 * DUMPM KEY FOR OUTER LAYER
	 */
	rc = fscrypt_get_encryption_kek(inode->i_crypt_info, &dd_outer_master_key);
	if (rc) {
		dd_error("[DUALDAR_DUMP] failed to retrieve outer master key, rc : %d\n", rc);
		goto out;
	}
	dd_hex_key_dump("[DUALDAR_DUMP] OUTER LAYER MASTER KEY", dd_outer_master_key.raw, dd_outer_master_key.size);

	memset(&dd_outer_file_encryption_key, 0, sizeof(dd_outer_file_encryption_key));
	rc = fscrypt_get_encryption_key(inode->i_crypt_info, &dd_outer_file_encryption_key);
	if (rc) {
		dd_error("[DUALDAR_DUMP] failed to retrieve outer fek, rc:%d\n", rc);
		goto out;
	}
	dd_hex_key_dump("[DUALDAR_DUMP] OUTER LAYER FILE ENCRYPTION KEY", dd_outer_file_encryption_key.raw, dd_outer_file_encryption_key.size);

out:
	if (dd_inner_file_encryption_key)
		kfree(dd_inner_file_encryption_key);
	if (f.file)
		fdput(f);
	dd_error("########## DUALDAR_DUMP - END ##########\n");

	return rc;
}
#endif
#endif

static int get_dd_file_key(struct dd_crypt_context *crypt_context,
		struct fscrypt_key *dd_master_key, unsigned char *raw_key)
{
	struct crypto_aead *key_aead = NULL;
	struct aead_request *aead_req = NULL;
	struct scatterlist src_sg[3], dst_sg[3];
	char *aad = NULL;
	char iv[DD_AES_256_GCM_IV_SIZE];
	char *tag = NULL;

	int rc = 0;
	unsigned char *cipher_file_encryption_key;
	struct dd_crypt_mode *mode = dd_get_crypt_mode(&(crypt_context->policy));
	dd_verbose("%s - cipher : %s, keysize : %d\n", __func__, mode->cipher_str, mode->keysize);

	cipher_file_encryption_key = kzalloc(mode->keysize, GFP_KERNEL);
	aad = kzalloc(strlen(DD_AES_256_GCM_AAD)+1, GFP_KERNEL);
	tag = kzalloc(DD_AES_256_GCM_TAG_SIZE, GFP_KERNEL);
	if (!cipher_file_encryption_key || !aad || !tag) {
		rc = -ENOMEM;
		goto out;
	}

	memcpy(aad, DD_AES_256_GCM_AAD, strlen(DD_AES_256_GCM_AAD));
	aad[strlen(DD_AES_256_GCM_AAD)] = '\0';
	dd_dump("aad", aad, strlen(DD_AES_256_GCM_AAD));
	memset(iv, 0, DD_AES_256_GCM_IV_SIZE);
	memcpy(tag, crypt_context->tag, DD_AES_256_GCM_TAG_SIZE);
	dd_dump("tag", crypt_context->tag, DD_AES_256_GCM_TAG_SIZE);
	key_aead = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(key_aead)) {
		rc = PTR_ERR(key_aead);
		key_aead = NULL;
		goto out;
	}

	rc = crypto_aead_setauthsize(key_aead, DD_AES_256_GCM_TAG_SIZE);
	if (rc < 0) {
		dd_error("can't set crypto auth tag len: %d\n", rc);
		goto out;
	}

	aead_req = aead_request_alloc(key_aead, GFP_KERNEL);
	if (!aead_req) {
		rc = -ENOMEM;
		goto out;
	}

	dd_dump("ddar file key (cipher)", crypt_context->cipher_file_encryption_key, mode->keysize);
	memcpy(cipher_file_encryption_key, crypt_context->cipher_file_encryption_key, mode->keysize);

	sg_init_table(src_sg, 3);
	sg_set_buf(&src_sg[0], aad, strlen(aad));
	sg_set_buf(&src_sg[1], cipher_file_encryption_key, mode->keysize);
	sg_set_buf(&src_sg[2], tag, DD_AES_256_GCM_TAG_SIZE);

	sg_init_table(dst_sg, 3);
	sg_set_buf(&dst_sg[0], aad, strlen(aad));
	sg_set_buf(&dst_sg[1], raw_key, mode->keysize);
	sg_set_buf(&dst_sg[2], tag, DD_AES_256_GCM_TAG_SIZE);

	aead_request_set_ad(aead_req, strlen(aad));
	aead_request_set_crypt(aead_req, src_sg, dst_sg, mode->keysize + DD_AES_256_GCM_TAG_SIZE, iv);
	if (crypto_aead_setkey(key_aead, dd_master_key->raw, DD_AES_256_GCM_KEY_SIZE)) {
		rc = -EAGAIN;
		goto out;
	}

	rc = crypto_aead_decrypt(aead_req);
	if (rc) {
		dd_error("failed to decrypt file key\n");
		goto out;
	}

	dd_dump("ddar file key", raw_key, mode->keysize);
out:
	if (rc)
		dd_error("file key derivation failed\n");

	crypto_free_aead(key_aead);
	if (cipher_file_encryption_key)
		kfree(cipher_file_encryption_key);
	if (aad)
		kfree(aad);
	if (tag)
		kfree(tag);
	if (aead_req)
		aead_request_free(aead_req);

	return rc;
}

struct crypto_skcipher *dd_alloc_ctfm(struct dd_crypt_context *crypt_context, void *key)
{
	struct fscrypt_key *dd_master_key = (struct fscrypt_key *)key;
	struct crypto_skcipher *ctfm = NULL;
	unsigned char *raw_key;
	int rc;
	struct dd_crypt_mode *mode = dd_get_crypt_mode(&(crypt_context->policy));
	dd_verbose("%s - cipher : %s, keysize : %d\n", __func__, mode->cipher_str, mode->keysize);

	raw_key = kzalloc(mode->keysize, GFP_KERNEL);
	if (!raw_key) {
		rc = -ENOMEM;
		goto out;
	}

	rc = get_dd_file_key(crypt_context, dd_master_key, raw_key);
	if (rc) {
		dd_error("Failed to retrieve file key rc:%d\n", rc);
		goto out;
	}

	ctfm = crypto_alloc_skcipher(mode->cipher_str, 0, 0);
	if (!ctfm || IS_ERR(ctfm)) {
		rc = ctfm ? PTR_ERR(ctfm) : -ENOMEM;
		dd_error("Failed allocating crypto tfm rc:%d\n", rc);
		goto out;
	}

	crypto_skcipher_clear_flags(ctfm, ~0);
	crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);
	rc = crypto_skcipher_setkey(ctfm, raw_key, mode->keysize);
	if (rc) {
		dd_error("failed to set file key rc:%d\n", rc);
		goto out;
	}

out:
	if (raw_key) {
		secure_zeroout(__func__, raw_key, mode->keysize);
		kfree(raw_key);
	}

	if (rc) {
		if (ctfm && !IS_ERR(ctfm))
			crypto_free_skcipher(ctfm);

		return ERR_PTR(rc);
	}

	return ctfm;
}

int dd_sec_crypt_page(struct dd_info *info, dd_crypto_direction_t rw,
		struct page *src_page, struct page *dst_page)
{
	struct skcipher_request *req = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist dst, src;
	struct crypto_skcipher *tfm = info->ctfm;
	char iv[DD_XTS_TWEAK_SIZE];

	int rc = 0;

	memset(iv, 0, DD_XTS_TWEAK_SIZE);
	req = skcipher_request_alloc(tfm, GFP_ATOMIC);
	if (!req) {
		dd_error("crypto_request_alloc() failed\n");
		return -ENOMEM;
	}

	skcipher_request_set_callback(
			req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &wait);

	sg_init_table(&dst, 1);
	sg_set_page(&dst, dst_page, PAGE_SIZE, 0);
	sg_init_table(&src, 1);
	sg_set_page(&src, src_page, PAGE_SIZE, 0);
	skcipher_request_set_crypt(req, &src, &dst, PAGE_SIZE, iv);
	if (rw == DD_DECRYPT)
	    rc = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	else
	    rc = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);

	skcipher_request_free(req);
	if (rc) {
		dd_error("crypto_skcipher_encrypt() returned %d\n", rc);
		return rc;
	}
	return 0;
}

int dd_sec_crypt_bio_pages(struct dd_info *info, struct bio *orig,
		struct bio *clone, dd_crypto_direction_t rw)
{
    struct bvec_iter iter_backup;
    int rc = 0;

	BUG_ON(rw == DD_ENCRYPT && !clone);
    // back up bio iterator. restore before submitting it to block layer
    memcpy(&iter_backup, &orig->bi_iter, sizeof(struct bvec_iter));

	while (orig->bi_iter.bi_size) {
		if (rw == DD_ENCRYPT) {
			struct bio_vec orig_bv = bio_iter_iovec(orig, orig->bi_iter);
			struct bio_vec clone_bv = bio_iter_iovec(clone, clone->bi_iter);
			struct page *plaintext_page = orig_bv.bv_page;
			struct page *ciphertext_page = clone_bv.bv_page;

			BUG_ON(info->ino != orig_bv.bv_page->mapping->host->i_ino);
			dd_dump("dd_crypto_bio_pages::encryption start", page_address(plaintext_page), PAGE_SIZE);
			rc = dd_sec_crypt_page(info, DD_ENCRYPT, plaintext_page, ciphertext_page);
			if (rc) {
				dd_error("failed encryption rc:%d\n", rc);
				return rc;
			}
			dd_dump("dd_crypto_bio_pages::encryption finished", page_address(ciphertext_page), PAGE_SIZE);

			bio_advance_iter(orig, &orig->bi_iter, 1 << PAGE_SHIFT);
			bio_advance_iter(clone, &clone->bi_iter, 1 << PAGE_SHIFT);
		} else {
			struct bio_vec orig_bv = bio_iter_iovec(orig, orig->bi_iter);
			struct page *ciphertext_page = orig_bv.bv_page;

			BUG_ON(info->ino != orig_bv.bv_page->mapping->host->i_ino);
			dd_dump("dd_crypto_bio_pages::decryption start", page_address(ciphertext_page), PAGE_SIZE);
			rc = dd_sec_crypt_page(info, DD_DECRYPT, ciphertext_page, ciphertext_page);
			if (rc) {
				dd_error("failed encryption rc:%d\n", rc);
				return rc;
			}
			dd_dump("dd_crypto_bio_pages::decryption finished", page_address(ciphertext_page), PAGE_SIZE);

			bio_advance_iter(orig, &orig->bi_iter, 1 << PAGE_SHIFT);
		}
	}

	memcpy(&orig->bi_iter, &iter_backup, sizeof(struct bvec_iter));
	if (rw == DD_ENCRYPT)
		memcpy(&clone->bi_iter, &iter_backup, sizeof(struct bvec_iter));

	return 0;
}

void dd_hex_key_dump(const char *tag, uint8_t *data, unsigned int data_len)
{
	static const char *hex = "0123456789ABCDEF";
	static const char delimiter = ' ';
	unsigned int i;
	char *buf;
	size_t buf_len;

	if (tag == NULL || data == NULL || data_len <= 0) {
		return;
	}

	buf_len = data_len * 3;
	buf = (char *)kmalloc(buf_len, GFP_ATOMIC);
	if (buf == NULL) {
		return;
	}
	for (i = 0; i < data_len; i++) {
		buf[i*3 + 0] = hex[(data[i] >> 4) & 0x0F];
		buf[i*3 + 1] = hex[(data[i]) & 0x0F];
		buf[i*3 + 2] = delimiter;
	}
	buf[buf_len - 1] = '\0';
	printk(KERN_ERR
		"[%s] %s(len=%d) : %s\n", "DEK_DBG", tag, data_len, buf);
	kfree(buf);
}
