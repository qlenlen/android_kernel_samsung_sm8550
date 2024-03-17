#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/drbg.h>
#include <linux/scatterlist.h>
#include <linux/err.h>

#include "fips140.h"
#include "fips140_test.h"
#include "fips140_test_tv.h"

#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
static char *fips_functest_mode;

static char *fips_functest_KAT_list[] = {
	"integrity",
	"ecb(aes-generic)",
	"cbc(aes-generic)",
	"ecb(aes-ce)",
	"cbc(aes-ce)",
	"sha1-generic",
	"hmac(sha1-generic)",
	"sha1-ce",
	"hmac(sha1-ce)",
	"sha224-generic",
	"sha256-generic",
	"hmac(sha224-generic)",
	"hmac(sha256-generic)",
	"sha224-ce",
	"sha256-ce",
	"hmac(sha224-ce)",
	"hmac(sha256-ce)",
	"sha384-generic",
	"sha512-generic",
	"hmac(sha384-generic)",
	"hmac(sha512-generic)",
};
static char *fips_functest_conditional_list[] = {
	"zeroization"
};

// This function is added to change fips_functest_KAT_num from tcrypt.c
void set_fips_functest_KAT_mode(int num)
{
	if (num >= 0 && num < SKC_FUNCTEST_KAT_CASE_NUM)
		fips_functest_mode = fips_functest_KAT_list[num];
	else
		fips_functest_mode = SKC_FUNCTEST_NO_TEST;
}
EXPORT_SYMBOL_GPL(set_fips_functest_KAT_mode);

void set_fips_functest_conditional_mode(int num)
{
	if (num >= 0 && num < SKC_FUNCTEST_CONDITIONAL_CASE_NUM)
		fips_functest_mode = fips_functest_conditional_list[num];
	else
		fips_functest_mode = SKC_FUNCTEST_NO_TEST;
}
EXPORT_SYMBOL_GPL(set_fips_functest_conditional_mode);

char *get_fips_functest_mode(void)
{
	if (fips_functest_mode)
		return fips_functest_mode;
	else
		return SKC_FUNCTEST_NO_TEST;
}
EXPORT_SYMBOL_GPL(get_fips_functest_mode);

#endif /* CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST */

#if defined ADD_CUSTOM_KVMALLOC
static inline void *kvmalloc(size_t size, gfp_t flags)
{
	void *ret;

	ret = kmalloc(size, flags | GFP_NOIO | __GFP_NOWARN);
	if (!ret) {
		if (flags & __GFP_ZERO)
			ret = vzalloc(size);
		else
			ret = vmalloc(size);
	}
	return ret;
}
#endif

struct tcrypt_result {
	struct completion completion;
	int err;
};

static void crypt_complete(struct crypto_async_request *req, int err)
{
	struct tcrypt_result *res = req->data;

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}

static int __test_skcipher(struct crypto_skcipher *tfm,
							int enc,
							const struct cipher_testvec *tv)
{
#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
	const char *algo = crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm));
#endif
	struct skcipher_request *req = NULL;
	struct tcrypt_result result;
	struct scatterlist sg_src;
	struct scatterlist sg_dst;
	int ret = -EINVAL;
	uint8_t *__out_buf = NULL;
	uint8_t *__in_buf = NULL;
	uint8_t __iv[FIPS140_MAX_LEN_IV] = {0,};
	const uint8_t *__in = NULL;
	const uint8_t *__out = NULL;

	__out_buf = kvmalloc(FIPS140_MAX_LEN_PCTEXT, GFP_KERNEL);
	__in_buf = kvmalloc(FIPS140_MAX_LEN_PCTEXT, GFP_KERNEL);

	if ((!__out_buf) ||
		(!__in_buf)) {
		ret = -ENOMEM;
		goto out;
	}

	__in = enc ? tv->ptext : tv->ctext;
	__out = enc ? tv->ctext : tv->ptext;

	memcpy(__in_buf, __in, tv->len);

	if (tv->iv_len)
		memcpy(__iv, tv->iv, tv->iv_len);
	else
		memset(__iv, 0x00, FIPS140_MAX_LEN_IV);

	init_completion(&result.completion);

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto out;

	skcipher_request_set_callback(req,
									CRYPTO_TFM_REQ_MAY_BACKLOG,
									crypt_complete,
									&result);

#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
	if (!strcmp(algo, get_fips_functest_mode())) {
		unsigned char temp_key[512];

		memcpy(temp_key, tv->key, tv->klen);
		temp_key[0] += 1;
		ret = crypto_skcipher_setkey(tfm, temp_key, tv->klen);
	} else {
		ret = crypto_skcipher_setkey(tfm, tv->key, tv->klen);
	}
#else
	ret = crypto_skcipher_setkey(tfm, tv->key, tv->klen);
#endif

	if (ret)
		goto out;


	sg_init_one(&sg_src, __in_buf, tv->len);
	sg_init_one(&sg_dst, __out_buf, tv->len);

	skcipher_request_set_crypt(req,
								&sg_src,
								&sg_dst,
								tv->len,
								(void *)__iv);

	ret = enc ?	crypto_skcipher_encrypt(req) :
				crypto_skcipher_decrypt(req);
	switch (ret) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&result.completion);
		reinit_completion(&result.completion);
		ret = result.err;
		if (!ret)
			break;

	default:
		goto out;
	}

	if (memcmp(__out_buf, __out, tv->len))
		ret = -EINVAL;

out:
	if (req)
		skcipher_request_free(req);
	if (__in_buf)
		kfree_sensitive(__in_buf);
	if (__out_buf)
		kfree_sensitive(__out_buf);

	return ret;
}

static int test_skcipher(const struct cipher_test_suite *tv,
						 const char *driver,
						 u32 type,
						 u32 mask)
{
	struct crypto_skcipher *tfm;
	int err = 0;
	int i = 0;
	const char *algo = NULL;

	tfm = crypto_alloc_skcipher(driver, type, mask);
	if (IS_ERR(tfm)) {
		pr_err("FIPS : skcipher allocation error");
		return PTR_ERR(tfm);
	}

	algo = crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm));

	for (i = 0; i < tv->tv_count; i++) {
		err = __test_skcipher(tfm, FIPS140_TEST_ENCRYPT, &tv->vecs[i]);
		if (err) {
			pr_err("FIPS : %s, test %d encrypt failed, err=%d\n", algo, i, err);
			goto out;
		}
	}

	for (i = 0; i < tv->tv_count; i++) {
		err = __test_skcipher(tfm, FIPS140_TEST_DECRYPT, &tv->vecs[i]);
		if (err) {
			pr_err("FIPS : %s, test %d decrypt failed, err=%d\n", algo, i, err);
			goto out;
		}
	}

	pr_err("FIPS : self-tests for %s passed\n", algo);

out:
	if (tfm)
		crypto_free_skcipher(tfm);
	return err;
}

static int test_hash(const struct hash_test_suite *tv,
					const char *driver,
					u32 type,
					u32 mask)
{
	struct crypto_shash *tfm = NULL;
	struct shash_desc *shash_desc = NULL;
	int err = 0;
	int i = 0;
	int size = 0;
	uint8_t __digest_buf[FIPS140_MAX_LEN_DIGEST] = {0,};
	uint32_t __digest_len = 0;
	const char *__ptext = NULL;
	size_t __ptext_len = 0;
	const char *algo = driver;
#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
	uint8_t func_buf[1024];
#endif

	tfm = crypto_alloc_shash(driver, 0, 0);
	if (IS_ERR(tfm)) {
		err = -EINVAL;
		tfm = NULL;
		pr_err("FIPS : shash allocation error");
		goto out;
	}

	algo = crypto_tfm_alg_driver_name(crypto_shash_tfm(tfm));

	size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
	shash_desc = kvmalloc(size, GFP_KERNEL);
	if (!shash_desc) {
		shash_desc = NULL;
		err = -ENOMEM;
		goto out;
	}

	shash_desc->tfm = tfm;
	__digest_len = crypto_shash_digestsize(tfm);

	for (i = 0; i < tv->tv_count; i++) {
		if (tv->vecs[i].klen) {
			err = crypto_shash_setkey(tfm, tv->vecs[i].key, tv->vecs[i].klen);
			if (err)
				goto out;
		}

		err = crypto_shash_init(shash_desc);
		if (err)
			goto out;

		__ptext = tv->vecs[i].ptext;
		__ptext_len = tv->vecs[i].plen;
#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
		if (!strcmp(algo, get_fips_functest_mode())) {
			if (sizeof(func_buf) < tv->vecs[i].plen) {
				__ptext_len = sizeof(func_buf);
			}

			memcpy(func_buf, tv->vecs[i].ptext, __ptext_len);
			func_buf[0] = ~func_buf[0];
			__ptext = func_buf;
		}
#endif
		err = crypto_shash_update(shash_desc, __ptext, __ptext_len);
		if (err)
			goto out;

		err = crypto_shash_final(shash_desc, __digest_buf);
		if (err)
			goto out;

		if (memcmp(__digest_buf, tv->vecs[i].digest, __digest_len)) {
			err = -EINVAL;
			goto out;
		}
	}

	err = 0;

out:
	if (err)
		pr_err("FIPS : %s, test %d failed, err=%d\n", algo, i, err);
	else
		pr_err("FIPS : self-tests for %s passed\n", algo);

	if (tfm)
		crypto_free_shash(tfm);

	if (shash_desc)
		kfree_sensitive(shash_desc);

	return err;
}

int fips140_kat(void)
{
	int ret = 0;

#ifdef CONFIG_CRYPTO_AES
	ret += test_skcipher(&aes_cbc_tv, "cbc(aes-generic)", 0, 0);
	ret += test_skcipher(&aes_ecb_tv, "ecb(aes-generic)", 0, 0);
#endif

#ifdef CONFIG_CRYPTO_AES_ARM64_CE
	ret += test_skcipher(&aes_ecb_tv, "ecb(aes-ce)", 0, 0);
	ret += test_skcipher(&aes_cbc_tv, "cbc(aes-ce)", 0, 0);
#endif

#ifdef CONFIG_CRYPTO_SHA1
	ret += test_hash(&sha1_tv, "sha1-generic", 0, 0);
	ret += test_hash(&hmac_sha1_tv, "hmac(sha1-generic)", 0, 0);
#endif

#ifdef CONFIG_CRYPTO_SHA1_ARM64_CE
	ret += test_hash(&sha1_tv, "sha1-ce", 0, 0);
	ret += test_hash(&hmac_sha1_tv, "hmac(sha1-ce)", 0, 0);
#endif

#ifdef CONFIG_CRYPTO_SHA256
	ret += test_hash(&sha224_tv, "sha224-generic", 0, 0);
	ret += test_hash(&sha256_tv, "sha256-generic", 0, 0);
	ret += test_hash(&hmac_sha224_tv, "hmac(sha224-generic)", 0, 0);
	ret += test_hash(&hmac_sha256_tv, "hmac(sha256-generic)", 0, 0);
#endif

#ifdef CONFIG_CRYPTO_SHA2_ARM64_CE
	ret += test_hash(&sha224_tv, "sha224-ce", 0, 0);
	ret += test_hash(&sha256_tv, "sha256-ce", 0, 0);
	ret += test_hash(&hmac_sha224_tv, "hmac(sha224-ce)", 0, 0);
	ret += test_hash(&hmac_sha256_tv, "hmac(sha256-ce)", 0, 0);
#endif

#ifdef CONFIG_CRYPTO_SHA512
	ret += test_hash(&sha384_tv, "sha384-generic", 0, 0);
	ret += test_hash(&sha512_tv, "sha512-generic", 0, 0);
	ret += test_hash(&hmac_sha384_tv, "hmac(sha384-generic)", 0, 0);
	ret += test_hash(&hmac_sha512_tv, "hmac(sha512-generic)", 0, 0);
#endif

	return ret;
}
