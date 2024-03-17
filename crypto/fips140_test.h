#ifndef _CRYPTO_FIPS140_TEST_H
#define _CRYPTO_FIPS140_TEST_H

#include <linux/types.h>

#define FIPS140_MAX_LEN_IV		48
#define FIPS140_MAX_LEN_KEY	132
#define FIPS140_MAX_LEN_DIGEST	64
#define FIPS140_MAX_LEN_PCTEXT	1024
#define FIPS140_MAX_LEN_ENTROPY	48
#define FIPS140_MAX_LEN_STR	128

#define FIPS140_TEST_ENCRYPT 1
#define FIPS140_TEST_DECRYPT 0

#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
void set_fips_functest_KAT_mode(int num);
void set_fips_functest_conditional_mode(int num);
char *get_fips_functest_mode(void);
#define SKC_FUNCTEST_KAT_CASE_NUM 21
#define SKC_FUNCTEST_CONDITIONAL_CASE_NUM 1
#define SKC_FUNCTEST_NO_TEST "NO_TEST"
#endif /* CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST */

struct cipher_testvec {
	const char key[FIPS140_MAX_LEN_KEY];
	const char iv[FIPS140_MAX_LEN_IV];
	const char ptext[FIPS140_MAX_LEN_PCTEXT];
	const char ctext[FIPS140_MAX_LEN_PCTEXT];
	unsigned char klen;
	unsigned char iv_len;
	unsigned short len;
};

struct hash_testvec {
	const char key[FIPS140_MAX_LEN_KEY];
	const char ptext[FIPS140_MAX_LEN_PCTEXT];
	const char digest[FIPS140_MAX_LEN_DIGEST];
	unsigned short plen;
	unsigned short klen;
};

struct cipher_test_suite {
	const struct cipher_testvec *vecs;
	unsigned int tv_count;
};

struct hash_test_suite {
	const struct hash_testvec *vecs;
	unsigned int tv_count;
};

extern int alg_test_fips140(const char *driver, const char *alg);
int fips140_kat(void);

#endif	/* _CRYPTO_FIPS140_TEST_H */
