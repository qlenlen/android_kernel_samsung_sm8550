#ifndef _CRYPTO_FIPS140_H
#define _CRYPTO_FIPS140_H

#include <linux/kernel.h>
#include <linux/module.h>

#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
#include "fips140_test.h"
#endif

#define SKC_VERSION_TEXT "Samsung Kernel Cryptographic Module v2.3"
#define FIPS140_ERR 1
#define FIPS140_NO_ERR 0

#define FIPS_HMAC_SIZE         (32)
#define FIPS_CRYPTO_ADDRS_SIZE (4096)

struct first_last {
	aligned_u64 first;
	aligned_u64 last;
};

extern const volatile uint64_t crypto_buildtime_address;
extern const volatile struct first_last integrity_crypto_addrs[FIPS_CRYPTO_ADDRS_SIZE];
extern const volatile uint8_t buildtime_crypto_hmac[FIPS_HMAC_SIZE];

extern int do_integrity_check(void);

uint32_t skc_is_approved_service(const char *alg_name);
const char *skc_module_get_version(void);

#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
void reset_in_fips_err(void);
#endif /* CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST */

#endif /* _CRYPTO_FIPS140_H */
