#include <crypto/aes.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>

#include "fips140.h"
#include "fips140_test.h"

int skc_fips_enabled;
EXPORT_SYMBOL_GPL(skc_fips_enabled);
#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
static int functest_status;
#endif

static int __init fips140_post(void)
{
	int err_kat = -1;
	int err_integrity = -1;

	skc_fips_enabled = 0;

	pr_info("FIPS : POST (%s)\n", SKC_VERSION_TEXT);

	err_kat = fips140_kat();
	err_integrity = do_integrity_check();

	if (err_kat || err_integrity) {
		pr_err("FIPS : POST - one or more selftests failed\n");

#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
		if (functest_status) {
			pr_err("FIPS : POST - bypass panic because of functional test\n");
			return -1;
		}
		panic("FIPS : POST - one or more selftests failed\n");
#else
		panic("FIPS : POST - one or more selftests failed\n");
#endif
	}

	skc_fips_enabled = 1;
	pr_info("FIPS : POST - CRYPTO API started in FIPS approved mode : skc_fips_enabled = %d\n", skc_fips_enabled);

	return 0;
}

// When SKC_FUNC_TEST is defined, this function will be called instead of fips140_post.
// After all tests are done, the normal POST test will start.
#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
static int __init fips140_post_func_test(void)
{
	int i;
	int err = -ENOMEM;
	struct crypto_skcipher *tfm = NULL;

	pr_info("FIPS FUNC : Functional test start\n");

	functest_status = 1;
	for (i = 0; i < SKC_FUNCTEST_KAT_CASE_NUM; i++) {
		set_fips_functest_KAT_mode(i);
		pr_info("FIPS FUNC : --------------------------------------------------\n");
		pr_info("FIPS FUNC : Failure inducement case %d - [%s]\n", i + 1, get_fips_functest_mode());
		pr_info("FIPS FUNC : --------------------------------------------------\n");

		err = fips140_post();

		pr_info("FIPS FUNC : (%d) POST done. SKC module FIPS status : fips140_post() returns %d | %s\n",
			i+1, err, skc_fips_enabled ? "passed" : "failed");
	}
	functest_status = 0;

	for (i = 0; i < SKC_FUNCTEST_CONDITIONAL_CASE_NUM; i++) {
		set_fips_functest_conditional_mode(i);
		pr_info("FIPS FUNC : --------------------------------------------------\n");
		pr_info("FIPS FUNC : Conditional test case %d - [%s]\n", i + 1, get_fips_functest_mode());
		pr_info("FIPS FUNC : --------------------------------------------------\n");

		if (!strcmp("zeroization", get_fips_functest_mode())) {
			uint8_t key[AES_KEYSIZE_256];

			memset(key, 0xFE, AES_KEYSIZE_256);
			tfm = crypto_alloc_skcipher("ecb(aes-ce)", 0, 0);
			if (tfm) {
				crypto_skcipher_setkey(tfm, key, AES_KEYSIZE_256);
				crypto_free_skcipher(tfm);
			}
		}
	}
	set_fips_functest_conditional_mode(-1);

	pr_info("FIPS FUNC : Functional test end\n");
	pr_info("FIPS FUNC : Normal POST start\n");

	return fips140_post();
}
#endif

/*
 * If an init function is provided, an exit function must also be provided
 * to allow module unload.
 */
static void __exit fips140_fini(void) { }

#ifdef CONFIG_CRYPTO_SKC_FIPS_FUNC_TEST
	late_initcall(fips140_post_func_test);
#else
	late_initcall(fips140_post);
#endif
module_exit(fips140_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FIPS140 POST");
