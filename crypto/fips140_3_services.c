//
// In Samsung R&D Institute Ukraine, LLC (SRUKR) under a contract between
// Samsung R&D Institute Ukraine, LLC (Kyiv, Ukraine)
// and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
// Copyright: (c) Samsung Electronics Co, Ltd 2023. All rights reserved.
//

#include <linux/kernel.h>
#include "fips140.h"

static const char * const approved_algs[] = {
	"cbc(aes-generic)",
	"ecb(aes-generic)",
	"hmac(sha1-generic)",
	"hmac(sha224-generic)",
	"hmac(sha256-generic)",
	"hmac(sha384-generic)",
	"hmac(sha512-generic)",
	"sha1-generic",
	"sha224-generic",
	"sha256-generic",
	"sha384-generic",
	"sha512-generic",
	"ecb(aes-ce)",
	"cbc(aes-ce)",
	"hmac(sha1-ce)",
	"hmac(sha224-ce)",
	"hmac(sha256-ce)",
	"sha1-ce",
	"sha224-ce",
	"sha256-ce",
};

uint32_t skc_is_approved_service(const char *alg_name)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(approved_algs); ++i) {
		if (!strcmp(alg_name, approved_algs[i]))
			return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(skc_is_approved_service);

const char *skc_module_get_version(void)
{
	return SKC_VERSION_TEXT;
}
EXPORT_SYMBOL_GPL(skc_module_get_version);
