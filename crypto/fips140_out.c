#include "fips140.h"

__section(".rodata")
const volatile uint8_t buildtime_crypto_hmac[FIPS_HMAC_SIZE] = {0};

__section(".rodata")
const volatile struct first_last integrity_crypto_addrs[FIPS_CRYPTO_ADDRS_SIZE] = {{0},};

__section(".rodata")
const volatile uint64_t crypto_buildtime_address = 10;
