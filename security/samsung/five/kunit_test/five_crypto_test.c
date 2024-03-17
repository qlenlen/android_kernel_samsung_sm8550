#include <kunit/test.h>
#include <crypto/hash_info.h>
#include <linux/fs.h>
#include "five_crypto.h"
#include "five_file.h"

static uint8_t test_str[] = "hash_test_string";
static uint8_t file_hash_sha512[] = {
			0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
			0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
			0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
			0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
			0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
			0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
			0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
			0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};
static uint8_t file_hash_sha256[] = {
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
static uint8_t file_hash_sha1[] = {
			0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
			0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
			0xaf, 0xd8, 0x07, 0x09};
static uint8_t cert_hash_sha1[] = {
			0x7a, 0x18, 0x6b, 0x28, 0xd2, 0xf8, 0xac, 0x24,
			0xfa, 0x56, 0xa3, 0x5a, 0xe4, 0x81, 0x0d, 0xea,
			0xd4, 0x56, 0x42, 0xe5};
static uint8_t filename[] = "/testfile";

static void five_calc_file_hash_sha1_test(struct kunit *test)
{
	struct file *file;
	uint8_t hash[SHA1_DIGEST_SIZE];
	size_t hash_len = -1;
	int rc = -1;

	file = test_open_file(filename);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	vfs_write(file, test_str, sizeof(test_str), 0);

	rc = five_calc_file_hash(file, HASH_ALGO_SHA1, hash, &hash_len);

	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, hash_len, (size_t)SHA1_DIGEST_SIZE);
	rc = memcmp(hash, file_hash_sha1, SHA1_DIGEST_SIZE);
	test_close_file(file);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void five_calc_file_hash_sha256_test(struct kunit *test)
{
	struct file *file;
	uint8_t hash[SHA256_DIGEST_SIZE];
	size_t hash_len = -1;
	int rc = -1;

	file = test_open_file(filename);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	vfs_write(file, test_str, sizeof(test_str), 0);

	rc = five_calc_file_hash(file, HASH_ALGO_SHA256, hash, &hash_len);

	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, hash_len, (size_t)SHA256_DIGEST_SIZE);
	rc = memcmp(hash, file_hash_sha256, SHA256_DIGEST_SIZE);
	test_close_file(file);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void five_calc_file_hash_sha512_test(struct kunit *test)
{
	struct file *file;
	uint8_t hash[SHA512_DIGEST_SIZE];
	size_t hash_len = -1;
	int rc = -1;

	file = test_open_file(filename);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	vfs_write(file, test_str, sizeof(test_str), 0);

	rc = five_calc_file_hash(file, HASH_ALGO_SHA512, hash, &hash_len);

	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, hash_len, (size_t)SHA512_DIGEST_SIZE);
	rc = memcmp(hash, file_hash_sha512, SHA512_DIGEST_SIZE);
	test_close_file(file);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void five_calc_data_hash_test(struct kunit *test)
{
	uint8_t hash[SHA1_DIGEST_SIZE];
	size_t hash_len = -1;
	int rc = -1;

	rc = five_calc_data_hash(test_str, sizeof(test_str), HASH_ALGO_SHA1,
				 hash, &hash_len);

	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, hash_len, (size_t)SHA1_DIGEST_SIZE);
	rc = memcmp(hash, cert_hash_sha1, SHA1_DIGEST_SIZE);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static int security_five_test_init(struct kunit *test)
{
	return 0;
}

static void security_five_test_exit(struct kunit *test)
{
	return;
}

static struct kunit_case security_five_test_cases[] = {
	KUNIT_CASE(five_calc_file_hash_sha1_test),
	KUNIT_CASE(five_calc_file_hash_sha256_test),
	KUNIT_CASE(five_calc_file_hash_sha512_test),
	KUNIT_CASE(five_calc_data_hash_test),
	{},
};

static struct kunit_suite security_five_test_module = {
	.name = "five-crypto-test",
	.init = security_five_test_init,
	.exit = security_five_test_exit,
	.test_cases = security_five_test_cases,
};

kunit_test_suites(&security_five_test_module);

MODULE_LICENSE("GPL v2");
