/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */
#include <linux/key-type.h>
#include <crypto/public_key.h>
#include <crypto/hash_info.h>
#include "five.h"
#include "five_lv.h"
#include "five_cert.h"
#include "test_helpers.h"

struct key *five_request_asymmetric_key(uint32_t keyid);
int __init five_load_x509_from_mem(const char *data, size_t size);

DEFINE_FUNCTION_MOCK(
	METHOD(call_keyring_search), RETURNS(key_ref_t),
	PARAMS(key_ref_t, struct key_type *, const char *, bool));

DEFINE_FUNCTION_MOCK(
	METHOD(call_request_key), RETURNS(struct key *),
	PARAMS(struct key_type *, const char *, const char *));

DEFINE_FUNCTION_MOCK_VOID_RETURN(
	METHOD(call_key_put), PARAMS(struct key *));

DEFINE_FUNCTION_MOCK(
	METHOD(call_five_verify_signature), RETURNS(int),
	PARAMS(struct key *, struct public_key_signature *,
		struct five_cert *, struct five_cert_header *));

#define DIGEST_SIZE 155
#define VERIFY_SIGNATURE_RET 88
#define KEY_ID 77
#define SIZEOF_FIVE_CERT_HEADER (4 + 4)
#define CORRECT_SIZE	55
#define WRONG_SIZE	0
#define SUCCESS_CODE 0
#define CORRECT_PTR 2
#define WRONG_PTR -2
#define FIVE_KEYRING_ALLOC_PERM_MASK ((KEY_POS_ALL & ~KEY_POS_SETATTR) | \
		     KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH)

extern const char *five_keyring_name;
extern struct key *five_keyring;

// test 'NULL five_keyring' scenario
static void five_keyring_request_asymmetric_key_wo_five_keyring_test(
		struct kunit *test)
{
	struct key *five_keyring_tmp = five_keyring;

	five_keyring = NULL;

	KUNIT_EXPECT_PTR_EQ(test,
		(void *)five_request_asymmetric_key(KEY_ID), ERR_PTR(-ENOKEY));
	KUNIT_EXPECT_PTR_EQ(test,
		(void *)five_request_asymmetric_key(KEY_ID), ERR_PTR(-ENOKEY));
	five_keyring = five_keyring_tmp;
}

// test 'non-NULL five_keyring', 'keyring_search returns error' scenario
static void five_keyring_keyring_search_returns_error_test(
		struct kunit *test)
{
	char name[12];
	struct key foo_keyring;

	five_keyring = &foo_keyring;
	snprintf(name, sizeof(name), "id:%08x", KEY_ID);

	KunitReturns(KUNIT_EXPECT_CALL(call_keyring_search(
		ptr_eq(test, make_key_ref(five_keyring, 1)),
		any(test),
		streq(test, name),
		int_eq(test, true)
		)),
		ptr_return(test, (key_ref_t)WRONG_PTR));

	KUNIT_EXPECT_PTR_EQ(test,
		five_request_asymmetric_key(KEY_ID), (struct key *)WRONG_PTR);
}

// test 'non-NULL five_keyring', 'keyring_search returns specific error' scenario
static void five_keyring_keyring_search_returns_error_eacces_test(
		struct kunit *test)
{
	char name[12];
	struct key foo_keyring;

	five_keyring = &foo_keyring;
	snprintf(name, sizeof(name), "id:%08x", KEY_ID);

	KunitReturns(KUNIT_EXPECT_CALL(call_keyring_search(
		ptr_eq(test, make_key_ref(five_keyring, 1)),
		any(test),
		streq(test, name),
		int_eq(test, true)
		)),
		ptr_return(test, (void *)-EACCES));

	KUNIT_EXPECT_PTR_EQ(test, (void *)five_request_asymmetric_key(KEY_ID),
		(void *)ERR_PTR(-ENOKEY));
}

// test 'non-NULL five_keyring', 'keyring_search returns specific error' scenario
static void five_keyring_keyring_search_returns_error_enotdir_test(
		struct kunit *test)
{
	char name[12];
	struct key foo_keyring;

	five_keyring = &foo_keyring;
	snprintf(name, sizeof(name), "id:%08x", KEY_ID);

	KunitReturns(KUNIT_EXPECT_CALL(call_keyring_search(
		ptr_eq(test, make_key_ref(five_keyring, 1)),
		any(test),
		streq(test, name),
		int_eq(test, true)
		)),
		ptr_return(test, (void *)-ENOTDIR));

	KUNIT_EXPECT_PTR_EQ(test, (void *)five_request_asymmetric_key(KEY_ID),
		(void *)ERR_PTR(-ENOKEY));
}

// test 'non-NULL five_keyring', 'keyring_search returns specific error' scenario
static void five_keyring_keyring_search_returns_error_eagain_test(
		struct kunit *test)
{
	char name[12];
	struct key foo_keyring;

	five_keyring = &foo_keyring;
	snprintf(name, sizeof(name), "id:%08x", KEY_ID);

	KunitReturns(KUNIT_EXPECT_CALL(call_keyring_search(
		ptr_eq(test, make_key_ref(five_keyring, 1)),
		any(test),
		streq(test, name),
		int_eq(test, true)
		)),
		ptr_return(test, (void *)-EAGAIN));

	KUNIT_EXPECT_PTR_EQ(test, (void *)five_request_asymmetric_key(KEY_ID),
		(void *)ERR_PTR(-ENOKEY));
}

static void five_keyring_load_x509_wrong_five_keyring_test(struct kunit *test)
{
	five_keyring = NULL;
	KUNIT_EXPECT_EQ(test,
		five_load_x509_from_mem(NULL, CORRECT_SIZE), -EINVAL);
}

static void five_keyring_load_x509_wrong_size_test(struct kunit *test)
{
	struct key foo_keyring;

	five_keyring = &foo_keyring;
	KUNIT_EXPECT_EQ(test,
		five_load_x509_from_mem(NULL, WRONG_SIZE), -EINVAL);
}

static void five_keyring_request_key_returns_err_test(struct kunit *test)
{
	five_keyring = NULL;
	KunitReturns(KUNIT_EXPECT_CALL(call_request_key(
		any(test),
		streq(test, five_keyring_name),
		ptr_eq(test, NULL)
		)),
		ptr_return(test, (void *)WRONG_PTR));
	KUNIT_EXPECT_EQ(test,
		five_digsig_verify(NULL, NULL, 0), (int)WRONG_PTR);
	KUNIT_EXPECT_PTR_EQ(test, five_keyring, (struct key *)NULL);
}

// test 'request_key returns correct key' and 'wrong_hash_algo' scenario
static void five_keyring_request_key_returns_success_test(
		struct kunit *test)
{
	struct five_cert_header *header;
	struct {
		uint16_t length;
		uint8_t value[SIZEOF_FIVE_CERT_HEADER];
	} __packed header_lv;
	DECLARE_NEW(test, struct five_cert, cert);

	cert->body.header = (struct lv *)&header_lv;
	header = (struct five_cert_header *)cert->body.header->value;
	header->hash_algo = HASH_ALGO__LAST;
	five_keyring = NULL;

	KunitReturns(KUNIT_EXPECT_CALL(call_request_key(
		any(test),
		streq(test, five_keyring_name),
		ptr_eq(test, NULL)
		)),
		ptr_return(test, (void *)CORRECT_PTR));
	KUNIT_EXPECT_EQ(test, five_digsig_verify(cert, NULL, 0), (int)-ENOPKG);
	KUNIT_EXPECT_PTR_EQ(test, five_keyring, (struct key *)CORRECT_PTR);
}

// test 'asymmetric_verify with existing five_keyring' and 'request_asymmetric_key returns error' scenario
static void five_keyring_request_asymmetric_key_return_error_test(
		struct kunit *test)
{
	struct key foo_keyring;
	struct five_cert_header *header;
	struct {
		uint16_t length;
		uint8_t value[SIZEOF_FIVE_CERT_HEADER];
	} __packed header_lv;
	DECLARE_NEW(test, struct five_cert, cert);
	char name[12];

	cert->body.header = (struct lv *)&header_lv;
	header = (struct five_cert_header *)cert->body.header->value;
	header->hash_algo = HASH_ALGO__LAST - 1;
	header->key_id = KEY_ID;
	snprintf(name, sizeof(name), "id:%08x", __be32_to_cpu(header->key_id));
	five_keyring = &foo_keyring;

	KunitReturns(KUNIT_EXPECT_CALL(call_keyring_search(
		ptr_eq(test, make_key_ref(five_keyring, 1)),
		any(test),
		streq(test, name),
		int_eq(test, true)
		)),
		ptr_return(test, (void *)WRONG_PTR));

	KUNIT_EXPECT_EQ(test,
		five_digsig_verify(cert, NULL, 0), (int)WRONG_PTR);
}

// test 'asymmetric_verify with existing five_keyring' and 'request_asymmetric_key returns success' scenario
static void five_keyring_request_asymmetric_key_returns_success_test(
		struct kunit *test)
{
	char digest[] = "didgest";
	struct public_key_signature pks;
	struct key foo_keyring;
	struct five_cert_header *header;
	struct {
		uint16_t length;
		uint8_t value[SIZEOF_FIVE_CERT_HEADER];
	} __packed header_lv;
	DECLARE_NEW(test, struct five_cert, cert);
	char name[12];

	cert->body.header = (struct lv *)&header_lv;
	header = (struct five_cert_header *)cert->body.header->value;
	header->hash_algo = HASH_ALGO__LAST - 1;
	header->key_id = KEY_ID;
	snprintf(name, sizeof(name), "id:%08x", __be32_to_cpu(header->key_id));
	five_keyring = &foo_keyring;
	memset(&pks, 0, sizeof(pks));
	pks.digest = (u8 *)digest;
	pks.digest_size = DIGEST_SIZE;

	KunitReturns(KUNIT_EXPECT_CALL(call_keyring_search(
		ptr_eq(test, make_key_ref(five_keyring, 1)),
		any(test),
		streq(test, name),
		int_eq(test, true)
		)),
		ptr_return(test, (void *)CORRECT_PTR));

	KunitReturns(KUNIT_EXPECT_CALL(call_five_verify_signature(
		ptr_eq(test, (void *)CORRECT_PTR),
		memeq(test, (void *)&pks, sizeof(pks)),
		ptr_eq(test, cert),
		ptr_eq(test, header)
		)),
		int_return(test, VERIFY_SIGNATURE_RET));

	KunitReturns(KUNIT_EXPECT_CALL(call_key_put(
		ptr_eq(test, (void *)CORRECT_PTR))), int_return(test, 0));

	KUNIT_EXPECT_EQ(test, five_digsig_verify(
		cert, digest, DIGEST_SIZE), VERIFY_SIGNATURE_RET);
}

static struct kunit_case five_keyring_test_cases[] = {
	KUNIT_CASE(five_keyring_request_asymmetric_key_wo_five_keyring_test),
	KUNIT_CASE(five_keyring_keyring_search_returns_error_test),
	KUNIT_CASE(five_keyring_keyring_search_returns_error_eacces_test),
	KUNIT_CASE(five_keyring_keyring_search_returns_error_enotdir_test),
	KUNIT_CASE(five_keyring_keyring_search_returns_error_eagain_test),
	KUNIT_CASE(five_keyring_load_x509_wrong_five_keyring_test),
	KUNIT_CASE(five_keyring_load_x509_wrong_size_test),
	KUNIT_CASE(five_keyring_request_key_returns_err_test),
	KUNIT_CASE(five_keyring_request_key_returns_success_test),
	KUNIT_CASE(five_keyring_request_asymmetric_key_return_error_test),
	KUNIT_CASE(five_keyring_request_asymmetric_key_returns_success_test),
	{},
};

static int five_keyring_test_init(struct kunit *test)
{
	return 0;
}

static void five_keyring_test_exit(struct kunit *test)
{
	return;
}

static struct kunit_suite five_keyring_test_module = {
	.name = "five_keyring_test",
	.init = five_keyring_test_init,
	.exit = five_keyring_test_exit,
	.test_cases = five_keyring_test_cases,
};

kunit_test_suites(&five_keyring_test_module);

MODULE_LICENSE("GPL v2");
