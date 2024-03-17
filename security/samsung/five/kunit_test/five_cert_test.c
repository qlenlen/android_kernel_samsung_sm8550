#include <kunit/test.h>
#include <crypto/hash_info.h>
#include "five_cert.h"

const static uint8_t hdr[] = {0x01, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00};
static uint8_t hsh[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13};
static uint8_t lbl[] = {0x01, 0x02, 0x03, 0x04, 0x05};
static uint8_t sgn[] = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01, 0x12,
			0x23, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40};
static uint8_t cert_data[sizeof(hdr) + sizeof(hsh) + sizeof(lbl) +
			 + sizeof(struct lv) * 3] = {0};
static uint8_t cert_data_signed[sizeof(hdr) + sizeof(hsh) + sizeof(lbl) +
			 sizeof(sgn) + sizeof(struct lv) * 4] = {0};
const static uint8_t cert_hash[] = {0xae, 0x72, 0xc3, 0xd6,
			0x7e, 0x47, 0x20, 0x7a, 0xec, 0xdb, 0xd5, 0x90,
			0xcb, 0xd2, 0xe4, 0xbe, 0x92, 0x43, 0xf2, 0x46};

static void five_cert_body_alloc_test(struct kunit *test)
{
	uint8_t *raw_cert;
	size_t raw_cert_len;
	int rc = -1;
	int pos = 0;
	uint16_t size;
	struct five_cert_header header = {
			.version = FIVE_CERT_VERSION1,
			.privilege = FIVE_PRIV_DEFAULT,
			.hash_algo = HASH_ALGO_SHA1,
			.signature_type = FIVE_XATTR_HMAC };

	rc = five_cert_body_alloc(&header, hsh, sizeof(hsh), lbl,
				  sizeof(lbl), &raw_cert, &raw_cert_len);

	size = *((uint16_t *)&raw_cert[pos]);
	KUNIT_EXPECT_EQ(test, size, (uint16_t)sizeof(hdr));
	pos += sizeof(struct lv);
	rc = memcmp(raw_cert + pos, hdr, (uint16_t)sizeof(hdr));
	KUNIT_EXPECT_EQ(test, rc, 0);
	pos += sizeof(hdr);

	size = *((uint16_t *)&raw_cert[pos]);
	KUNIT_EXPECT_EQ(test, size, (uint16_t)sizeof(hsh));
	pos += sizeof(struct lv);
	rc = memcmp(raw_cert + pos, hsh, (uint16_t)sizeof(hsh));
	KUNIT_EXPECT_EQ(test, rc, 0);
	pos += sizeof(hsh);

	size = *((uint16_t *)&raw_cert[pos]);
	KUNIT_EXPECT_EQ(test, size, (uint16_t)sizeof(lbl));
	pos += sizeof(struct lv);
	rc = memcmp(raw_cert + pos, lbl, (uint16_t)sizeof(lbl));
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = five_cert_body_alloc(NULL, hsh, sizeof(hsh), lbl,
				  sizeof(lbl), &raw_cert, &raw_cert_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_body_alloc(&header, hsh, sizeof(hsh), lbl,
				  sizeof(lbl), NULL, &raw_cert_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_body_alloc(&header, hsh, sizeof(hsh), lbl,
				  sizeof(lbl), &raw_cert, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_body_alloc(&header, hsh, FIVE_MAX_CERTIFICATE_SIZE, lbl,
				  sizeof(lbl), &raw_cert, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void five_cert_free_test(struct kunit *test)
{
	uint8_t *raw_cert;

	raw_cert = kzalloc(sizeof(cert_data), GFP_NOFS);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, raw_cert);

	memcpy(raw_cert, cert_data, sizeof(cert_data));

	five_cert_free(raw_cert);

	KUNIT_SUCCEED(test);
}

static void five_cert_append_signature_test(struct kunit *test)
{
	uint8_t *raw_cert;
	size_t raw_cert_len = 0;
	uint8_t signature[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff};
	uint16_t *size;
	int rc = -1;

	raw_cert = kunit_kzalloc(test, sizeof(cert_data), GFP_NOFS);
	KUNIT_ASSERT_NOT_NULL(test, raw_cert);

	memcpy(raw_cert, cert_data, sizeof(cert_data));
	raw_cert_len = sizeof(cert_data);

	rc = five_cert_append_signature((void **)&raw_cert, &raw_cert_len,
					signature, sizeof(signature));

	KUNIT_EXPECT_EQ(test, rc, 0);
	size = (uint16_t *)&raw_cert[sizeof(cert_data)];
	KUNIT_EXPECT_EQ(test, *size, (uint16_t)sizeof(signature));
	rc = memcmp(raw_cert + sizeof(cert_data) + sizeof(struct lv),
		    signature, sizeof(signature));
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = five_cert_append_signature(NULL, &raw_cert_len,
					signature, sizeof(signature));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_append_signature((void **)&raw_cert, NULL,
					signature, sizeof(signature));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_append_signature((void **)&raw_cert, &raw_cert_len,
					NULL, sizeof(signature));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_append_signature((void **)&raw_cert, &raw_cert_len,
					signature, FIVE_MAX_CERTIFICATE_SIZE);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void five_cert_body_fillout_test(struct kunit *test)
{
	struct five_cert_body body_cert = {0};
	struct five_cert_header *header = NULL;
	int rc = -1;

	rc = five_cert_body_fillout(&body_cert, cert_data, sizeof(cert_data));

	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = memcmp(body_cert.header->value, hdr, body_cert.header->length);
	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = memcmp(body_cert.hash->value, hsh, body_cert.hash->length);
	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = memcmp(body_cert.label->value, lbl, body_cert.label->length);
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = five_cert_body_fillout(NULL, cert_data, sizeof(cert_data));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_body_fillout(&body_cert, NULL, sizeof(cert_data));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_body_fillout(&body_cert, cert_data,
					FIVE_MAX_CERTIFICATE_SIZE + 1);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_body_fillout(&body_cert, cert_data, 0);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_body_fillout(&body_cert, cert_data,
					sizeof(cert_data) - 10);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	header = (struct five_cert_header *)body_cert.header->value;
	header->version = FIVE_CERT_VERSION1 + 1;
	rc = five_cert_body_fillout(&body_cert, cert_data, sizeof(cert_data));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	body_cert.header->length = sizeof(*hdr) + 1;
	rc = five_cert_body_fillout(&body_cert, cert_data, sizeof(cert_data));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void five_cert_fillout_test(struct kunit *test)
{
	struct five_cert cert;
	int rc = -1;

	rc = five_cert_fillout(&cert,
				cert_data_signed, sizeof(cert_data_signed));

	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = memcmp(cert.body.header->value, hdr, cert.body.header->length);
	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = memcmp(cert.body.hash->value, hsh, cert.body.hash->length);
	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = memcmp(cert.body.label->value, lbl, cert.body.label->length);
	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = memcmp(cert.signature->value, sgn, cert.signature->length);
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = five_cert_fillout(NULL, cert_data, sizeof(cert_data));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_fillout(&cert, NULL, sizeof(cert_data));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_fillout(&cert, cert_data,
		FIVE_MAX_CERTIFICATE_SIZE + 1);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void five_cert_calc_hash_test(struct kunit *test)
{
	struct five_cert_body body_cert = {0};
	uint8_t out_hash[FIVE_MAX_DIGEST_SIZE] = {0};
	size_t out_hash_len = sizeof(out_hash);
	int rc = -1;

	rc = five_cert_body_fillout(&body_cert, cert_data, sizeof(cert_data));
	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = five_cert_calc_hash(&body_cert, out_hash, &out_hash_len);

	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, out_hash_len, sizeof(cert_hash));

	rc = memcmp(out_hash, cert_hash, out_hash_len);
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = five_cert_calc_hash(NULL, out_hash, &out_hash_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_calc_hash(&body_cert, NULL, &out_hash_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	rc = five_cert_calc_hash(&body_cert, out_hash, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	body_cert.header->length = FIVE_MAX_CERTIFICATE_SIZE + 1;
	rc = five_cert_calc_hash(&body_cert, out_hash, &out_hash_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void init_cert_data(uint8_t *target, const uint8_t *arr,
	uint16_t arrSize, int *pos)
{
	uint16_t *size;

	size = (uint16_t *)&target[*pos];
	*size = arrSize;
	*pos += sizeof(*size);
	memcpy(target + *pos, arr, arrSize);
	*pos += arrSize;
}

static int security_five_test_init(struct kunit *test)
{
	int pos = 0;

	init_cert_data(cert_data, hdr, sizeof(hdr), &pos);
	init_cert_data(cert_data, hsh, sizeof(hsh), &pos);
	init_cert_data(cert_data, lbl, sizeof(lbl), &pos);

	memcpy(cert_data_signed, cert_data, sizeof(cert_data));
	init_cert_data(cert_data_signed, sgn, sizeof(sgn), &pos);

	return 0;
}

static void security_five_test_exit(struct kunit *test)
{
	return;
}

static struct kunit_case security_five_test_cases[] = {
	KUNIT_CASE(five_cert_body_alloc_test),
	KUNIT_CASE(five_cert_free_test),
	KUNIT_CASE(five_cert_body_fillout_test),
	KUNIT_CASE(five_cert_fillout_test),
	KUNIT_CASE(five_cert_append_signature_test),
	KUNIT_CASE(five_cert_calc_hash_test),
	{},
};

static struct kunit_suite security_five_test_module = {
	.name = "five-cert-test",
	.init = security_five_test_init,
	.exit = security_five_test_exit,
	.test_cases = security_five_test_cases,
};

kunit_test_suites(&security_five_test_module);

MODULE_LICENSE("GPL v2");
