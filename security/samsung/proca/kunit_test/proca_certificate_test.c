#include <kunit/test.h>
#include <kunit/mock.h>
#include "proca_certificate.h"
#include "proca_test_certificate.h"
#include "test_helpers.h"

DEFINE_FUNCTION_MOCK(
	METHOD(check_native_pa_id), RETURNS(bool),
	PARAMS(const struct proca_certificate *, struct task_struct *));

static void parse_proca_certificate_test_pos(struct kunit *test)
{
	int rc;
	struct proca_certificate proca_cert;

	proca_cert.app_name_size = 0;
	proca_cert.five_signature_hash_size = 0;

	rc = parse_proca_certificate(pa_cert, sizeof(pa_cert), &proca_cert);

	KUNIT_EXPECT_EQ(test, rc, 0);

	KUNIT_EXPECT_EQ(test, app_name_len, proca_cert.app_name_size);
	rc = memcmp(app_name, proca_cert.app_name, app_name_len);
	KUNIT_EXPECT_EQ(test, rc, 0);

	KUNIT_EXPECT_EQ(test, sig_hash_len, proca_cert.five_signature_hash_size);
	rc = memcmp(sig_hash, proca_cert.five_signature_hash, sig_hash_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void parse_proca_certificate_test(struct kunit *test)
{
	int rc;
	char cert_data[] = "1234abcd";
	struct proca_certificate proca_cert;

	proca_cert.app_name_size = 0;
	proca_cert.five_signature_hash_size = 0;

	rc = parse_proca_certificate(cert_data, sizeof(cert_data), &proca_cert);

	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void compare_with_five_signature_test_pos(struct kunit *test)
{
	int rc;
	struct proca_certificate proca_cert;

	rc = init_certificate_validation_hash();
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = parse_proca_certificate(pa_cert, sizeof(pa_cert), &proca_cert);
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = compare_with_five_signature(&proca_cert, sig_hash, sig_hash_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void compare_with_five_signature_test(struct kunit *test)
{
	int rc;
	struct proca_certificate proca_cert;

	proca_cert.five_signature_hash_size = 123;

	rc = compare_with_five_signature(&proca_cert, NULL, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void is_certificate_relevant_to_task_test(struct kunit *test)
{
	bool rcb;
	int rc;
	struct proca_certificate proca_cert;
	struct task_struct *task = current;

	KunitReturns(KUNIT_EXPECT_CALL(check_native_pa_id(
		any(test), any(test))),
		bool_return(test, 1));

	rc = init_certificate_validation_hash();
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = parse_proca_certificate(pa_cert, sizeof(pa_cert), &proca_cert);
	KUNIT_EXPECT_EQ(test, rc, 0);

	rcb = is_certificate_relevant_to_task(
			&proca_cert,
			task);

	KUNIT_EXPECT_EQ(test, (int)rcb, 1);
}


static int security_proca_test_init(struct kunit *test)
{
	return 0;
}

static void security_proca_test_exit(struct kunit *test)
{
	return;
}

static struct kunit_case security_proca_test_cases[] = {
	KUNIT_CASE(parse_proca_certificate_test),
	KUNIT_CASE(parse_proca_certificate_test_pos),
	KUNIT_CASE(compare_with_five_signature_test_pos),
	KUNIT_CASE(compare_with_five_signature_test),
	KUNIT_CASE(is_certificate_relevant_to_task_test),
	{},
};

static struct kunit_suite proca_certificate_test_module = {
	.name = "proca-certificate-test",
	.init = security_proca_test_init,
	.exit = security_proca_test_exit,
	.test_cases = security_proca_test_cases,
};

kunit_test_suites(&proca_certificate_test_module);

MODULE_LICENSE("GPL v2");
