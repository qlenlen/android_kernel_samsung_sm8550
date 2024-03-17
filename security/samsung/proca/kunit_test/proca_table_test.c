#include "proca_table.h"
#include "test_helpers.h"
#include "proca_test_certificate.h"

static void proca_table_init_test(struct kunit *test)
{
	DECLARE_NEW(test, struct proca_table, pt);

	proca_table_init(pt);

	KUNIT_EXPECT_EQ(test, pt->hash_tables_shift,
			(unsigned int)PROCA_TASKS_TABLE_SHIFT);
}

static void proca_table_get_by_task_test(struct kunit *test)
{
	DECLARE_NEW(test, struct proca_table, pt);
	DECLARE_NEW(test, struct proca_task_descr, descr_put);
	DECLARE_NEW(test, struct proca_task_descr, descr_get);
	DECLARE_NEW(test, struct file, p_file);
	struct proca_certificate parsed_cert;
	int rc;

	descr_put->task = current;

	rc = init_certificate_validation_hash();
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = parse_proca_certificate(pa_cert, sizeof(pa_cert), &parsed_cert);
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = init_proca_identity(&descr_put->proca_identity, p_file,
				 "test", sizeof("test"), &parsed_cert);
	KUNIT_EXPECT_EQ(test, rc, 0);

	proca_table_init(pt);
	proca_table_add_task_descr(pt, descr_put);

	descr_get = proca_table_get_by_task(pt, current);
	KUNIT_EXPECT_PTR_EQ(test, descr_put, descr_get);

	KUNIT_EXPECT_EQ(test, app_name_len,
			descr_get->proca_identity.parsed_cert.app_name_size);
	rc = memcmp(app_name, descr_get->proca_identity.parsed_cert.app_name,
			app_name_len);
	KUNIT_EXPECT_EQ(test, rc, 0);

	KUNIT_EXPECT_EQ(test, sig_hash_len,
		descr_get->proca_identity.parsed_cert.five_signature_hash_size);
	rc = memcmp(sig_hash,
		descr_get->proca_identity.parsed_cert.five_signature_hash,
		sig_hash_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void proca_table_remove_by_task_test(struct kunit *test)
{
	DECLARE_NEW(test, struct proca_table, pt);
	DECLARE_NEW(test, struct proca_task_descr, descr_put);
	DECLARE_NEW(test, struct proca_task_descr, descr_get);

	descr_put->task = current;

	proca_table_init(pt);
	proca_table_add_task_descr(pt, descr_put);

	descr_get = proca_table_remove_by_task(pt, current);
	KUNIT_EXPECT_PTR_EQ(test, descr_put, descr_get);

	descr_get = proca_table_get_by_task(pt, current);
	KUNIT_EXPECT_PTR_EQ(test, descr_get, (struct proca_task_descr *)NULL);
}

static int proca_table_test_init(struct kunit *test)
{
	return 0;
}

static void proca_table_test_exit(struct kunit *test)
{
	return;
}

static struct kunit_case security_proca_table_test_cases[] = {
	KUNIT_CASE(proca_table_init_test),
	KUNIT_CASE(proca_table_get_by_task_test),
	KUNIT_CASE(proca_table_remove_by_task_test),
	{},
};

static struct kunit_suite proca_table_test = {
	.name = "proca-table-test",
	.init = proca_table_test_init,
	.exit = proca_table_test_exit,
	.test_cases = security_proca_table_test_cases,
};

kunit_test_suites(&proca_table_test);
