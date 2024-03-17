#include <kunit/test.h>
#include "five_lv.h"

static uint8_t value_1[] = {0x01, 0x02, 0x03, 0x04, 0x05};
static uint8_t value_2[] = {0x0A, 0x09, 0x08, 0x07, 0x06, 0x07};
static uint8_t value_3[] = {0x0A, 0x09, 0x08, 0x07, 0x06, 0x07, 0x08};

static struct lv *lv_set_and_test(struct kunit *test, struct lv *next,
	uint8_t value[], size_t size, const void *end)
{
	int rc = 0;

	rc = lv_set(next, value, size, end);
	KUNIT_EXPECT_EQ(test, rc, 0);
	next = lv_get_next(next, end);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, next);

	return next;
}

static void lv_test(struct kunit *test)
{
	size_t data_len;
	uint8_t *data;
	struct lv *next;
	const void *end;
	int rc = 0;

	data_len = sizeof(value_1) + sizeof(value_2) + sizeof(value_3) +
		   sizeof(struct lv) * 3;

	data = kunit_kzalloc(test, data_len, GFP_NOFS);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data);

	next = (struct lv *)data;
	end = data + data_len;

	next = lv_set_and_test(test, next, value_1, sizeof(value_1), end);
	next = lv_set_and_test(test, next, value_2, sizeof(value_2), end);

	rc = lv_set(next, value_3, sizeof(value_3), end);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void lv_test_negative(struct kunit *test)
{
	size_t data_len;
	uint8_t *data;
	struct lv *next;
	struct lv *tmp_next;
	const void *end;
	int rc = 0;

	data_len = sizeof(value_1) + sizeof(value_2) + sizeof(value_3) +
		   sizeof(struct lv) * 3 - 1;

	data = kunit_kzalloc(test, data_len, GFP_NOFS);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data);

	next = (struct lv *)data;
	end = data + data_len;

	next = lv_set_and_test(test, next, value_1, sizeof(value_1), end);

	tmp_next = lv_get_next(NULL, end);
	KUNIT_EXPECT_NULL(test, tmp_next);
	tmp_next = lv_get_next(next, NULL);
	KUNIT_EXPECT_NULL(test, tmp_next);
	tmp_next = lv_get_next(NULL, NULL);
	KUNIT_EXPECT_NULL(test, tmp_next);

	rc = lv_set(NULL, value_2, sizeof(value_2), end);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	rc = lv_set(next, value_2, sizeof(value_2), NULL);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	rc = lv_set(next, NULL, sizeof(value_2), end);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	rc = lv_set(next, value_2, data_len + 10, end);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	rc = lv_set(next, value_2, sizeof(value_2), end);
	KUNIT_EXPECT_EQ(test, rc, 0);

	next = lv_get_next(next, end);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, next);
	rc = lv_set(next, value_3, sizeof(value_3), end);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
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
	KUNIT_CASE(lv_test),
	KUNIT_CASE(lv_test_negative),
	{},
};

static struct kunit_suite security_five_test_module = {
	.name = "five-lv-test",
	.init = security_five_test_init,
	.exit = security_five_test_exit,
	.test_cases = security_five_test_cases,
};

kunit_test_suites(&security_five_test_module);

MODULE_LICENSE("GPL v2");
