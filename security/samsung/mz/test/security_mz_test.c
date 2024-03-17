#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/mz.h>

int test_pid = 10;

static void security_mz_add_target_pfn_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

/*	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mzinit());
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_add_target_pfn(test_pid, 99999));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_all_zero_set(test_pid));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_add_target_pfn(test_pid, 100000));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_add_target_pfn(0, 99999));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_add_target_pfn(PRLIMIT, 99999));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_add_target_pfn(test_pid, 0));
	KUNIT_EXPECT_EQ(test, MZ_MALLOC_ERROR, mz_add_target_pfn(MALLOC_FAIL_CUR, 99999));
	KUNIT_EXPECT_EQ(test, MZ_MALLOC_ERROR, mz_add_target_pfn(MALLOC_FAIL_PFN, 99999));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(test_pid));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(MALLOC_FAIL_CUR));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(MALLOC_FAIL_PFN)); //*/
}

static void security_mz_add_new_target_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

/*	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_add_new_target(test_pid));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_add_new_target(0));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_add_new_target(PRLIMIT));
	KUNIT_EXPECT_EQ(test, MZ_MALLOC_ERROR, mz_add_new_target(MALLOC_FAIL_PID));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(test_pid)); //*/
}

static void security_mz_is_mz_target_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

/*	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_add_target_pfn(test_pid, 99999));
	KUNIT_EXPECT_TRUE(test, is_mz_target(test_pid));
	KUNIT_EXPECT_FALSE(test, is_mz_target(999));
	KUNIT_EXPECT_FALSE(test, is_mz_target(0));
	KUNIT_EXPECT_FALSE(test, is_mz_target(PRLIMIT));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(test_pid)); //*/
}

static void security_mz_is_mz_all_zero_target_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

/*	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_all_zero_set(test_pid));
	KUNIT_EXPECT_TRUE(test, is_mz_all_zero_target(test_pid));
	KUNIT_EXPECT_FALSE(test, is_mz_all_zero_target(999));
	KUNIT_EXPECT_FALSE(test, is_mz_all_zero_target(0));
	KUNIT_EXPECT_FALSE(test, is_mz_all_zero_target(PRLIMIT));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(test_pid)); //*/
}

static void security_mz_all_zero_set_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

/*	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_all_zero_set(test_pid));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_all_zero_set(0));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_all_zero_set(PRLIMIT));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(test_pid)); //*/
}

static void security_mz_remove_target_from_all_list_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

/*	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_add_target_pfn(test_pid, 1));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(test_pid));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, remove_target_from_all_list(0));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, remove_target_from_all_list(PRLIMIT)); //*/
}

static void security_mz_exit_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_exit());
}

static void security_mz_util_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

/*	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_kget_process_name(test_pid, NULL));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_kget_process_name(0, NULL));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_kget_process_name(PRLIMIT, NULL));
	KUNIT_EXPECT_NULL(test, findts(0));
	KUNIT_EXPECT_NULL(test, findts(PRLIMIT)); //*/
}

static void security_mz_ioctl_test(struct kunit *test)
{
	pr_info("MZ %s start\n", __func__);

/*	KUNIT_EXPECT_EQ(test, 0, mz_ioctl_init());
	KUNIT_EXPECT_EQ(test, -ENOMEM, mz_ioctl_init());
	KUNIT_EXPECT_EQ(test, 0, mz_ioctl_init());
	KUNIT_EXPECT_EQ(test, MZ_GENERAL_ERROR, mz_ioctl(NULL, IOCTL_MZ_SET_CMD, 0));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, mz_ioctl(NULL, IOCTL_MZ_ALL_SET_CMD, 0));
	KUNIT_EXPECT_EQ(test, MZ_INVALID_INPUT_ERROR, mz_ioctl(NULL, IOCTL_MZ_FAIL_CMD, 0));
	KUNIT_EXPECT_EQ(test, MZ_SUCCESS, remove_target_from_all_list(current->tgid));
	mz_ioctl_exit(); //*/
}

static int security_mz_test_init(struct kunit *test)
{
	return 0;
}

static void security_mz_test_exit(struct kunit *test)
{
	test_pid++;
	if (test_pid >= PRLIMIT)
		test_pid = 10;
}

static struct kunit_case security_mz_test_cases[] = {
	KUNIT_CASE(security_mz_add_target_pfn_test),
	KUNIT_CASE(security_mz_add_new_target_test),
	KUNIT_CASE(security_mz_is_mz_target_test),
	KUNIT_CASE(security_mz_is_mz_all_zero_target_test),
	KUNIT_CASE(security_mz_all_zero_set_test),
	KUNIT_CASE(security_mz_remove_target_from_all_list_test),
	KUNIT_CASE(security_mz_exit_test),
	KUNIT_CASE(security_mz_util_test),
	KUNIT_CASE(security_mz_ioctl_test),
	{},
};

static struct kunit_suite security_mz_test_module = {
	.name = "security-mz-test",
	.init = security_mz_test_init,
	.exit = security_mz_test_exit,
	.test_cases = security_mz_test_cases,
};
kunit_test_suites(&security_mz_test_module);

MODULE_LICENSE("GPL v2");
