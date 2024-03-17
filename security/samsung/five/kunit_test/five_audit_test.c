#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/fs.h>
#include <linux/task_integrity.h>
#include "five_audit.h"
#include "test_helpers.h"

#define FILE_ADDR 0xABCE

static const uint8_t cause[] = "cause", op[] = "op";

DEFINE_FUNCTION_MOCK_VOID_RETURN(five_audit_msg, PARAMS(struct task_struct *,
		struct file *, const char *, enum task_integrity_value,
		enum task_integrity_value, const char *, int))

DEFINE_FUNCTION_MOCK_VOID_RETURN(call_five_dsms_reset_integrity,
		PARAMS(const char *, int, const char *))

DEFINE_FUNCTION_MOCK_VOID_RETURN(call_five_dsms_sign_err,
		PARAMS(const char *, int))

static void five_audit_info_test(struct kunit *test)
{
	struct file *file;
	int result = 0xab;
	struct task_struct *task = current;

	file = (struct file *)FILE_ADDR;

	KunitReturns(KUNIT_EXPECT_CALL(five_audit_msg(ptr_eq(test, task),
	ptr_eq(test, file), streq(test, op), int_eq(test, INTEGRITY_NONE),
	int_eq(test, INTEGRITY_NONE), streq(test, cause),
	int_eq(test, result))), int_return(test, 0));

	five_audit_info(task, file,
		op, INTEGRITY_NONE, INTEGRITY_NONE, cause, result);
}

static void five_audit_err_test_1(struct kunit *test)
{
	struct file *file;
	struct task_struct *task = current;
	int result = 1;

	file = (struct file *)FILE_ADDR;
	Times(1, KunitReturns(KUNIT_EXPECT_CALL(five_audit_msg(
		ptr_eq(test, task),
		ptr_eq(test, file), streq(test, op),
		int_eq(test, INTEGRITY_NONE), int_eq(test, INTEGRITY_NONE),
		streq(test, cause), int_eq(test, result))),
		int_return(test, 0)));

	Times(0, KunitReturns(KUNIT_EXPECT_CALL(call_five_dsms_reset_integrity(
		any(test), any(test), any(test))), int_return(test, 0)));

	five_audit_err(task, file,
		op, INTEGRITY_NONE, INTEGRITY_NONE, cause, result);
}

static void five_audit_err_test_2(struct kunit *test)
{
	struct file *file;
	struct task_struct *task = current;
	char comm[TASK_COMM_LEN];
	int result = 0;

	file = (struct file *)FILE_ADDR;
	KunitReturns(KUNIT_EXPECT_CALL(five_audit_msg(ptr_eq(test, task),
		ptr_eq(test, file), streq(test, op),
		int_eq(test, INTEGRITY_NONE), int_eq(test, INTEGRITY_NONE),
		streq(test, cause), int_eq(test, result))),
		int_return(test, 0));

	get_task_comm(comm, current);
	KunitReturns(KUNIT_EXPECT_CALL(call_five_dsms_reset_integrity(
		streq(test, comm), int_eq(test, 0), streq(test, op))),
		int_return(test, 0));

	five_audit_err(task, file,
		op, INTEGRITY_NONE, INTEGRITY_NONE, cause, result);
}

static void five_audit_sign_err_test(struct kunit *test)
{
	struct file *file;
	struct task_struct *task = current;
	char comm[TASK_COMM_LEN];
	int result = 0xab;

	file = (struct file *)FILE_ADDR;

	get_task_comm(comm, current);
	KunitReturns(KUNIT_EXPECT_CALL(
		call_five_dsms_sign_err(streq(test, comm),
		int_eq(test, result))), int_return(test, 0));

	five_audit_sign_err(task, file,
		op, INTEGRITY_NONE, INTEGRITY_NONE, cause, result);
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
	KUNIT_CASE(five_audit_info_test),
	KUNIT_CASE(five_audit_err_test_1),
	KUNIT_CASE(five_audit_err_test_2),
	KUNIT_CASE(five_audit_sign_err_test),
	{},
};

static struct kunit_suite security_five_test_module = {
	.name = "five-audit-test",
	.init = security_five_test_init,
	.exit = security_five_test_exit,
	.test_cases = security_five_test_cases,
};

kunit_test_suites(&security_five_test_module);

MODULE_LICENSE("GPL v2");
