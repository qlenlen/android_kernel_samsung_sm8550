#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/uh.h>
#include <linux/nsproxy.h>
#include <linux/security.h>
#include <../../fs/mount.h>
#include <linux/sched/signal.h>

#include <linux/kdp.h>

/* Never enable this flag*/
//#define CONFIG_KDP_SEC_TEST

struct task_security_struct {
	u32 osid;               /* SID prior to last execve */
	u32 sid;                /* current SID */
	u32 exec_sid;           /* exec SID */
	u32 create_sid;         /* fscreate SID */
	u32 keycreate_sid;      /* keycreate SID */
	u32 sockcreate_sid;     /* fscreate SID */
	void *bp_cred;
};

struct test_case {
	int (*fn)(void);
	char *describe;
};

enum __KDP_TEST {
	CMD_ID_CRED = 0,
	CMD_ID_SEC_CONTEXT,
	CMD_ID_NS,
};

#define KDP_PA_READ		0
#define KDP_PA_WRITE	1

/* BUF define */
#define KDP_BUF_SIZE	8192
#define KDP_LINE_MAX	80
static char kdp_test_buf[KDP_BUF_SIZE];
static unsigned long kdp_test_len;

static DEFINE_RAW_SPINLOCK(par_lock);
static u64 *ha1;

static void kdp_print(const char *fmt, ...)
{
	va_list aptr;

	if (kdp_test_len > KDP_BUF_SIZE - KDP_LINE_MAX)
		return;

	va_start(aptr, fmt);
	kdp_test_len += vsprintf(kdp_test_buf + kdp_test_len, fmt, aptr);
	va_end(aptr);
}

static struct vfsmount *get_vfsmnt(struct task_struct *p)
{
	if (!p || !(p->nsproxy) ||
		!(p->nsproxy->mnt_ns) ||
		!(p->nsproxy->mnt_ns->root))
		return NULL;

	return ((struct kdp_mount *)p->nsproxy->mnt_ns->root)->mnt;
}

static bool hyp_check_page_ro(u64 va)
{
	unsigned long flags;
	u64 par = 0;

	raw_spin_lock_irqsave(&par_lock, flags);
	uh_call(UH_APP_KDP, TEST_GET_PAR, (unsigned long)va, KDP_PA_WRITE, 0, 0);
	par = *ha1;
	raw_spin_unlock_irqrestore(&par_lock, flags);

	return (par & 0x1) ? true : false;
}

static int test_case_kdp_ro(int cmd_id)
{
	struct task_struct *p = NULL;
	u64 ro = 0, rw = 0, dst;

	for_each_process(p) {
		switch (cmd_id) {
		case CMD_ID_CRED:
			/* Here dst points to struct cred */
			dst = (u64)__task_cred(p);
			break;
		case CMD_ID_SEC_CONTEXT:
			/* Here dst points to process security context */
			dst = (u64)__task_cred(p)->security;
			break;
		case CMD_ID_NS:
			/* Here dst points to process security context */
			dst = (u64)get_vfsmnt(p);
			break;
		}

		if (!dst)
			continue;

		if (hyp_check_page_ro(dst))
			ro++;
		else
			rw++;
	}

	kdp_print("ro: %llu, rw: %llu\n", ro, rw);
	return rw ? 1 : 0;
}

static int cred_match(struct task_struct *p, const struct cred *cred)
{
	struct mm_struct *mm = p->mm;
	pgd_t *tgt = NULL;

	if (((struct cred_kdp *)cred)->bp_task != p) {
		kdp_print("KDP_WARN task: #%s# cred: %p, task: %p bp_task: %p\n",
					p->comm, cred, p, ((struct cred_kdp *)cred)->bp_task);
		return 0;
	}

	if (!(in_interrupt() || in_softirq()))
		return 1;

	tgt = mm ? mm->pgd : init_mm.pgd;
	if (((struct cred_kdp *)cred)->bp_pgd != tgt) {
		kdp_print("KDP_WARN task: #%s# cred: %p, mm: %p, init_mm: %p, pgd: %p, bp_pgd: %p\n",
					p->comm, cred, mm, init_mm.pgd, tgt, ((struct cred_kdp *)cred)->bp_pgd);
		return 0;
	}

	return 1;
}

static int sec_context_match(const struct cred *cred)
{
	struct task_security_struct *tsec = (struct task_security_struct *)cred->security;

	if ((u64)tsec->bp_cred != (u64)cred)
		return 0;

	return 1;
}

static int test_case_match_bp(int cmd_id)
{
	struct task_struct *p = NULL;
	u64 match = 0, mismatch = 0, ret = 0;

	for_each_process(p) {
		switch (cmd_id) {
		case CMD_ID_CRED:
			/*Here dst points to struct cred*/
			ret = cred_match(p, __task_cred(p));
			break;
		case CMD_ID_SEC_CONTEXT:
			/*Here dst points to process security context*/
			ret = sec_context_match(__task_cred(p));
			break;
		}
		ret ? match++ : mismatch++;
	}
	kdp_print("match: %llu, mismatch: %llu\n", match, mismatch);
	return mismatch ? 1 : 0;
}

static int test_case_cred_ro(void)
{
	kdp_print("CRED PROTECTION ");
	return test_case_kdp_ro(CMD_ID_CRED);
}

static int test_case_sec_context_ro(void)
{
	kdp_print("SECURITY CONTEXT PROTECTION ");
	return test_case_kdp_ro(CMD_ID_SEC_CONTEXT);
}

static int test_case_cred_match_bp(void)
{
	kdp_print("CRED Back Poiner check ");
	return test_case_match_bp(CMD_ID_CRED);
}

static int test_case_sec_context_match_bp(void)
{
	kdp_print("Security Context Back Poiner check ");
	return test_case_match_bp(CMD_ID_SEC_CONTEXT);
}

static int test_case_ns_ro(void)
{
	kdp_print("NAMESPACE PROTECTION ");
	return test_case_kdp_ro(CMD_ID_NS);
}

#ifdef CONFIG_KDP_SEC_TEST
enum {
	CMD_ID_COMMIT_CRED,
	CMD_ID_OVERRIDE_CRED,
	CMD_ID_REVERT_CRED,
};

enum {
	CMD_ID_SEC_WRITE_CRED,
	CMD_ID_SEC_WRITE_SP,
	CMD_ID_SEC_DIRECT_PE,
	CMD_ID_SEC_INDIRECT_PE_COMMIT,
	CMD_ID_SEC_INDIRECT_PE_OVERRIDE,
	CMD_ID_SEC_INDIRECT_PE_REVERT,
};

#define PROCFS_MAX_SIZE	64
void write_ro(u64 *p)
{
	memcpy(p, "c", 1);
}
static void sec_test_cred(void)
{
	write_ro((u64 *)current_cred());
}
static void sec_test_sp(void)
{
	write_ro((u64 *)current_cred()->security);
}

struct cred *get_root_cred(void)
{
	struct cred *cred;

	cred = prepare_creds();
	cred->uid.val  = 0;
	cred->gid.val  = 0;
	cred->euid.val = 0;
	cred->egid.val = 0;

	return cred;
}

static void sec_test_cred_direct_pe(void)
{
	struct cred *rcred;

	rcred = get_root_cred();
	current->cred = rcred;
}

static void sec_test_cred_indirect_pe(int cmd_id)
{
	struct cred *rcred;

	rcred = get_root_cred();
	pr_info("RKP_SEC_TEST #%d# BEFORE current cred uid = %llx euid = %llx gid = %llx egid = %llx Root Cred%llx\n",
			cmd_id, current->cred->uid.val, current->cred->euid.val, current->cred->gid.val,
			current->cred->egid.val, (u64)rcred);

	switch (cmd_id) {
	case CMD_ID_COMMIT_CRED:
		commit_creds(rcred);
		break;
	case CMD_ID_OVERRIDE_CRED:
		override_creds(rcred);
		break;
	case CMD_ID_REVERT_CRED:
		revert_creds(rcred);
	break;
	}

	pr_info("RKP_SEC_TEST#%d# AFTER current cred uid = %llx euid = %llx gid = %llx egid = %llx  Root Cred %llx\n",
			cmd_id, current->cred->uid.val, current->cred->euid.val, current->cred->gid.val,
			current->cred->egid.val, (u64)rcred);
}

ssize_t kdp_test_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset)
{
	char procfs_buffer[PROCFS_MAX_SIZE];
	int buff_size;
	int tcase;

	buff_size = (len > PROCFS_MAX_SIZE)?PROCFS_MAX_SIZE:len;

	if (copy_from_user(procfs_buffer, buffer, buff_size))
		return -EFAULT;

	sscanf(procfs_buffer, "%d", &tcase);
	switch (tcase) {
	case CMD_ID_SEC_WRITE_CRED:
		sec_test_cred();
		break;
	case CMD_ID_SEC_WRITE_SP:
		sec_test_sp();
		break;
	case CMD_ID_SEC_DIRECT_PE:
		sec_test_cred_direct_pe();
		break;
	case CMD_ID_SEC_INDIRECT_PE_COMMIT:
		sec_test_cred_indirect_pe(CMD_ID_COMMIT_CRED);
		break;
	case CMD_ID_SEC_INDIRECT_PE_OVERRIDE:
		sec_test_cred_indirect_pe(CMD_ID_OVERRIDE_CRED);
		break;
	case CMD_ID_SEC_INDIRECT_PE_REVERT:
		sec_test_cred_indirect_pe(CMD_ID_REVERT_CRED);
		break;
	}
	return len;
}
#endif /* CONFIG_KDP_SEC_TEST*/

ssize_t kdp_test_read(struct file *filep, char __user *buffer, size_t count, loff_t *ppos)
{
	int ret = 0, temp_ret = 0, i = 0;
	struct test_case tc_funcs[] = {
		{test_case_cred_ro,		"TEST TASK_CRED_RO"},
		{test_case_sec_context_ro,	"TEST TASK_SECURITY_CONTEXT_RO"},
		{test_case_cred_match_bp,	"TEST CRED_MATCH_BACKPOINTERS"},
		{test_case_sec_context_match_bp,	"TEST TASK_SEC_CONTEXT_BACKPOINTER"},
		{test_case_ns_ro,	"TEST NAMESPACE_RO"},
	};
	int tc_num = sizeof(tc_funcs)/sizeof(struct test_case);

	static bool done;

	if (done)
		return 0;

	done = true;

	for (i = 0; i < tc_num; i++) {
		kdp_print("KDP_TEST_CASE %d ===========> RUNNING %s\n", i, tc_funcs[i].describe);
		temp_ret = tc_funcs[i].fn();

		if (temp_ret) {
			kdp_print("KDP_TEST_CASE %d ===========> %s FAILED WITH %d ERRORS\n",
					i, tc_funcs[i].describe, temp_ret);
		} else {
			kdp_print("KDP_TEST_CASE %d ===========> %s PASSED\n", i, tc_funcs[i].describe);
		}

		ret += temp_ret;
	}

	if (ret)
		kdp_print("KDP_TEST SUMMARY: FAILED WITH %d ERRORS\n", ret);
	else
		kdp_print("KDP_TEST SUMMARY: PASSED\n");

	return simple_read_from_buffer(buffer, count, ppos, kdp_test_buf, kdp_test_len);
}

static const struct proc_ops kdp_proc_ops = {
	.proc_read		= kdp_test_read,
#ifdef CONFIG_KDP_SEC_TEST
	.proc_write		= kdp_test_write,
#endif
};

static int __init kdp_test_init(void)
{
	u64 va;

#ifndef CONFIG_KDP_SEC_TEST
	if (proc_create("kdp_test", 0444, NULL, &kdp_proc_ops) == NULL) {
#else
	if (proc_create("kdp_test", 0777, NULL, &kdp_proc_ops) == NULL) {
#endif
		pr_err("KDP_TEST: Error creating proc entry");
		return -1;
	}

	va = __get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!va)
		return -1;

	uh_call(UH_APP_KDP, TEST_INIT, va, 0, 0, 1);

	ha1 = (u64 *)va;

	return 0;
}

static void __exit kdp_test_exit(void)
{
	uh_call(UH_APP_KDP, TEST_EXIT, (u64)ha1, 0, 0, 0);
	free_page((unsigned long)ha1);

	remove_proc_entry("kdp_test", NULL);
}

module_init(kdp_test_init);
module_exit(kdp_test_exit);
