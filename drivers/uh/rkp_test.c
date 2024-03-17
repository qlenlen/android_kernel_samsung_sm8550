#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/rkp.h>

/*
 * BIT[0:1]	TYPE	PXN BIT
 * 01		BLOCK	53	For LEVEL 0, 1, 2 //defined by L012_BLOCK_PXN
 * 11		TABLE	59	For LEVEL 0, 1, 2 //defined by L012_TABLE_PXN
 * 11		PAGE	53	For LEVEL 3       //defined by L3_PAGE_PXN
 */
#define L012_BLOCK_PXN (_AT(pmdval_t, 1) << 53)
#define L012_TABLE_PXN (_AT(pmdval_t, 1) << 59)
#define L3_PAGE_PXN    (_AT(pmdval_t, 1) << 53)

#define MEM_END		0xfffffffffffff000 /* 4K aligned */
#define DESC_MASK	0xFFFFFFFFF000

#define RKP_PA_READ	0
#define RKP_PA_WRITE	1

/* BUF define */
#define RKP_BUF_SIZE	8192
#define RKP_LINE_MAX	80

/* FIMC */
#define CDH_SIZE		SZ_128K		/* CDH : Camera Debug Helper */
#define IS_RCHECKER_SIZE_RO	(SZ_4M + SZ_1M)
#define IS_RCHECKER_SIZE_RW	(SZ_256K)
#define RCHECKER_SIZE	(IS_RCHECKER_SIZE_RO + IS_RCHECKER_SIZE_RW)

#ifdef CONFIG_KASAN
#define LIB_OFFSET		(VMALLOC_START + 0xF6000000 - 0x8000000)
#else
#define LIB_OFFSET		(VMALLOC_START + 0x1000000000UL + 0xF6000000 - 0x8000000)
#endif

#define __LIB_START		(LIB_OFFSET + 0x04000000 - CDH_SIZE)
#define LIB_START		(__LIB_START)

#define VRA_LIB_ADDR	(LIB_START + CDH_SIZE)
#define VRA_LIB_SIZE	(SZ_512K + SZ_256K)

#define DDK_LIB_ADDR	(LIB_START + VRA_LIB_SIZE + CDH_SIZE)
#define DDK_LIB_SIZE	((SZ_2M + SZ_1M + SZ_256K) + SZ_1M + RCHECKER_SIZE)

#define RTA_LIB_ADDR	(LIB_START + VRA_LIB_SIZE + DDK_LIB_SIZE + CDH_SIZE)
#define RTA_LIB_SIZE	(SZ_2M + SZ_2M)

#define VRA_CODE_SIZE	SZ_512K
#define VRA_DATA_SIZE	SZ_256K

#define DDK_CODE_SIZE	(SZ_2M + SZ_1M + SZ_256K + IS_RCHECKER_SIZE_RO)
#define DDK_DATA_SIZE	SZ_1M

#define RTA_CODE_SIZE	SZ_2M
#define RTA_DATA_SIZE	SZ_2M

#define LIB_END			(RTA_LIB_ADDR + RTA_CODE_SIZE + RTA_DATA_SIZE)

static char rkp_test_buf[RKP_BUF_SIZE];
static unsigned long rkp_test_len = 0;
static unsigned long prot_user_l2 = 1;

static DEFINE_RAW_SPINLOCK(par_lock);
static u64 *ha1;
static u64 *ha2;

struct test_data {
	u64 iter;
	u64 pxn;
	u64 no_pxn;
	u64 read;
	u64 write;
	u64 cred_bkptr_match;
	u64 cred_bkptr_mismatch;
};

static void buf_print(const char *fmt, ...)
{
	va_list aptr;

	if (rkp_test_len > RKP_BUF_SIZE - RKP_LINE_MAX) {
		pr_err("RKP_TEST: Error Maximum buf");
		return;
	}
	va_start(aptr, fmt);
	rkp_test_len += vsprintf(rkp_test_buf+rkp_test_len, fmt, aptr);
	va_end(aptr);
}

//if RO, return true; RW return false
static bool hyp_check_page_ro(u64 va)
{
	unsigned long flags;
	u64 par = 0;

	raw_spin_lock_irqsave(&par_lock, flags);
	uh_call(UH_APP_RKP, RKP_TEST_GET_PAR, (unsigned long)va, RKP_PA_WRITE, 0, 0);
	par = *ha1;
	raw_spin_unlock_irqrestore(&par_lock, flags);

	return (par & 0x1) ? true : false;
}

static void hyp_check_l23pgt_rw(u64 *pg_l, unsigned int level, struct test_data *test)
{
	unsigned int i;

	// Level is 1 2
	if (level >= 3)
		return;

	for (i = 0; i < 512; i++) {
		if ((pg_l[i] & 3) == 3) {
			test[level].iter++;
			if (hyp_check_page_ro((u64)phys_to_virt(pg_l[i] & DESC_MASK)))
				test[level].read++;
			else
				test[level].write++;

			hyp_check_l23pgt_rw((u64 *) (phys_to_virt(pg_l[i] & DESC_MASK)), level + 1, test);
		}
	}
}

static pmd_t *get_addr_pmd(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd))
		return NULL;

	pud = pud_offset((p4d_t *)pgd, addr);
	if (pud_none(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	return pmd;
}

static int test_case_user_pgtable_ro(void)
{
	struct task_struct *task;
	struct test_data test[3] = {{0}, {0}, {0} };
	struct mm_struct *mm = NULL;
	int i;

	for_each_process(task) {
		mm = task->active_mm;
		if (!(mm) || !(mm->context.id.counter) || !(mm->pgd))
			continue;

		if (hyp_check_page_ro((u64)(mm->pgd)))
			test[0].read++;
		else
			test[0].write++;

		test[0].iter++;
		hyp_check_l23pgt_rw(((u64 *) (mm->pgd)), 1, test);
	}

	for (i = 0; i < 3; i++) {
		buf_print("\t\tL%d TOTAL PAGES %6llu | READ ONLY %6llu | WRITABLE %6llu\n",
			i+1, test[i].iter, test[i].read, test[i].write);
	}

	//L1 and L2 pgtable should be RO
	if ((!prot_user_l2) && (test[0].write == 0))
		return 0;

	if ((test[0].write == 0) && (test[1].write == 0))
		return 0; //pass
	else
		return 1; //fail
}

static int test_case_kernel_pgtable_ro(void)
{
	struct test_data test[3] = {{0}, {0}, {0} };
	int i = 0;
	// Check for swapper_pg_dir
	test[0].iter++;
	if (hyp_check_page_ro((u64)swapper_pg_dir))
		test[0].read++;
	else
		test[0].write++;

	hyp_check_l23pgt_rw((u64 *)swapper_pg_dir, 1, test);

	for (i = 0; i < 3; i++)
		buf_print("\t\tL%d TOTAL PAGE TABLES %6llu | READ ONLY %6llu |WRITABLE %6llu\n",
			i+1, test[i].iter, test[i].read, test[i].write);

	if ((test[0].write == 0) && (test[1].write == 0))
		return 0;
	else
		return 1;
}

static int test_case_kernel_l3pgt_ro(void)
{
	int rw = 0, ro = 0, i = 0;
	u64 addrs[] = {
		(u64)_text,
		(u64)_etext
	};
	int len = sizeof(addrs)/sizeof(u64);

	pmd_t *pmd;
	u64 pgt_addr;

	for (i = 0; i < len; i++) {
		pmd = get_addr_pmd(&init_mm, addrs[i]);

		pgt_addr = (u64)phys_to_virt(((u64)(pmd_val(*pmd))) & DESC_MASK);
		if (hyp_check_page_ro(pgt_addr))
			ro++;
		else
			rw++;
	}

	buf_print("\t\tKERNEL TEXT HEAD TAIL L3PGT | RO %6u | RW %6u\n", ro, rw);
	return (rw == 0) ? 0 : 1;
}

// return true if addr mapped, otherwise return false
static bool page_pxn_set(unsigned long addr, u64 *xn, u64 *x, u64 *v_x)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd))
		return false;

	pud = pud_offset((p4d_t *)pgd, addr);
	if (pud_none(*pud))
		return false;

	if (pud_sect(*pud)) {
		if ((pud_val(*pud) & L012_BLOCK_PXN) > 0)
			*xn += 1;
		else
			*x += 1;
		return true;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return false;

	if (pmd_sect(*pmd)) {
		if ((pmd_val(*pmd) & L012_BLOCK_PXN) > 0)
			*xn += 1;
		else
			*x += 1;
		return true;
	}

	if ((pmd_val(*pmd) & L012_TABLE_PXN) > 0) {
		*xn += 1;
		return true;
	}

	// If pmd is table, such as kernel text head and tail, need to check L3
	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return false;

	if ((pte_val(*pte) & L3_PAGE_PXN) > 0)
		*xn += 1;
	else {
		if (addr >= (u64)__end_rodata) {
			u64 res = 0;
			uh_call(UH_APP_RKP, RKP_TEST_TEXT_VALID, addr, (u64)&res, 0, 0);
			if (res)
				*v_x += 1;
		}
		*x += 1;
	}
	return true;
}

static void count_pxn(unsigned long pxn, int level, struct test_data *test)
{
	test[level].iter++;
	if (pxn)
		test[level].pxn++;
	else
		test[level].no_pxn++;
}

static void walk_pte(pmd_t *pmd, int level, struct test_data *test)
{
	pte_t *pte = pte_offset_kernel(pmd, 0UL);
	unsigned int i;
	unsigned long prot;

	for (i = 0; i < PTRS_PER_PTE; i++, pte++) {
		if (pte_none(*pte)) {
			continue;
		} else {
			prot = pte_val(*pte) & L3_PAGE_PXN;
			count_pxn(prot, level, test);
		}
	}
}

static void walk_pmd(pud_t *pud, int level, struct test_data *test)
{
	pmd_t *pmd = pmd_offset(pud, 0UL);
	unsigned int i;
	unsigned long prot;

	for (i = 0; i < PTRS_PER_PMD; i++, pmd++) {
		if (pmd_none(*pmd)) {
			continue;
		} else if (pmd_sect(*pmd)) {
			prot = pmd_val(*pmd) & L012_BLOCK_PXN;
			count_pxn(prot, level, test);
		} else {
		/*
		 * For user space, all L2 should have PXN, including block and
		 * table. Only kernel text head and tail L2 table can have no
		 * pxn, and kernel text middle L2 blocks can have no pxn
		 */
			BUG_ON(pmd_bad(*pmd));
			prot = pmd_val(*pmd) & L012_TABLE_PXN;
			count_pxn(prot, level, test);
			walk_pte(pmd, level+1, test);
		}
	}
}

static void walk_pud(pgd_t *pgd, int level, struct test_data *test)
{
	pud_t *pud = pud_offset((p4d_t *)pgd, 0UL);
	unsigned int i;

	for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
		if (pud_none(*pud) || pud_sect(*pud)) {
			continue;
		} else {
			BUG_ON(pud_bad(*pud));
			walk_pmd(pud, level, test);
		}
	}
}

#define rkp_pgd_table		(_AT(pgdval_t, 1) << 1)
#define rkp_pgd_bad(pgd)	(!(pgd_val(pgd) & rkp_pgd_table))
static void walk_pgd(struct mm_struct *mm, int level, struct test_data *test)
{
	pgd_t *pgd = pgd_offset(mm, 0UL);
	unsigned int i;
	unsigned long prot;

	for (i = 0; i < PTRS_PER_PGD; i++, pgd++) {
		if (rkp_pgd_bad(*pgd)) {
			continue;
		} else { //table
			prot = pgd_val(*pgd) & L012_TABLE_PXN;
			count_pxn(prot, level, test);
			walk_pud(pgd, level+1, test);
		}
	}
}

static int test_case_user_pxn(void)
{
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	struct test_data test[3] = {{0}, {0}, {0} };
	int i = 0;

	for_each_process(task) {
		mm = task->active_mm;
		if (!(mm) || !(mm->context.id.counter) || !(mm->pgd))
			continue;

		/* Check if PXN bit is set */
		walk_pgd(mm, 0, test);
	}

	for (i = 0; i < 3; i++) {
		buf_print("\t\tL%d TOTAL ENTRIES %6llu | PXN %6llu | NO_PXN %6llu\n",
			i+1, test[i].iter, test[i].pxn, test[i].no_pxn);
	}

	//all 2nd level entries should be PXN
	if (test[0].no_pxn == 0) {
		prot_user_l2 = 0;
		return 0;
	} else if (test[1].no_pxn == 0) {
		prot_user_l2 = 1;
		return 0;
	} else {
		return 1;
	}
}

struct mem_range {
	u64 start_va;
	u64 size; //in bytes
	char *info;
	bool no_rw;
	bool no_x;
};

struct test_case {
	int (*fn)(void);
	char *describe;
};

static int test_case_kernel_range_rwx(void)
{
	int ret = 0;
	u64 ro = 0, rw = 0;
	u64 xn = 0, x = 0;
	u64 v_x = 0;
	int i;
	u64 j;
	bool mapped = false;
	u64 va_temp;

	struct mem_range test_ranges[] = {
		{(u64)VMALLOC_START, ((u64)_text) - ((u64)VMALLOC_START), "VMALLOC -  STEXT", false, true},
		{((u64)_text), ((u64)_etext) - ((u64)_text), "STEXT - ETEXT", true, false},
		{((u64)_etext), ((u64) __end_rodata) - ((u64)_etext), "ETEXT - ERODATA", true, true},
#ifdef CONFIG_USE_DIRECT_IS_CONTROL /* FIMC */
		{((u64) __end_rodata), VRA_LIB_ADDR-((u64) __end_rodata), "ERODATA - S_FIMC", false, true},
		{VRA_LIB_ADDR, VRA_CODE_SIZE, "VRA CODE", true, false},
		{VRA_LIB_ADDR + VRA_CODE_SIZE, VRA_DATA_SIZE, "VRA DATA", false, true},
		{DDK_LIB_ADDR, DDK_CODE_SIZE, "DDK CODE", true, false},
		{DDK_LIB_ADDR + DDK_CODE_SIZE, DDK_DATA_SIZE, "DDK_DATA", false, true},
		{RTA_LIB_ADDR, RTA_CODE_SIZE, "RTA CODE", true, false},
		{RTA_LIB_ADDR + RTA_CODE_SIZE, RTA_DATA_SIZE, "RTA DATA", false, true},
		{LIB_END, MEM_END - LIB_END, "E_FIMC - MEM END", false, true},
#else
		{((u64) __end_rodata), MEM_END-((u64) __end_rodata), "ERODATA -MEM_END", false, true},
#endif

	};
	int len = sizeof(test_ranges)/sizeof(struct mem_range);

	buf_print("\t\t| MEMORY RANGES  | %16s - %16s | %8s %8s %8s %8s\n",
		"START", "END", "RO", "RW", "PXN", "PX");
	for (i = 0; i < len; i++) {
		for (j = 0; j < test_ranges[i].size/PAGE_SIZE; j++) {
			va_temp = test_ranges[i].start_va + j*PAGE_SIZE;
			mapped = page_pxn_set(va_temp, &xn, &x, &v_x);
			if (!mapped)
				continue;
			// only for mapped pages
			if (hyp_check_page_ro(va_temp))
				ro += 1;
			else
				rw += 1;
		}

		buf_print("\t\t|%s| %016llx - %016llx | %8llu %8llu %8llu %8llu\n",
			test_ranges[i].info, test_ranges[i].start_va,
			test_ranges[i].start_va + test_ranges[i].size,
			ro, rw, xn, x);

		if (test_ranges[i].no_rw && (rw != 0)) {
			buf_print("RKP_TEST FAILED, NO RW PAGE ALLOWED, rw=%llu\n", rw);
			ret++;
		}

		if (test_ranges[i].no_x && (x != 0)) {
			if (x == v_x)
				break;
			buf_print("RKP_TEST FAILED, NO X PAGE ALLOWED, x=%llu\n", x);
			ret++;
		}

		if ((rw != 0) && (x != 0)) {
			if (x == v_x)
				break;
			buf_print("RKP_TEST FAILED, NO RWX PAGE ALLOWED, rw=%llu, x=%llu\n", rw, x);
			ret++;
		}

		ro = 0; rw = 0;
		xn = 0; x = 0;
		v_x = 0;
	}

	return ret;
}

ssize_t	rkp_read(struct file *filep, char __user *buffer, size_t count, loff_t *ppos)
{
	int ret = 0, temp_ret = 0, i = 0;
	struct test_case tc_funcs[] = {
		{test_case_user_pxn,		"TEST USER_PXN"},
		{test_case_user_pgtable_ro,	"TEST USER_PGTABLE_RO"},
		{test_case_kernel_pgtable_ro,	"TEST KERNEL_PGTABLE_RO"},
		{test_case_kernel_l3pgt_ro,	"TEST KERNEL TEXT HEAD TAIL L3PGT RO"},
		{test_case_kernel_range_rwx,	"TEST KERNEL_RANGE_RWX"},
	};
	int tc_num = sizeof(tc_funcs)/sizeof(struct test_case);

	static bool done = false;

	if (done)
		return 0;
	done = true;

	if ((!ha1) || (!ha2)) {
		buf_print("ERROR RKP_TEST ha1 is NULL\n");
		goto error;
	}

	for (i = 0; i < tc_num; i++) {
		buf_print("RKP_TEST_CASE %d ===========> RUNNING %s\n", i, tc_funcs[i].describe);
		temp_ret = tc_funcs[i].fn();

		if (temp_ret) {
			buf_print("RKP_TEST_CASE %d ===========> %s FAILED WITH %d ERRORS\n",
				i, tc_funcs[i].describe, temp_ret);
		} else {
			buf_print("RKP_TEST_CASE %d ===========> %s PASSED\n", i, tc_funcs[i].describe);
		}

		ret += temp_ret;
	}

	if (ret)
		buf_print("RKP_TEST SUMMARY: FAILED WITH %d ERRORS\n", ret);
	else
		buf_print("RKP_TEST SUMMARY: PASSED\n");

error:
	return simple_read_from_buffer(buffer, count, ppos, rkp_test_buf, rkp_test_len);
}

static const struct proc_ops rkp_proc_fops = {
	.proc_read	= rkp_read,
};

static int __init rkp_test_init(void)
{
	u64 va;

	if (proc_create("rkp_test", 0444, NULL, &rkp_proc_fops) == NULL) {
		pr_err("RKP_TEST: Error creating proc entry");
		return -1;
	}

	va = __get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!va)
		return -1;
	uh_call(UH_APP_RKP, RKP_TEST_INIT, va, 0, 0, 0);

	ha1 = (u64 *)va;
	ha2 = (u64 *)(va + 8);

	return 0;
}

static void __exit rkp_test_exit(void)
{
	uh_call(UH_APP_RKP, RKP_TEST_EXIT, (u64)ha1, 0, 0, 0);
	free_page((unsigned long)ha1);

	remove_proc_entry("rkp_test", NULL);
}

module_init(rkp_test_init);
module_exit(rkp_test_exit);

