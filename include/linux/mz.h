#ifndef _LINUX_MZ_H
#define _LINUX_MZ_H

#include <asm/page.h>
#include <asm/tlb.h>

#include <linux/list.h>
#include <linux/sched.h>

#if defined(MEZ_KUNIT_ENABLED)
#include <kunit/mock.h>
#endif /* !defined(MEZ_KUNIT_ENABLED) */

#define MZ_PAGE_POISON 0x53
#define PRLIMIT 32768
#define MZ_APP_KEY_SIZE 32
#define PFN_BYTE_LEN 32
#define MZ_TA_SUCCESS 1
#define MAX_PROCESS_NAME 256
#define RAND_SIZE 32

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

typedef enum {
	MZ_SUCCESS = 1,   //!< The operation is completed successfully
	MZ_GENERAL_ERROR = 0,   //!< Common error
	MZ_MALLOC_ERROR = -1,
	MZ_IOCTL_OPEN_ERROR = -2,
	MZ_INVALID_INPUT_ERROR = -3,
	MZ_TA_FAIL = -4, //!< It mean this is target but ta work fail
	MZ_NO_TARGET = -5,
	MZ_DRIVER_FAIL = -6,
	MZ_PROC_NAME_GET_ERROR = -7,
	MZ_GET_TS_ERROR = -8,
	MZ_LOCK_FAIL = -9,
	MZ_PAGE_FAIL = -10,
	MZ_CRYPTO_FAIL = -11,
} MzResult;

MzResult mzinit(void);
MzResult mz_add_target_pfn(pid_t tgid, unsigned long pfn, unsigned long offset,
							unsigned long len, unsigned long va, uint8_t __user *buf);
MzResult mz_all_zero_set(pid_t tgid);
MzResult mz_exit(void);
MzResult mz_kget_process_name(pid_t tgid, char *name);

MzResult mz_wb_encrypt(uint8_t *pt, uint8_t *ct);

bool isaddrset(void);

int mz_addr_init(void);
int set_mz_mem(void);

typedef struct pfn_node_encrypted_t {
	u8 pfn[PFN_BYTE_LEN];
	int pa_index;
	struct list_head list;
} pfn_node_encrypted;

typedef struct page_node_t {
	struct page **mz_page;
	struct list_head list;
} page_node;

typedef struct mztarget_t {
	bool target;
	struct list_head mz_list_head_crypto;
	struct list_head mz_list_head_page;
	bool is_ta_fail_target;
} mztarget_s;

extern struct mutex crypto_list_lock;
extern struct mutex page_list_lock;

typedef struct vainfo_t {
	uint64_t va;
	uint64_t len;
	uint8_t __user *buf;
} vainfo;

typedef struct pid_node_t {
	pid_t tgid;
	struct list_head list;
} pid_node;

static LIST_HEAD(pid_list);

#define IOC_MAGIC 'S'
#define IOCTL_MZ_SET_CMD _IOWR(IOC_MAGIC, 1, struct vainfo_t)
#define IOCTL_MZ_ALL_SET_CMD _IOWR(IOC_MAGIC, 2, struct vainfo_t)

struct mz_tee_driver_fns {
	MzResult (*encrypt)(uint8_t *pt, uint8_t *ct, uint8_t *iv);
};
MzResult register_mz_tee_crypto_driver(
		struct mz_tee_driver_fns *tee_driver_fns);
void unregister_mz_tee_crypto_driver(void);

extern struct mztarget_t mz_pt_list[PRLIMIT];
extern uint64_t *addr_list;
extern int addr_list_count_max;

extern MzResult (*load_trusted_app)(void);
extern void (*unload_trusted_app)(void);

#ifdef MEZ_KUNIT_ENABLED
#define MALLOC_FAIL_CUR 2
#define MALLOC_FAIL_PFN 3
#define MALLOC_FAIL_PID 4
#define PANIC_FAIL_PID 5
__visible_for_testing MzResult mz_add_new_target(pid_t tgid);
__visible_for_testing bool is_mz_target(pid_t tgid);
__visible_for_testing bool is_mz_all_zero_target(pid_t tgid);
__visible_for_testing MzResult remove_target_from_all_list(pid_t tgid);
__visible_for_testing struct task_struct *findts(pid_t tgid);
__visible_for_testing long mz_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int mz_ioctl_init(void);
void mz_ioctl_exit(void);
#define IOCTL_MZ_FAIL_CMD _IOWR(IOC_MAGIC, 0, struct vainfo_t)
#else
#ifndef __visible_for_testing
#define __visible_for_testing static
#endif
#endif /* MEZ_KUNIT_ENABLED */

#endif /* _LINUX_MZ_H */
