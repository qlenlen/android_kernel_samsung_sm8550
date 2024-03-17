/*
 * dd_common.h
 *
 *  Created on: Oct 3, 2018
 *      Author: olic.moon
 */

#ifndef SECURITY_DDAR_DD_COMMON_H_
#define SECURITY_DDAR_DD_COMMON_H_

#include <ddar/dd.h>
#include <linux/jiffies.h>
#include <linux/ratelimit.h>

typedef enum {
	DD_REQ_INIT = 0,
	DD_REQ_PENDING,
	DD_REQ_PROCESSING,
	DD_REQ_SUBMITTED,
	DD_REQ_FINISHING,
	DD_REQ_UNALLOCATED,
	DD_REQ_COUNT
} dd_req_state_t;

struct dd_benchmark_result {
	unsigned long count;
	struct ratelimit_state ratelimit_state;
	long data[DD_REQ_COUNT];

	spinlock_t lock;
};

struct dd_benchmark {
	struct timespec64 stage[DD_REQ_COUNT];
};

struct dd_context {
	char name[10];	// Informational name

	/**
	 * Protects dd_context resources
	 * - req_ctr: req counter
	 * - procs: process list
	 * - dd_proc allocation and free
	 */
	spinlock_t lock;
	spinlock_t ctr_lock; // lock for req counter
	int req_ctr; // counter for request unique number

	struct list_head procs;	// Process list

	struct dd_mmap_layout *layout;

	struct mutex bio_alloc_lock;
	struct bio_set *bio_set;
	mempool_t *page_pool;

	struct dd_benchmark_result bm_result;
};

struct dd_context *dd_get_global_context(void);

struct dd_proc {
	/**
	 * Protect dd_proc attributes
	 * - pending/processing lists
	 */
	spinlock_t lock;
	atomic_t reqcount;  // free the object when this becomes 0

	int abort;
	wait_queue_head_t waitq;

	pid_t pid;
	pid_t tgid;
	struct dd_context *context;

	struct list_head proc_node; // list held in dd_context.procs

	struct list_head pending; // pending requests
	struct list_head processing; // processing requests
	struct list_head submitted; // submitted requests

	int num_control_page;
	struct page *control_page[MAX_NUM_CONTROL_PAGE];

	struct vm_area_struct *control_vma;
	struct vm_area_struct *metadata_vma;
	struct vm_area_struct *plaintext_vma;
	struct vm_area_struct *ciphertext_vma;
};

#define CONFIG_DD_REQ_DEBUG 1

struct dd_req {
	struct dd_context *context;
	unsigned unique; // unique request id
	dd_request_code_t code;
	unsigned char dir;
	struct list_head list;
	int user_space_crypto;

	int abort;
	int need_xattr_flush;

	dd_req_state_t state;
	wait_queue_head_t waitq;

#if CONFIG_DD_REQ_DEBUG
	struct list_head debug_list;
#endif
	unsigned long timestamp;

	struct dd_info *info;
	unsigned long ino;
	pid_t pid;
	pid_t tgid;

	union {
		struct {
			struct page *metadata;
		} prepare;

		struct {
			dd_crypto_direction_t dir;
			struct page *src_page;
			struct page *dst_page;
		} page;

		struct {
			struct bio *orig;
			struct bio *clone;
		} bio;
	} u;

	struct work_struct decryption_work;
	struct work_struct delayed_free_work;

	struct dd_benchmark bm;
};

#define nsec(t) (t.tv_sec * 1000000000 + t.tv_nsec)

static inline void dd_req_state(struct dd_req *req, dd_req_state_t state)
{
	if (dd_debug_bit_test(DD_DEBUG_BENCHMARK)) {

		if (state == DD_REQ_INIT)
			memset((void *)&req->bm, 0, sizeof(struct dd_benchmark));

		ktime_get_real_ts64(&req->bm.stage[state]);
	}

	req->state = state;
}

static inline void dd_submit_benchmark(struct dd_benchmark *bm, struct dd_context *context)
{
	int i;

	if (dd_debug_bit_test(DD_DEBUG_BENCHMARK)) {
		spin_lock(&context->bm_result.lock);
		for (i = 1; i < DD_REQ_COUNT; i++) {
			long avg = context->bm_result.data[i];
			long val = nsec(bm->stage[i]) - nsec(bm->stage[DD_REQ_INIT]);
			long div = context->bm_result.count + 1;
			context->bm_result.data[i] = avg + ((val - avg) / div);
		}
		context->bm_result.count++;
		spin_unlock(&context->bm_result.lock);
	}
}

static inline void dd_dump_benchmark(struct dd_benchmark_result *bm_result)
{
	if (dd_debug_bit_test(DD_DEBUG_BENCHMARK) &&
			__ratelimit(&bm_result->ratelimit_state)) {
		spin_lock(&bm_result->lock);
		dd_info("benchmark req{pending:%ld processing:%ld submitted:%ld finishing:%ld freed:%ld} cnt:%ld\n",
				bm_result->data[DD_REQ_PENDING],
				bm_result->data[DD_REQ_PROCESSING],
				bm_result->data[DD_REQ_SUBMITTED],
				bm_result->data[DD_REQ_FINISHING],
				bm_result->data[DD_REQ_UNALLOCATED],
				bm_result->count);
		spin_unlock(&bm_result->lock);
	}
}

#define USE_KEYRING (0)

#if USE_KEYRING
#else
int dd_add_master_key(int userid, void *key, int len);
void dd_evict_master_key(int userid);
#ifdef CONFIG_SDP_KEY_DUMP
int dd_dump_key(int userid, int fd);
#endif
#endif
int get_dd_master_key(int userid, void *key);

int dd_sec_crypt_bio_pages(struct dd_info *info, struct bio *orig,
		struct bio *clone, dd_crypto_direction_t rw);
int dd_sec_crypt_page(struct dd_info *info, dd_crypto_direction_t rw,
		struct page *src_page, struct page *dst_page);

void dd_hex_key_dump(const char *tag, uint8_t *data, unsigned int data_len);

#define FSCRYPT_STORAGE_TYPE_DATA_CE				-2
#define FSCRYPT_STORAGE_TYPE_MEDIA_CE				-3
#define FSCRYPT_STORAGE_TYPE_SYSTEM_CE				-4
#define FSCRYPT_STORAGE_TYPE_MISC_CE				-5
#define FSCRYPT_STORAGE_TYPE_DATA_DE				-6
#define FSCRYPT_STORAGE_TYPE_SYSTEM_DE				-7
#define FSCRYPT_STORAGE_TYPE_MISC_DE				-8
#define FSCRYPT_STORAGE_TYPE_SDP_ENC_USER			-9
#define FSCRYPT_STORAGE_TYPE_SDP_ENC_EMULATED		-10

#define FSCRYPT_DDAR_NAME_FUNC_OK	0
#define FSCRYPT_DDAR_NAME_FUNC_ERROR	-1
#define FSCRYPT_DDAR_NAME_FUNC_FOUND_DATA_ROOT	1

int fscrypt_ddar_get_storage_type(struct dentry *target_dentry);

extern void fscrypt_dd_trace_inode(const struct inode *inode);

#endif /* SECURITY_DDAR_DD_COMMON_H_ */
