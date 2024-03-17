/*
 * File: include/ddar/dd.h
 *
 * Samsung dual DAR cache I/O relay driver kernel interface
 *
 * Author: Olic Moon <olic.moon@samsung.com>
 */

#ifndef INCLUDE_DDAR_DD_H_
#define INCLUDE_DDAR_DD_H_

#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/time.h>

//#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/mempool.h>
#include <crypto/skcipher.h>

#include <ddar/common.h>
#include <ddar/dd_i.h>

struct dd_crypt_context {
	struct dd_policy policy;
	unsigned char cipher_file_encryption_key[64]; // only used for kernel crypto
	unsigned char tag[16];
} __attribute__((__packed__));

extern unsigned int dd_debug_mask;

#define dd_debug_bit_test(mask) (dd_debug_mask & mask)
void __dd_debug(unsigned int mask,
		const char *func, const char *fmt, ...);

#define dd_debug(mask, fmt, ...) \
		__dd_debug(mask, __func__, fmt, ##__VA_ARGS__)
#define dd_error(fmt, ...) \
		__dd_debug(DD_DEBUG_ERROR, __func__, fmt, ##__VA_ARGS__)
#define dd_info(fmt, ...) \
		__dd_debug(DD_DEBUG_INFO, __func__, fmt, ##__VA_ARGS__)
#define dd_verbose(fmt, ...) \
		__dd_debug(DD_DEBUG_VERBOSE, __func__, fmt, ##__VA_ARGS__)
#define dd_memory(fmt, ...) \
		__dd_debug(DD_DEBUG_MEMORY, __func__, fmt, ##__VA_ARGS__)
#define dd_benchmark(fmt, ...) \
		__dd_debug(DD_DEBUG_BENCHMARK, __func__, fmt, ##__VA_ARGS__)
#define dd_process(fmt, ...) \
		__dd_debug(DD_DEBUG_PROCESS, __func__, fmt, ##__VA_ARGS__)

extern void dd_dump(const char *msg, char *buf, int len);
extern void dd_dump_bio_pages(const char *msg, struct bio *bio);

struct dd_info {
	void *context;
	struct inode *inode;
	unsigned long ino;
	struct dd_policy policy;
	struct dd_crypt_context crypt_context;
	struct page *mdpage;  // metadata cache page

	spinlock_t lock; // lock to protect proc pointer
	void *proc;  // process processing blocks that belong to this file
	atomic_t reqcount;
	atomic_t refcount;  // free the object when this becomes 0

	struct crypto_skcipher *ctfm; // Secondary kernel crypto support
};

struct dd_info *alloc_dd_info(struct inode *inode, const struct dd_policy *policy, struct dd_crypt_context *crypt_context);
void dd_info_try_free(struct dd_info *info);

extern void *dd_get_info(const struct inode *inode);
int dd_is_user_deamon_locked(void);

int dd_generate_file_key(char userId, struct dd_crypt_context *crypt_context);
int dd_create_crypt_context(struct inode *inode, const struct dd_policy *policy, void *fs_data);

struct crypto_skcipher *dd_alloc_ctfm(struct dd_crypt_context *crypt_context, void *key);

int dd_page_crypto(struct dd_info *info, dd_crypto_direction_t dir,
		struct page *src_page, struct page *dst_page);

void set_ddar_count(long count);
long get_ddar_count(void);
void inc_ddar_count(void);
void dec_ddar_count(void);

int dd_read_crypt_context(struct inode *inode, struct dd_crypt_context *crypt_context);
int dd_write_crypt_context(struct inode *inode, const struct dd_crypt_context *context, void *fs_data);
int dd_read_crypto_metadata(struct inode *inode, const char *name, void *buffer, size_t buffer_size);
int dd_write_crypto_metadata(struct inode *inode, const char *name, const void *buffer, size_t len);

#endif /* INCLUDE_DDAR_DD_H_ */
