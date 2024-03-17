/*
 * This code is based on IMA's code
 *
 * Copyright (C) 2016 Samsung Electronics, Inc.
 *
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
 * Viacheslav Vovchenko <v.vovchenko@samsung.com>
 * Yevgen Kopylov <y.kopylov@samsung.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/ratelimit.h>
#include <linux/file.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <linux/freezer.h>
#include "five.h"
#include "five_crypto_comp.h"
#include "five_porting.h"
#include "security/integrity/integrity.h"
#include "five_testing.h"

struct ahash_completion {
	struct completion completion;
	int err;
};

/* minimum file size for ahash use */
static unsigned long five_ahash_minsize;
module_param_named(ahash_minsize, five_ahash_minsize, ulong, 0644);
MODULE_PARM_DESC(ahash_minsize, "Minimum file size for ahash use");

/* default is 0 - 1 page. */
static int five_maxorder;
static unsigned long five_bufsize = PAGE_SIZE;

__visible_for_testing __mockable struct crypto_shash *call_crypto_alloc_shash(
		const char *alg_name, u32 type, u32 mask)
{
	return crypto_alloc_shash(alg_name, type, mask);
}

static int param_set_bufsize(const char *val, const struct kernel_param *kp)
{
	unsigned long long size;
	int order;

	size = memparse(val, NULL);
	order = get_order(size);
	if (order >= MAX_ORDER)
		return -EINVAL;
	five_maxorder = order;
	five_bufsize = PAGE_SIZE << order;
	return 0;
}

static const struct kernel_param_ops param_ops_bufsize = {
	.set = param_set_bufsize,
	.get = param_get_uint,
};

#define param_check_bufsize(name, p) __param_check(name, p, unsigned int)

module_param_named(ahash_bufsize, five_bufsize, ulong, 0644);
MODULE_PARM_DESC(ahash_bufsize, "Maximum ahash buffer size");

static struct crypto_shash *five_shash_tfm;
static struct crypto_ahash *five_ahash_tfm;

int __init five_init_crypto(void)
{
	long rc;

	five_shash_tfm = call_crypto_alloc_shash(
					hash_algo_name[five_hash_algo], 0, 0);
	if (IS_ERR(five_shash_tfm)) {
		rc = PTR_ERR(five_shash_tfm);
		pr_err("Can not allocate %s (reason: %ld)\n",
		       hash_algo_name[five_hash_algo], rc);
		return rc;
	}
	return 0;
}

static struct crypto_shash *five_alloc_tfm(enum hash_algo algo)
{
	struct crypto_shash *tfm = five_shash_tfm;
	int rc;

	if (algo < 0 || algo >= HASH_ALGO__LAST)
		algo = five_hash_algo;

	if (algo != five_hash_algo) {
		tfm = crypto_alloc_shash(hash_algo_name[algo], 0, 0);
		if (IS_ERR(tfm)) {
			rc = PTR_ERR(tfm);
			pr_err("Can not allocate %s (reason: %d)\n",
			       hash_algo_name[algo], rc);
		}
	}
	return tfm;
}

static void five_free_tfm(struct crypto_shash *tfm)
{
	if (tfm != five_shash_tfm)
		crypto_free_shash(tfm);
}

/**
 * five_alloc_pages() - Allocate contiguous pages.
 * @max_size:       Maximum amount of memory to allocate.
 * @allocated_size: Returned size of actual allocation.
 * @last_warn:      Should the min_size allocation warn or not.
 *
 * Tries to do opportunistic allocation for memory first trying to allocate
 * max_size amount of memory and then splitting that until zero order is
 * reached. Allocation is tried without generating allocation warnings unless
 * last_warn is set. Last_warn set affects only last allocation of zero order.
 *
 * By default, five_maxorder is 0 and it is equivalent to kmalloc(GFP_KERNEL)
 *
 * Return pointer to allocated memory, or NULL on failure.
 */
static void *five_alloc_pages(loff_t max_size, size_t *allocated_size,
			     int last_warn)
{
	void *ptr;
	int order = five_maxorder;
	gfp_t gfp_mask = __GFP_RECLAIM | __GFP_NOWARN | __GFP_NORETRY;

	if (order)
		order = min(get_order(max_size), order);

	for (; order; order--) {
		ptr = (void *)__get_free_pages(gfp_mask, order);
		if (ptr) {
			*allocated_size = PAGE_SIZE << order;
			return ptr;
		}
	}

	/* order is zero - one page */

	gfp_mask = GFP_KERNEL;

	if (!last_warn)
		gfp_mask |= __GFP_NOWARN;

	ptr = (void *)__get_free_pages(gfp_mask, 0);
	if (ptr) {
		*allocated_size = PAGE_SIZE;
		return ptr;
	}

	*allocated_size = 0;
	return NULL;
}

/**
 * five_free_pages() - Free pages allocated by five_alloc_pages().
 * @ptr:  Pointer to allocated pages.
 * @size: Size of allocated buffer.
 */
static void five_free_pages(void *ptr, size_t size)
{
	if (!ptr)
		return;
	free_pages((unsigned long)ptr, get_order(size));
}

static struct crypto_ahash *five_alloc_atfm(enum hash_algo algo)
{
	struct crypto_ahash *tfm = five_ahash_tfm;
	int rc;

	if (algo < 0 || algo >= HASH_ALGO__LAST)
		algo = five_hash_algo;

	if (algo != five_hash_algo || !tfm) {
		tfm = crypto_alloc_ahash(hash_algo_name[algo], 0, 0);
		if (!IS_ERR(tfm)) {
			if (algo == five_hash_algo)
				five_ahash_tfm = tfm;
		} else {
			rc = PTR_ERR(tfm);
			pr_err("Can not allocate %s (reason: %d)\n",
			       hash_algo_name[algo], rc);
		}
	}
	return tfm;
}

static void five_free_atfm(struct crypto_ahash *tfm)
{
	if (tfm != five_ahash_tfm)
		crypto_free_ahash(tfm);
}

static void ahash_complete(struct crypto_async_request *req, int err)
{
	struct ahash_completion *res = req->data;

	if (err == -EINPROGRESS)
		return;
	res->err = err;
	complete(&res->completion);
}

static int ahash_wait(int err, struct ahash_completion *res)
{
	try_to_freeze();

	switch (err) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&res->completion);
		reinit_completion(&res->completion);
		err = res->err;
		fallthrough;
	default:
		pr_crit_ratelimited("ahash calculation failed: err: %d\n", err);
	}

	return err;
}

static int five_calc_file_hash_atfm(struct file *file,
				   u8 *hash, size_t *hash_len,
				   struct crypto_ahash *tfm)
{
	const size_t len = crypto_ahash_digestsize(tfm);
	loff_t i_size, offset;
	char *rbuf[2] = { NULL, };
	int rc, read = 0, rbuf_len, active = 0, ahash_rc = 0;
	struct ahash_request *req;
	struct scatterlist sg[1];
	struct ahash_completion res;
	size_t rbuf_size[2];

	if (*hash_len < len)
		return -EINVAL;

	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	init_completion(&res.completion);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				   CRYPTO_TFM_REQ_MAY_SLEEP,
				   ahash_complete, &res);

	rc = ahash_wait(crypto_ahash_init(req), &res);
	if (rc)
		goto out1;

	i_size = i_size_read(file_inode(file));

	if (i_size == 0)
		goto out2;

	/*
	 * Try to allocate maximum size of memory.
	 * Fail if even a single page cannot be allocated.
	 */
	rbuf[0] = five_alloc_pages(i_size, &rbuf_size[0], 1);
	if (!rbuf[0]) {
		rc = -ENOMEM;
		goto out1;
	}

	/* Only allocate one buffer if that is enough. */
	if (i_size > rbuf_size[0]) {
		/*
		 * Try to allocate secondary buffer. If that fails fallback to
		 * using single buffering. Use previous memory allocation size
		 * as baseline for possible allocation size.
		 */
		rbuf[1] = five_alloc_pages(i_size - rbuf_size[0],
					  &rbuf_size[1], 0);
	}

	if (!(file->f_mode & FMODE_READ)) {
		file->f_mode |= FMODE_READ;
		read = 1;
	}

	for (offset = 0; offset < i_size; offset += rbuf_len) {
		if (!rbuf[1] && offset) {
			/* Not using two buffers, and it is not the first
			 * read/request, wait for the completion of the
			 * previous ahash_update() request.
			 */
			rc = ahash_wait(ahash_rc, &res);
			if (rc)
				goto out3;
		}
		/* read buffer */
		rbuf_len = min_t(loff_t, i_size - offset, rbuf_size[active]);
		rc = integrity_kernel_read(file, offset, rbuf[active],
					   rbuf_len);
		if (rc != rbuf_len)
			goto out3;

		if (rbuf[1] && offset) {
			/* Using two buffers, and it is not the first
			 * read/request, wait for the completion of the
			 * previous ahash_update() request.
			 */
			rc = ahash_wait(ahash_rc, &res);
			if (rc)
				goto out3;
		}

		sg_init_one(&sg[0], rbuf[active], rbuf_len);
		ahash_request_set_crypt(req, sg, NULL, rbuf_len);

		ahash_rc = crypto_ahash_update(req);

		if (rbuf[1])
			active = !active; /* swap buffers, if we use two */
	}
	/* wait for the last update request to complete */
	rc = ahash_wait(ahash_rc, &res);
out3:
	if (read)
		file->f_mode &= ~FMODE_READ;
	five_free_pages(rbuf[0], rbuf_size[0]);
	five_free_pages(rbuf[1], rbuf_size[1]);
out2:
	if (!rc) {
		ahash_request_set_crypt(req, NULL, hash, 0);
		rc = ahash_wait(crypto_ahash_final(req), &res);
		if (!rc)
			*hash_len = len;
	}
out1:
	ahash_request_free(req);
	return rc;
}

static int five_calc_file_ahash(struct file *file,
			       u8 hash_algo, u8 *hash,
			       size_t *hash_len)
{
	struct crypto_ahash *tfm;
	int rc;

	tfm = five_alloc_atfm(hash_algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = five_calc_file_hash_atfm(file, hash, hash_len, tfm);

	five_free_atfm(tfm);

	return rc;
}

static int five_calc_file_hash_tfm(struct file *file,
				  u8 *hash, size_t *hash_len,
				  struct crypto_shash *tfm)
{
	SHASH_DESC_ON_STACK(shash, tfm);
	const size_t len = crypto_shash_digestsize(tfm);
	loff_t i_size, offset = 0;
	char *rbuf;
	int rc, read = 0;

	if (*hash_len < len)
		return -EINVAL;

	shash->tfm = tfm;
	#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	shash->flags = 0;
	#endif

	rc = crypto_shash_init(shash);
	if (rc != 0)
		return rc;

	i_size = i_size_read(file_inode(file));

	if (i_size == 0)
		goto out;

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!rbuf)
		return -ENOMEM;

	if (!(file->f_mode & FMODE_READ)) {
		file->f_mode |= FMODE_READ;
		read = 1;
	}

	while (offset < i_size) {
		int rbuf_len;

		rbuf_len = integrity_kernel_read(file, offset, rbuf, PAGE_SIZE);
		if (rbuf_len < 0) {
			rc = rbuf_len;
			break;
		}
		if (rbuf_len == 0)
			break;
		offset += rbuf_len;

		try_to_freeze();

		rc = crypto_shash_update(shash, rbuf, rbuf_len);
		if (rc)
			break;
	}
	if (read)
		file->f_mode &= ~FMODE_READ;
	kfree(rbuf);
out:
	if (!rc)
		rc = crypto_shash_final(shash, hash);

	if (!rc)
		*hash_len = len;

	return rc;
}

static int five_calc_hash_tfm(const u8 *data, size_t data_len,
		u8 *hash, size_t *hash_len, struct crypto_shash *tfm)
{
	SHASH_DESC_ON_STACK(shash, tfm);
	const size_t len = crypto_shash_digestsize(tfm);
	int rc;

	if (*hash_len < len || data_len == 0)
		return -EINVAL;

	shash->tfm = tfm;
	#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	shash->flags = 0;
	#endif

	rc = crypto_shash_init(shash);
	if (rc != 0)
		return rc;

	rc = crypto_shash_update(shash, data, data_len);
	if (!rc) {
		rc = crypto_shash_final(shash, hash);

		if (!rc)
			*hash_len = len;
	}

	return rc;
}

static int five_calc_file_shash(struct file *file,
			       u8 hash_algo,
			       u8 *hash,
			       size_t *hash_len)
{
	struct crypto_shash *tfm;
	int rc;

	tfm = five_alloc_tfm(hash_algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = five_calc_file_hash_tfm(file, hash, hash_len, tfm);

	five_free_tfm(tfm);

	return rc;
}

static int five_calc_data_shash(const u8 *data, size_t data_len, u8 hash_algo,
				u8 *hash, size_t *hash_len)
{
	struct crypto_shash *tfm;
	int rc;

	tfm = five_alloc_tfm(hash_algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = five_calc_hash_tfm(data, data_len, hash, hash_len, tfm);

	five_free_tfm(tfm);

	return rc;
}

/*
 * five_calc_file_hash - calculate file hash
 *
 * Asynchronous hash (ahash) allows using HW acceleration for calculating
 * a hash. ahash performance varies for different data sizes on different
 * crypto accelerators. shash performance might be better for smaller files.
 * The 'five.ahash_minsize' module parameter allows specifying the best
 * minimum file size for using ahash on the system.
 *
 * If the five.ahash_minsize parameter is not specified, this function uses
 * shash for the hash calculation.  If ahash fails, it falls back to using
 * shash.
 */
int five_calc_file_hash(struct file *file, u8 hash_algo, u8 *hash,
		size_t *hash_len)
{
	loff_t i_size;
	int rc;

	i_size = i_size_read(file_inode(file));

	if (five_ahash_minsize && i_size >= five_ahash_minsize) {
		rc = five_calc_file_ahash(file, hash_algo, hash, hash_len);
		if (!rc)
			return 0;
	}

	return five_calc_file_shash(file, hash_algo, hash, hash_len);
}

int five_calc_data_hash(const uint8_t *data, size_t data_len,
			uint8_t hash_algo, uint8_t *hash, size_t *hash_len)
{
	return five_calc_data_shash(data, data_len, hash_algo, hash, hash_len);
}
