/*
 * File: security/ddar/dd_core.c
 *
 * Samsung Dual-DAR(Data At Rest) cache I/O relay driver
 *
 * Author: Olic Moon <olic.moon@samsung.com>
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/aio.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>
#include <linux/sched/signal.h>

#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/blk-crypto.h>

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/freezer.h>
#include <linux/pagemap.h>

#include <linux/fscrypt.h>
#include <ddar/fs_request.h>

#include "dd_common.h"

#define TIMEOUT_PENDING_REQ (5*1000)

static struct kmem_cache *dd_req_cachep;
static struct workqueue_struct *dd_free_req_workqueue;
static struct workqueue_struct *dd_ioctl_workqueue;
static struct workqueue_struct *dd_read_workqueue;

//static struct task_struct *abort_thread;

static struct dd_context *dd_context_global;
struct dd_context *dd_get_global_context(void)
{
	return dd_context_global;
}
static inline void __benchmark_init(struct dd_benchmark_result *bm_result)
__acquires(&bm_result->lock)
__releases(&bm_result->lock)
{
	int i;
	spin_lock(&bm_result->lock);
	bm_result->count = 0;
	for (i = 0; i < DD_REQ_COUNT; i++)
		bm_result->data[i] = 0;
	spin_unlock(&bm_result->lock);
}

static LIST_HEAD(dd_free_reqs);
static DEFINE_SPINLOCK(dd_req_list_lock);

static inline long req_time_spent(struct dd_req *req)
{
	return jiffies_to_msecs(jiffies) - req->timestamp;
}

#if CONFIG_DD_REQ_DEBUG
static LIST_HEAD(dd_debug_req_list);

static void __dd_debug_req(const char *msg, int mask,
		const char *func, struct dd_req *req)
{
	struct dd_proc *proc = (struct dd_proc *) req->info->proc;

	__dd_debug(mask, func,
			"req {id:%ld ino:%ld (%s) code:%d abort:%d pid:%d(tgid:%d), proc:%p state:%d alive:%ld list:%p(prev:%p, next:%p)}: %s\n",
			req->unique, req->ino, (req->dir == WRITE) ? "write":"read", req->code, req->abort, req->pid, req->tgid, proc,
			req->state, req_time_spent(req), &req->list, req->list.prev, req->list.next, msg);
}

#if 1
#define dd_debug_req(msg, mask, req) \
		__dd_debug_req(msg, mask, __func__, req)
#else
#define dd_debug_req(msg, mask, req) \
		__dd_debug_req(msg, mask, __func__, req)
#endif

static int dd_dump_debug_req_list(int mask)
{
	struct dd_context *ctx = dd_context_global;
	struct dd_proc *proc = NULL;
	struct dd_req *req = NULL;
	int num = 0;

	spin_lock(&ctx->lock);
	list_for_each_entry(proc, &ctx->procs, proc_node) {
		num++;
		dd_debug(mask, "proc { pid:%d(%p) tgid:%d abort:%d req_count:%d pending:%p processing:%p submitted:%p}\n",
				proc->pid, proc, proc->tgid, proc->abort, atomic_read(&proc->reqcount), &proc->pending, &proc->processing, &proc->submitted);
	}
	spin_unlock(&ctx->lock);
	dd_debug(mask, "available process:%d\n", num);

	num = 0;
	spin_lock(&dd_req_list_lock);
	list_for_each_entry(req, &dd_debug_req_list, debug_list) {
		num++;
		dd_debug_req("dump", mask, req);
	}
	spin_unlock(&dd_req_list_lock);
	dd_debug(mask, "allocated requests: %d\n", num);

	return num;
}
#endif

static void dd_info_get(struct dd_info *info);
static struct dd_req *get_req(const char *msg, struct dd_info *info,
		dd_request_code_t code, int dir)
{
	struct dd_context *ctx = dd_context_global;
	struct dd_req  *req;

	BUG_ON(!info);

	spin_lock(&dd_req_list_lock);
	req = list_first_entry_or_null(&dd_free_reqs, struct dd_req, list);
	if (req) {
		if (!list_empty(&req->list))
			list_del_init(&req->list);
		else
			dd_error("get req: debug list is already empty\n");
	}
	spin_unlock(&dd_req_list_lock);

	if (!req) {
		req = kmem_cache_alloc(dd_req_cachep, GFP_NOFS);

		if (!req)
			return ERR_PTR(-ENOMEM);

		INIT_LIST_HEAD(&req->list);
		init_waitqueue_head(&req->waitq);
	}

#if CONFIG_DD_REQ_DEBUG
	INIT_LIST_HEAD(&req->debug_list);

	spin_lock(&dd_req_list_lock);
	list_add(&req->debug_list, &dd_debug_req_list);
	spin_unlock(&dd_req_list_lock);
#endif

	req->context = ctx;
	req->info = info;
	dd_info_get(req->info);

	req->code = code;
	req->dir = dir;
	req->ino = info->ino;
	req->pid = 0;
	req->tgid = 0;
	req->timestamp = jiffies_to_msecs(jiffies);

	req->abort = 0;
	req->need_xattr_flush = 0;
	req->user_space_crypto = dd_policy_user_space_crypto(info->policy.flags);

	memset(&req->bm, 0, sizeof(struct dd_benchmark));

	spin_lock(&ctx->ctr_lock);
	ctx->req_ctr++;
	if (ctx->req_ctr > 4096)
		ctx->req_ctr = 0;
	req->unique = ctx->req_ctr;
	spin_unlock(&ctx->ctr_lock);

	dd_debug_req("req <init>", DD_DEBUG_PROCESS, req);
	dd_req_state(req, DD_REQ_INIT);

	return req;
}

static inline void dd_proc_try_free(struct dd_proc *proc)
{
	int reqcnt = atomic_read(&proc->reqcount);

	BUG_ON(!proc->abort);
	if (reqcnt > 0) {
		dd_info("dd_proc_try_free: delayed freeing proc:%p (reqcnt:%d)\n", proc, reqcnt);
	} else {
		int i;

		dd_info("dd_proc_try_free: freeing proc:%p\n", proc);
		for (i = 0; i < MAX_NUM_CONTROL_PAGE; i++)
			if (proc->control_page[i])
				mempool_free(proc->control_page[i], proc->context->page_pool);

		kfree(proc);
	}
}

static void dd_free_req_work(struct work_struct *work);
static inline void put_req(const char *msg, struct dd_req *req)
{
	if (unlikely(!req))
		return;

	/**
	 * Avoid reentrance. Since request objects are shared
	 * by crypto thread and kernel services and they can
	 * be aborted at any moment. This is to avoid fatal error
	 * even if abort_req and put_req are called multiple times
	 */
	if (unlikely(req->state == DD_REQ_UNALLOCATED))
		return;

	if (!req->abort) {
		if (req->state != DD_REQ_SUBMITTED) {
			dd_error("req unique:%d state is not submitted (%d)\n",
					req->unique, req->state);
		}
		BUG_ON(req->state != DD_REQ_SUBMITTED);
	}

	// delayed freeing req object
	dd_req_state(req, DD_REQ_FINISHING);
	INIT_WORK(&req->delayed_free_work, dd_free_req_work);
	queue_work(dd_free_req_workqueue, &req->delayed_free_work);
}

/**
 * delayed freeing req object. put_req() can be called by an irq handler where we
 * don't want to hold spin lock. put_req() only mark state as finished than this function
 * free those finished requests
 */
static void dd_free_req_work(struct work_struct *work)
{
	struct dd_req *req = container_of(work, struct dd_req, delayed_free_work);

	if (req->state == DD_REQ_FINISHING) {
		struct dd_info *info = req->info;
		struct dd_proc *proc = (struct dd_proc *) info->proc;

		dd_debug_req("req <free>", DD_DEBUG_PROCESS, req);

		/**
		 * proc must not null in majority of cases
		 * except req was aborted before assigned to a crypto task.
		 */
		if (proc && req->user_space_crypto) {
			/**
			 * In case the request was aborted, requested is
			 * dequeued immediately
			 */
			spin_lock(&proc->lock);
			if (!list_empty(&req->list))
				list_del_init(&req->list);
			spin_unlock(&proc->lock);

			if (atomic_dec_and_test(&proc->reqcount)) {
				dd_process("req:%p unbound from proc:%p\n", req, proc);

				if (proc->abort)
					dd_proc_try_free(proc);
			}
		}

		spin_lock(&dd_req_list_lock);
		list_add_tail(&req->list, &dd_free_reqs);
#if CONFIG_DD_REQ_DEBUG
		if (!list_empty(&req->debug_list))
			list_del(&req->debug_list);
		else
			dd_error("free req: debug list is already empty\n");
#endif
		spin_unlock(&dd_req_list_lock);

		dd_req_state(req, DD_REQ_UNALLOCATED);

		// Run benchmark only for read operation
		if (!req->abort && req->dir == READ) {
			dd_submit_benchmark(&req->bm, req->context);
			dd_dump_benchmark(&req->context->bm_result);
		}

		spin_lock(&info->lock);
		if (atomic_dec_and_test(&info->reqcount)) {
			dd_process("req:%p unbound from info:%p\n", req, info);
			info->proc = NULL;
		}
		spin_unlock(&info->lock);

		dd_info_try_free(info);
	} else {
		dd_debug_req("req <free>", DD_DEBUG_PROCESS, req);
	}
}

static void dd_free_pages(struct dd_info *info, struct bio *clone);

static inline void abort_req(const char *msg, struct dd_req *req, int err)
{
	struct dd_info *info = req->info;
	struct dd_proc *proc = (struct dd_proc *) info->proc;
	sdp_fs_command_t *cmd = NULL;

	if (unlikely(!req))
		return;

	if (unlikely(req->state == DD_REQ_UNALLOCATED))
		return;

	if (req->abort)
		return;

	printk("Record audit log in case of a failure during en/decryption of dualdar protected file\n");
	if (req->dir == READ) {
		cmd = sdp_fs_command_alloc(FSOP_AUDIT_FAIL_DECRYPT,
				current->tgid, info->policy.userid, -1, info->ino, err,
				GFP_KERNEL);
	} else {
		cmd = sdp_fs_command_alloc(FSOP_AUDIT_FAIL_ENCRYPT,
				current->tgid, info->policy.userid, -1, info->ino, err,
				GFP_KERNEL);
	}
	if (cmd) {
		sdp_fs_request(cmd, NULL);
		sdp_fs_command_free(cmd);
	}

	req->abort = 1;
	if (proc) {
		spin_lock(&proc->lock);
		// skip in case req is not assigned to any process
		if (!list_empty(&req->list))
			list_del_init(&req->list);
		spin_unlock(&proc->lock);
	}

	dd_debug_req(msg, DD_DEBUG_ERROR, req);

	switch (req->state) {
	case DD_REQ_INIT:
	case DD_REQ_PENDING:
	case DD_REQ_PROCESSING:
	case DD_REQ_SUBMITTED:
	{
		if (req->code == DD_REQ_CRYPTO_BIO) {
			unsigned dir = bio_data_dir(req->u.bio.orig);
			struct bio *orig = req->u.bio.orig;
			struct bio *clone = req->u.bio.clone;

			if (clone) {
				if (dir == WRITE)
					dd_free_pages(req->info, clone);

				bio_put(clone);
			}

			orig->bi_status = err;
			bio_endio(orig);
		}
		break;
	}
	case DD_REQ_FINISHING:
		// nothing to do
	default:
		break;
	}

	if (req->user_space_crypto)
		wake_up_interruptible(&req->waitq);

	put_req(__func__, req);
}

static inline void proc_abort_req_all(const char *msg, struct dd_proc *proc)
__acquires(&proc->lock)
__releases(&proc->lock)
{
	struct dd_req *pos, *temp;

	BUG_ON(!proc);

	spin_lock(&proc->lock);
	list_for_each_entry_safe(pos, temp, &proc->pending, list) {
		spin_unlock(&proc->lock);
		abort_req(__func__, pos, -EIO);
		spin_lock(&proc->lock);
	}

	list_for_each_entry_safe(pos, temp, &proc->processing, list) {
		spin_unlock(&proc->lock);
		abort_req(__func__, pos, -EIO);
		spin_lock(&proc->lock);
	}

	proc->abort = 1;
	wake_up(&proc->waitq);

	spin_unlock(&proc->lock);
}

#if CONFIG_DD_REQ_DEBUG
static int dd_abort_pending_req_timeout(int mask)
{
	struct dd_req *req = NULL;
	int num = 0;

	spin_lock(&dd_req_list_lock);
	list_for_each_entry(req, &dd_debug_req_list, debug_list) {
		if ((req_time_spent(req) > TIMEOUT_PENDING_REQ) && (req->state != DD_REQ_FINISHING)) {
			num++;
			abort_req(__func__, req, -EIO);
		}
	}
	spin_unlock(&dd_req_list_lock);
	if (num > 0)
		dd_debug(mask, "aborted requests: %d\n", num);

	return num;
}
#endif

static struct dd_req *find_req(struct dd_proc *proc, dd_req_state_t state, unsigned long ino)
__acquires(proc->lock)
__releases(proc->lock)
{
	struct dd_req *req = NULL, *p = NULL;
	struct list_head *head = NULL;

	switch (state) {
	case DD_REQ_PENDING:
		head = &proc->pending;
		break;
	case DD_REQ_PROCESSING:
		head = &proc->processing;
		break;
	case DD_REQ_SUBMITTED:
		head = &proc->submitted;
		break;
	default:
		dd_error("can't find process queue for state %d\n", state);
		break;
	}

	if (!head)
		return NULL;

	spin_lock(&proc->lock);
	list_for_each_entry(p, head, list) {
		if (p->info->ino == ino) {
			req = p;
			break;
		}
	}
	spin_unlock(&proc->lock);

	return req;
}

#define DD_CRYPTO_REQ_TIMEOUT 3000

// caller required to hold proc->lock
static void queue_pending_req_locked(struct dd_proc *proc, struct dd_req *req)
{
	list_move_tail(&req->list, &proc->pending);
	dd_req_state(req, DD_REQ_PENDING);
	req->pid = proc->pid;
	req->tgid = proc->tgid;
}

static void dd_free_pages(struct dd_info *info, struct bio *clone)
{
	struct dd_context *ctx = (struct dd_context *) info->context;

	struct address_space *mapping;
	struct bvec_iter iter;
	struct bio_vec bv;

	bio_for_each_bvec(bv, clone, iter) {
		BUG_ON(!bv.bv_page);
		mapping = page_mapping(bv.bv_page);
		if (mapping) {
			bv.bv_page->mapping = NULL;
		}

		mempool_free(bv.bv_page, ctx->page_pool);
		bv.bv_page = NULL;
	}
}

extern int dd_oem_page_crypto_inplace(struct dd_info *info, struct page *page, int dir);

/**
 * Run CE based OEM encryption
 *
 * This is a security requirement to hide cryptographic artifacts of vendor data-at-rest
 * layer behind device level encryption
 */
int dd_oem_crypto_bio_pages(struct dd_req *req, int dir, struct bio *bio)
{
	struct bio_vec *bv;
	struct bvec_iter_all i;
	int err = 0;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;
		int ret;

		dd_verbose("unique:%d dir:%d\n", req->unique, dir);
		ret = dd_oem_page_crypto_inplace(req->info, page, dir);

		if (ret) {
			err = ret;
			dd_error("failed to decrypt page:[ino:%ld] [index:%ld] \n",
					page->mapping->host->i_ino, page->index);
			SetPageError(page);
		}
	}

	return err;
}

static void dd_end_io(struct bio *clone);

static struct bio *dd_clone_bio(struct dd_req *req, struct bio *orig, unsigned size)
{
	struct dd_info *info = req->info;
	struct dd_context *ctx = (struct dd_context *) info->context;
	struct bio *clone;
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned int nr_iovecs = 0;
	gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;
	unsigned i, len, remaining_size;
	struct page *page;
	struct bio_vec *bvec;
	struct bio_vec *orig_bvec;

retry:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_lock(&ctx->bio_alloc_lock);

	dd_debug_req("cloning bio", DD_DEBUG_VERBOSE, req);

	bio_for_each_bvec(bv, orig, iter) {
		nr_iovecs++;
	}

	clone = bio_alloc_bioset(GFP_NOIO, nr_iovecs, ctx->bio_set);
	if (!clone) {
		dd_error("failed to alloc bioset\n");
		goto return_clone;
	}

	clone->bi_private = req;
	bio_copy_dev(clone, orig);
	clone->bi_opf = orig->bi_opf;
	bio_crypt_clone(clone, orig, GFP_NOIO);

	remaining_size = size;

	for (i = 0; i < nr_iovecs; i++) {
		page = mempool_alloc(ctx->page_pool, gfp_mask);
		if (!page) {
			dd_free_pages(info, clone);
			bio_put(clone);
			gfp_mask |= __GFP_DIRECT_RECLAIM;
			nr_iovecs = 0;
			goto retry;
		}

		len = (unsigned int)((remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size);

		bvec = &clone->bi_io_vec[clone->bi_vcnt];
		orig_bvec = &orig->bi_io_vec[clone->bi_vcnt++];
		bvec->bv_page = page;
		bvec->bv_len = len;
		bvec->bv_offset = 0;
		if (i == 0) {
			bvec->bv_page->mapping = page_mapping(orig_bvec->bv_page);
		}

		clone->bi_iter.bi_size += len;

		remaining_size -= len;
	}

return_clone:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_unlock(&ctx->bio_alloc_lock);

	return clone;
}

static int __request_user(struct dd_req *req)
{
	struct dd_context *context = req->context;
	struct dd_info *info = req->info;

	BUG_ON(!req->user_space_crypto);
	BUG_ON(!info || !context);

	spin_lock(&info->lock);
	if (!info->proc) {
		spin_lock(&context->lock);
		info->proc = list_first_entry_or_null(&context->procs, struct dd_proc, proc_node);
		spin_unlock(&context->lock);
	}

	if (unlikely(!info->proc)) {
		dd_error("no available process");

		spin_unlock(&info->lock);
		return -EIO; // IO error (5)
	} else {
		struct dd_proc *proc = (struct dd_proc *) info->proc;
		atomic_inc(&info->reqcount);
		atomic_inc(&proc->reqcount);

		spin_lock_irq(&proc->lock);
		queue_pending_req_locked(proc, req);
		spin_unlock_irq(&proc->lock);

		spin_lock(&context->lock);
		list_move_tail(&proc->proc_node, &context->procs);
		spin_unlock(&context->lock);

		spin_unlock(&info->lock);
		wake_up(&proc->waitq);

		dd_debug_req("req <queued>", DD_DEBUG_PROCESS, req);
		return 0;
	}
}

static void dd_decrypt_work(struct work_struct *work)
{
	struct dd_req *req = container_of(work, struct dd_req, decryption_work);
	struct dd_info *info = req->info;
	struct bio *orig = req->u.bio.orig;

	dd_dump_bio_pages("from disk", req->u.bio.orig);

#ifdef CONFIG_SDP_KEY_DUMP
	if (!dd_policy_skip_decryption_inner_and_outer(req->info->policy.flags)) {
#endif
	if (fscrypt_inode_uses_inline_crypto(req->info->inode)) {
		dd_verbose("skip oem s/w crypt. hw encryption enabled\n");
	} else {
		if (dd_oem_crypto_bio_pages(req, READ, orig)) {
			dd_error("failed oem crypto\n");
			goto abort_out;
		}

		dd_dump_bio_pages("outer (s/w) decryption done", req->u.bio.orig);
	}
#ifdef CONFIG_SDP_KEY_DUMP
	} else {
		dd_info("skip decryption for outer layer - ino : %ld, flag : 0x%04x\n",
				req->info->inode->i_ino, req->info->policy.flags);
	}
#endif

	if (req->user_space_crypto) {
#ifdef CONFIG_SDP_KEY_DUMP
		if (!dd_policy_skip_decryption_inner(req->info->policy.flags)) {
#endif
		if (__request_user(req)) {
			dd_error("failed vendor crypto\n");
			goto abort_out;
		}
#ifdef CONFIG_SDP_KEY_DUMP
		} else {
			dd_info("skip decryption for inner layer - ino : %ld, flag : 0x%04x\n",
					req->info->inode->i_ino, req->info->policy.flags);
			dd_req_state(req, DD_REQ_SUBMITTED);

			orig->bi_status = 0;
			bio_endio(orig);
			put_req(__func__, req);
		}
#endif
	} else {
#ifdef CONFIG_SDP_KEY_DUMP
		if (!dd_policy_skip_decryption_inner(req->info->policy.flags)) {
#endif
		if (dd_sec_crypt_bio_pages(info, req->u.bio.orig, NULL, DD_DECRYPT)) {
			dd_error("failed dd crypto\n");
			goto abort_out;
		}
#ifdef CONFIG_SDP_KEY_DUMP
		} else {
			dd_info("skip decryption for inner layer - ino : %ld, flag : 0x%04x\n",
					req->info->inode->i_ino, req->info->policy.flags);
		}
#endif
		dd_req_state(req, DD_REQ_SUBMITTED);

		orig->bi_status = 0;
		bio_endio(orig);
		put_req(__func__, req);
	}

	return;
	abort_out:
	abort_req(__func__, req, -EIO);
}

static void dd_end_io(struct bio *clone)
{
	struct dd_req *req = (struct dd_req *) clone->bi_private;
	struct dd_info *info = req->info;
	struct bio *orig = req->u.bio.orig;
	unsigned dir = bio_data_dir(clone);
	int err;

	err = clone->bi_status;
	if (dir == WRITE)
		dd_free_pages(info, clone);

	// free clone bio in both success or error case
	dd_verbose("ino:%ld info->context:%p\n", info->ino, info->context);
	bio_put(clone);
	req->u.bio.clone = NULL;

	if (!err)
		if (dir == READ) {
			INIT_WORK(&req->decryption_work, dd_decrypt_work);
			queue_work(dd_read_workqueue, &req->decryption_work);
			return;
		}

	// report success or error to caller
	orig->bi_status = err;
	bio_endio(orig);
	put_req(__func__, req);
}

int dd_submit_bio(struct dd_info *info, struct bio *bio)
{
	struct dd_context *context = (struct dd_context *) info->context;
	struct dd_req *req = get_req(__func__, info, DD_REQ_CRYPTO_BIO, bio_data_dir(bio));
	int err = 0;

	dd_verbose("ino:%ld info->context:%p\n", info->ino, info->context);
	req->info = info;
	req->u.bio.orig = bio;
	if (bio_data_dir(bio) == WRITE) {
		req->u.bio.clone = dd_clone_bio(req, bio, bio->bi_iter.bi_size);
		BUG_ON(!req->u.bio.clone);

		if (req->user_space_crypto) {
			if (__request_user(req)) {
				dd_error("failed to request daemon\n");
				goto err_out;
			}
		} else {
			if (dd_sec_crypt_bio_pages(info, req->u.bio.orig, req->u.bio.clone, DD_ENCRYPT)) {
				dd_error("failed dd crypto\n");
				goto err_out;
			}

			if (fscrypt_inode_uses_inline_crypto(req->info->inode)) {
				dd_verbose("skip oem s/w crypt. hw encryption enabled\n");
//				fscrypt_set_ice_dun(req->info->inode, req->u.bio.clone, 0/* temporary */);
			} else {
				if (dd_oem_crypto_bio_pages(req, WRITE, req->u.bio.clone)) {
					dd_error("failed oem crypto\n");
					goto err_out;
				}
			}

			dd_req_state(req, DD_REQ_SUBMITTED);

			req->u.bio.clone->bi_private = req;
			req->u.bio.clone->bi_end_io = dd_end_io;
			submit_bio_noacct(req->u.bio.clone);
		}
	} else {
		// clone a bio that shares original bio's biovec
		req->u.bio.clone = bio_clone_fast(bio, GFP_NOIO, context->bio_set);
		if (!req->u.bio.clone) {
			dd_error("failed in bio clone\n");
			goto err_out;
		}

		req->u.bio.clone->bi_private = req;
		req->u.bio.clone->bi_end_io = dd_end_io;

#ifdef CONFIG_SDP_KEY_DUMP
		if (!dd_policy_skip_decryption_inner_and_outer(req->info->policy.flags)) {
#endif
		if (fscrypt_inode_uses_inline_crypto(req->info->inode)) {
			dd_verbose("skip oem s/w crypt. hw encryption enabled\n");
//			fscrypt_set_ice_dun(req->info->inode, req->u.bio.clone, 0/* temporary */);
		}
#ifdef CONFIG_SDP_KEY_DUMP
		} else {
			if (fscrypt_inode_uses_inline_crypto(req->info->inode)) {
				req->u.bio.clone->bi_crypt_context = NULL;
				dd_info("skip h/w decryption for ino(%ld)\n", req->info->inode->i_ino);
			}
		}
#endif

		submit_bio_noacct(req->u.bio.clone);
	}

	return err;
err_out:
	abort_req(__func__, req, -EIO);
	return -EIO;
}
EXPORT_SYMBOL(dd_submit_bio);

#define DD_PAGE_CRYPTO_REQ_TIMEOUT 10000
static int __wait_user_request(struct dd_req *req)
{
	int intr;

	dd_debug_req("wait for user response", DD_DEBUG_PROCESS, req);
	while (req->state != DD_REQ_SUBMITTED) {
		intr = wait_event_interruptible_timeout(req->waitq,
				req->state == DD_REQ_SUBMITTED,
				msecs_to_jiffies(DD_PAGE_CRYPTO_REQ_TIMEOUT));
		dd_verbose("wake up unique:%d\n", req->unique);

		if (intr == 0 || intr == -ERESTARTSYS) {
			dd_error("timeout or interrupted (%d) [ID:%d] ino:%ld\n",
					intr, req->unique, req->ino);

			abort_req(__func__, req, -EIO);
			break;
		}
	}
	dd_verbose("user request completed (unique:%d)\n", req->unique);

	if (req->abort)
		return -ECONNABORTED;

	put_req(__func__, req);
	return 0; // return 0 if success
}

int dd_page_crypto(struct dd_info *info, dd_crypto_direction_t dir,
		struct page *src_page, struct page *dst_page)
{
	struct dd_req *req = NULL;
	int err = 0;

	BUG_ON(!src_page || !dst_page);

	dd_verbose("dd_page_crypto ino:%ld\n", info->ino);
	req = get_req(__func__, info, DD_REQ_CRYPTO_PAGE, READ);
	if (IS_ERR(req))
		return -ENOMEM;

	req->u.page.dir = dir;
	req->u.page.src_page = src_page;
	req->u.page.dst_page = dst_page;

	if (dir == DD_DECRYPT) {
		if (fscrypt_inode_uses_inline_crypto(req->info->inode)) {
			dd_verbose("skip oem s/w crypt. hw encryption enabled\n");
		} else {
			err = dd_oem_page_crypto_inplace(info, src_page, READ);
			if (err) {
				dd_error("failed oem crypto\n");
				return err;
			}
		}

		if (req->user_space_crypto) {
			err = __request_user(req);
			if (err) {
				dd_error("failed user request err:%d\n", err);
				return err;
			}

			return __wait_user_request(req);
		} else {
			err = dd_sec_crypt_page(info, DD_DECRYPT, src_page, src_page);
			if (err) {
				dd_error("failed page crypto:%d\n", err);
			}

			dd_req_state(req, DD_REQ_SUBMITTED);
			put_req(__func__, req);
			return err;
		}
	} else {
		dd_error("operation not supported\n");
		BUG();
	}
}

/**
 * Performance flag to describe lock status. We don't want to make a blocking
 * user space call for every time a file is opened
 *
 * This flag is set by user space daemon and is protected by SEAndroid MAC enforcement
 */
unsigned int dd_lock_state = 1; // 1: locked 0: unlocked
module_param_named(lock_state, dd_lock_state, uint, 0600);
MODULE_PARM_DESC(lock_state, "ddar lock status");

int dd_is_user_deamon_locked(void)
{
	return dd_lock_state;
}

#ifdef CONFIG_DDAR_USER_PREPARE
int dd_prepare(struct dd_info *info)
{
	struct dd_req *req = NULL;
	int err = 0;

	if (dd_debug_bit_test(DD_DEBUG_CALL_STACK))
		dump_stack();

	req = get_req(__func__, info, DD_REQ_PREPARE);
	if (!req)
		return -ENOMEM;

	req->u.prepare.metadata = info->mdpage;

	err = __request_user(req);
	if (err) {
		dd_error("failed user request err:%d\n", err);
		return err;
	}

	return __wait_user_request(req);
}
#endif

#define LIMIT_PAGE_NUM (MAX_NUM_REQUEST_PER_CONTROL * MAX_NUM_CONTROL_PAGE)
struct dd_mmap_layout default_mmap_layout = {
		.page_size = PAGE_SIZE,
		.page_num_limit = LIMIT_PAGE_NUM,
		.control_area 			= { .start = 0x00000000, .size = PAGE_SIZE * MAX_NUM_CONTROL_PAGE }, // 32KB
		.metadata_area 			= { .start = 0x01000000, .size = PAGE_SIZE * MAX_NUM_INO_PER_USER_REQUEST }, // 128KB
		.plaintext_page_area 	= { .start = 0x02000000, .size = PAGE_SIZE * LIMIT_PAGE_NUM }, // 1 MB
		.ciphertext_page_area	= { .start = 0x03000000, .size = PAGE_SIZE * LIMIT_PAGE_NUM }  //  MB
};

static int dd_open(struct inode *nodp, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

static int dd_mmap_available(struct dd_proc *proc)
{
	if (!proc->control_vma ||
			!proc->metadata_vma ||
			!proc->plaintext_vma ||
			!proc->ciphertext_vma)
		return 0;
	return 1;
}

static int dd_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct dd_proc *proc = filp->private_data;
	struct dd_context *context = proc->context;
	unsigned long addr = vma->vm_pgoff << PAGE_SHIFT;

	BUG_ON(!proc);
	dd_memory("offset:%p\n", (void *)addr);

	spin_lock(&proc->lock);
	if (addr == context->layout->control_area.start) {
		proc->control_vma = vma;
		proc->control_vma->vm_flags |= VM_LOCKED;
	} else if (addr == context->layout->metadata_area.start) {
		proc->metadata_vma = vma;
		proc->metadata_vma->vm_flags |= VM_LOCKED;
	} else if (addr == context->layout->plaintext_page_area.start) {
		proc->plaintext_vma = vma;
		proc->plaintext_vma->vm_flags |= VM_LOCKED;
	} else if (addr == context->layout->ciphertext_page_area.start) {
		proc->ciphertext_vma = vma;
		proc->ciphertext_vma->vm_flags |= VM_LOCKED;
	} else {
		dd_error("mmap failed. mmap addr:%p\n", (void *)addr);
	}
	spin_unlock(&proc->lock);

	return 0;
}

typedef enum {
	DD_TRANS_OK = 0,
	DD_TRANS_ERR_FULL,
	DD_TRANS_ERR_PROC_DIED,
	DD_TRANS_ERR_UNKNOWN
} dd_transaction_result;

// currently ongoing user-space crypto request. This is always on stack, so no locking needed
struct dd_transaction {
	struct dd_proc *proc;
	struct dd_mmap_control *control;
	int num_ctr_pg;
	int num_md_pg;
	int num_mapped_pg;
	unsigned long mapped_ino[MAX_NUM_INO_PER_USER_REQUEST];
};

static inline int __is_ctr_page_full(struct dd_mmap_control *control)
{
	if (control->num_requests == MAX_NUM_REQUEST_PER_CONTROL)
		return 1;

	return 0;
}

static inline struct dd_user_req *__get_next_user_req(struct dd_mmap_control *control)
{
	if (control->num_requests >= MAX_NUM_REQUEST_PER_CONTROL) {
		return NULL;
	}

	return &control->requests[control->num_requests++];
}

/**
 * Returns control page from current transaction
 */
static inline struct dd_mmap_control *__get_next_ctr_page(struct dd_transaction *t)
{
	struct dd_proc *proc = t->proc;
	unsigned long control_area_addr = proc->control_vma->vm_start;
	struct dd_mmap_control *control;

	control = (struct dd_mmap_control *) page_address(proc->control_page[t->num_ctr_pg]);
	memset((void *)control, 0, sizeof(struct dd_mmap_control));

	dd_memory("mapping text pages control:%p (struct page:%p num_ctr:%d)\n",
			(void *)control, (void *)proc->control_page[t->num_ctr_pg],
			t->num_ctr_pg);

	remap_pfn_range(proc->control_vma,
			control_area_addr + (t->num_ctr_pg << PAGE_SHIFT),
			page_to_pfn(proc->control_page[t->num_ctr_pg]), PAGE_SIZE,
			proc->control_vma->vm_page_prot);

	t->num_ctr_pg++;

	dd_memory("mapping control page proc:%p control:%p [mapped pages:%d] [total control pages:%d]\n",
			proc,
			(void *) (control_area_addr + (t->num_ctr_pg << PAGE_SHIFT)),
			t->num_mapped_pg, t->num_ctr_pg);

	BUG_ON(t->num_ctr_pg > MAX_NUM_CONTROL_PAGE);
	return control;
}

/**
 * Map if current transaction hasn't yet mapped meta-data page
 */
static inline void __get_md_page(struct dd_proc *proc, struct page *mdpage,
		unsigned long int ino, struct dd_transaction *t)
{
	int i = 0;
	unsigned long metadata_area_addr = proc->metadata_vma->vm_start;

	while (i < t->num_md_pg) {
		if (t->mapped_ino[i] == ino)
			return;
		i++;
	}

	dd_memory("mapping metadata area proc:%p md:%p (num_md:%d, num_ctr:%d) [ino:%ld]\n",
			proc,
			(void *) (metadata_area_addr + (t->num_md_pg << PAGE_SHIFT)),
			t->num_md_pg, t->num_ctr_pg, ino);
	remap_pfn_range(proc->metadata_vma,
			metadata_area_addr + (t->num_md_pg << PAGE_SHIFT),
			page_to_pfn(mdpage), PAGE_SIZE,
			proc->metadata_vma->vm_page_prot);
	t->mapped_ino[i] = ino;
	t->num_md_pg++;
}

#ifdef CONFIG_DDAR_USER_PREPARE
static dd_transaction_result __process_prepare_request_locked(
		struct dd_req *req, struct dd_transaction *t)
{
	// create single user space request for prepare
	struct dd_user_req *p = __get_next_user_req(t->control);
	p->unique = req->unique;
	p->userid = req->info->crypt_context.policy.userid;
	p->version = req->info->crypt_context.policy.version;
	p->ino = req->info->inode->i_ino;
	p->code = DD_REQ_PREPARE;

	return DD_TRANS_OK;
}
#endif

static dd_transaction_result __process_bio_request_locked(
		struct dd_req *req, struct dd_transaction *t)
{
	struct dd_proc *proc = t->proc;

	struct bio *orig = req->u.bio.orig;
	struct bio *clone = req->u.bio.clone;
	int dir = bio_data_dir(req->u.bio.orig);
	struct bvec_iter iter_backup;

	unsigned require_ctr_pages;

	/**
	 * NOTE: Do not assume the inode object is still alive at this point.
	 *
	 * It's possible bio was requested for a file's dirty page and the file gets
	 * removed before it's scheduled for crypto operation. In such case the inode
	 * object is freed; dd_info->inode points to NULL as well.
	 *
	 * At the very least, dd_info maintains refcount dd_info will be still alive until
	 * the request completes
	 */
	BUG_ON(!req->info);

	/**
	 * page count limit check. If current bio holds more pages than current user space
	 * transaction can mmap, postpone this to next round. Skipped bio will stay in
	 * pending queue until next dd_ioctl_wait_crypto_request() is called.
	 *
	 * We don't support splitting single bio into multiple user space request to avoid
	 * extra memory copy and keep code straight-forward.
	 */
	require_ctr_pages = (orig->bi_vcnt / MAX_NUM_REQUEST_PER_CONTROL);
	if (orig->bi_vcnt % MAX_NUM_REQUEST_PER_CONTROL > 0)
		require_ctr_pages++;

	if (require_ctr_pages > (MAX_NUM_CONTROL_PAGE - t->num_ctr_pg)) {
		dd_verbose("cannot accommodate %d control pages (%d available), continue\n",
				require_ctr_pages, MAX_NUM_CONTROL_PAGE - t->num_ctr_pg);
		return DD_TRANS_ERR_FULL;
	}

//	dd_verbose("%s mapping bio(vcnt:%d, ino:%ld) control available:%d (required:%d)\n",
//			__func__, orig->bi_vcnt, req->ino,
//			MAX_NUM_CONTROL_PAGE - t->num_ctr_pg, require_ctr_pages);

	spin_unlock(&proc->lock);

	// map pages in bio to user space vma
	BUG_ON(dir == WRITE && !clone);

	// back up bio iterator. restore before submitting it to block layer
	memcpy(&iter_backup, &orig->bi_iter, sizeof(struct bvec_iter));

	while (orig->bi_iter.bi_size) {
		int vm_offset = t->num_mapped_pg << PAGE_SHIFT;
		struct dd_user_req *p = __get_next_user_req(t->control);

		if (!p) {
			t->control = __get_next_ctr_page(t);
			continue; // try again
		}

		dd_verbose("bi_size:%d (control->num_requests:%d)\n",
				orig->bi_iter.bi_size, t->control->num_requests);
		p->unique = req->unique;
		p->userid = req->info->policy.userid;
		p->version = req->info->policy.version;
		p->ino = req->info->ino;
		p->code = DD_REQ_CRYPTO_BIO;
		if (dir == WRITE) {
			struct bio_vec orig_bv = bio_iter_iovec(orig, orig->bi_iter);
			struct bio_vec clone_bv = bio_iter_iovec(clone, clone->bi_iter);
			struct page *plaintext_page = orig_bv.bv_page;
			struct page *ciphertext_page = clone_bv.bv_page;

			BUG_ON(req->info->ino != orig_bv.bv_page->mapping->host->i_ino);

			p->u.bio.rw = DD_ENCRYPT;
			p->u.bio.index = plaintext_page->index;
			p->u.bio.plain_addr = proc->plaintext_vma->vm_start + vm_offset;
			p->u.bio.cipher_addr = proc->ciphertext_vma->vm_start + vm_offset;

			remap_pfn_range(proc->plaintext_vma,
					p->u.bio.plain_addr, page_to_pfn(plaintext_page), PAGE_SIZE,
					proc->plaintext_vma->vm_page_prot);
			remap_pfn_range(proc->ciphertext_vma,
					p->u.bio.cipher_addr, page_to_pfn(ciphertext_page), PAGE_SIZE,
					proc->ciphertext_vma->vm_page_prot);

			dd_dump("plain page", page_address(plaintext_page), PAGE_SIZE);
			bio_advance_iter(orig, &orig->bi_iter, 1 << PAGE_SHIFT);
			bio_advance_iter(clone, &clone->bi_iter, 1 << PAGE_SHIFT);
		} else {
			struct bio_vec orig_bv = bio_iter_iovec(orig, orig->bi_iter);
			struct page *ciphertext_page = orig_bv.bv_page;

			BUG_ON(req->info->ino != orig_bv.bv_page->mapping->host->i_ino);

			p->u.bio.rw = DD_DECRYPT;
			// crypto inplace decryption
			p->u.bio.index = ciphertext_page->index;
			p->u.bio.cipher_addr = proc->ciphertext_vma->vm_start + vm_offset;
			p->u.bio.plain_addr = proc->ciphertext_vma->vm_start + vm_offset;
			remap_pfn_range(proc->ciphertext_vma,
					p->u.bio.cipher_addr, page_to_pfn(ciphertext_page), PAGE_SIZE,
					proc->ciphertext_vma->vm_page_prot);

			dd_dump("cipher page", page_address(ciphertext_page), PAGE_SIZE);
			bio_advance_iter(orig, &orig->bi_iter, 1 << PAGE_SHIFT);
		}

		t->num_mapped_pg++;

		dd_memory("remap_pfn_range(plain:%p cipher:%p) dir:%d t->num_mapped_pg:%d\n",
				(void *)p->u.bio.plain_addr, (void *)p->u.bio.cipher_addr, dir, t->num_mapped_pg);
	}

	dd_memory("done mapping req:[%d] restore bi_iter\n", req->unique);
	memcpy(&orig->bi_iter, &iter_backup, sizeof(struct bvec_iter));
	if (dir == WRITE)
		memcpy(&clone->bi_iter, &iter_backup, sizeof(struct bvec_iter));

	spin_lock(&proc->lock);

	return DD_TRANS_OK;
}

static dd_transaction_result __process_page_request_locked(
		struct dd_req *req,  struct dd_transaction *t)
{
	struct dd_proc *proc = t->proc;
	int vm_offset = t->num_mapped_pg << PAGE_SHIFT;
	struct dd_user_req *p = NULL;
	dd_crypto_direction_t dir = req->u.page.dir;
	unsigned require_ctr_pages = 1;

	BUG_ON(!req->info);

	if (require_ctr_pages > (MAX_NUM_CONTROL_PAGE - t->num_ctr_pg)) {
		dd_verbose("cannot accommodate %d control pages (%d available), continue\n",
				require_ctr_pages, MAX_NUM_CONTROL_PAGE - t->num_ctr_pg);
		return DD_TRANS_ERR_FULL;
	}

	p = __get_next_user_req(t->control);
	if (!p) {
		spin_unlock(&proc->lock);
		t->control = __get_next_ctr_page(t);
		spin_lock(&proc->lock);
		p = __get_next_user_req(t->control);
	}

	p->unique = req->unique;
	p->userid = req->info->policy.userid;
	p->version = req->info->policy.version;
	p->ino = req->info->ino;
	p->code = DD_REQ_CRYPTO_PAGE;

	p->u.bio.rw = dir;

	spin_unlock(&proc->lock);
	if (dir == DD_DECRYPT) {
		struct page *ciphertext_page = req->u.page.src_page;

		p->u.bio.index = ciphertext_page->index;
		p->u.bio.cipher_addr = proc->ciphertext_vma->vm_start + vm_offset;
		p->u.bio.plain_addr = proc->ciphertext_vma->vm_start + vm_offset;
		remap_pfn_range(proc->ciphertext_vma,
				p->u.bio.cipher_addr, page_to_pfn(ciphertext_page), PAGE_SIZE,
				proc->ciphertext_vma->vm_page_prot);

		dd_dump("cipher page", page_address(ciphertext_page), PAGE_SIZE);
		t->num_mapped_pg++;
	} else {
		BUG();
	}
	spin_lock(&proc->lock);

	return DD_TRANS_OK;
}

/**
 * process_request - mmap requested bio to user address space
 * as defined in dd_proc's vma fields
 */
int process_request(struct dd_proc *proc, struct dd_transaction *t)
__releases(proc->lock)
__acquires(proc->lock)
{
	struct dd_req *req, *temp;

	memset(t, 0, sizeof(struct dd_transaction));
	t->proc = proc;
	t->control = NULL;
	spin_lock(&proc->lock);

	list_for_each_entry_safe(req, temp, &proc->pending, list) {
		dd_transaction_result result = DD_TRANS_ERR_UNKNOWN;

		if (t->num_md_pg >= MAX_NUM_INO_PER_USER_REQUEST-1) {
			dd_verbose("can't assign more metadata page (num-ctlpage:%d)\n", t->num_ctr_pg);
			break;
		}

		spin_unlock(&proc->lock);
		if (!t->control || __is_ctr_page_full(t->control))
			t->control = __get_next_ctr_page(t);
		spin_lock(&proc->lock);

		dd_debug_req("req <processing>", DD_DEBUG_PROCESS, req);
		dd_verbose("retrieve req [unique:%d] [code:%d] [ino:%ld] [num_pg:%d] [num_md:%d] [num_ctr:%d]\n",
				req->unique, req->code, req->ino, t->num_mapped_pg, t->num_md_pg, t->num_ctr_pg);
		switch (req->code) {
		case DD_REQ_PREPARE:
		{
#ifdef CONFIG_DDAR_USER_PREPARE
			result = __process_prepare_request_locked(req, t);
#endif
			break;
		}
		case DD_REQ_CRYPTO_BIO:
			result = __process_bio_request_locked(req, t);
			break;
		case DD_REQ_CRYPTO_PAGE:
			result = __process_page_request_locked(req, t);
			break;
		default:
			dd_error("unknown req code:%d\n", req->code);
		}

		BUG_ON(!req->info);
		BUG_ON(t->num_ctr_pg > MAX_NUM_CONTROL_PAGE);

		if (result == DD_TRANS_ERR_FULL) {
			break;
		}

		// todo: handle error when daemon process is not running at this moment
		if (result != DD_TRANS_OK) {
			continue;
		}
		// map meta-data page if not mapped in current transaction
		spin_unlock(&proc->lock);
		__get_md_page(proc, req->info->mdpage, req->ino, t);
		spin_lock(&proc->lock);

		list_move(&req->list, &proc->processing);
		dd_req_state(req, DD_REQ_PROCESSING);
	}
	spin_unlock(&proc->lock);

	return 0;
}

long dd_ioctl_wait_crypto_request(struct dd_proc *proc, struct dd_ioc *ioc)
{
	int rc = 0;
	int err = 0;
	struct dd_transaction t;

	memset(&t, 0, sizeof(struct dd_transaction));

	if (!dd_mmap_available(proc)) {
		dd_error("dd_ioctl_wait_crypto_request: user space memory not registered\n");
		return -ENOMEM;
	}

	spin_lock(&proc->lock);
	dd_verbose("waiting req (current:%p, pid:%p)\n", current, proc);
	if (list_empty(&proc->pending)) {
		DECLARE_WAITQUEUE(wait, current);
		add_wait_queue_exclusive(&proc->waitq, &wait);

		while (!proc->abort && list_empty(&proc->pending)) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (signal_pending(current)) {
				dd_error("dd_ioctl_wait_crypto_request() received signal in interruptible process state\n");
				rc = -EINTR;
				break;
			}

			spin_unlock(&proc->lock);
			freezable_schedule_timeout(msecs_to_jiffies(2000));
			spin_lock(&proc->lock);
		}

		set_current_state(TASK_RUNNING);
		remove_wait_queue(&proc->waitq, &wait);
	}

	spin_unlock(&proc->lock);

	if (proc->abort) {
		dd_error("process abort\n");
		return -EPIPE;
	}

	if (rc) {
		dd_error("dd_ioctl_wait_crypto_request() failed, try again :%d\n", rc);
		return rc;
	}

	dd_verbose("dd_ioctl_wait_crypto_request: retrieving req pid:%p\n", proc);

	err = process_request(proc, &t);
	if (!err) {
		dd_verbose("process_request: control:%d metadata:%d\n",
				t.num_ctr_pg, t.num_md_pg);
		ioc->u.crypto_request.num_control_page = t.num_ctr_pg;
		ioc->u.crypto_request.num_metadata_page = t.num_md_pg;
	}
	return err;
}

long dd_ioctl_submit_crypto_result(struct dd_proc *proc,
		struct dd_user_resp *errs, int num_err)
{
	struct dd_req *req, *temp;
	blk_qc_t ret;

	// should never happen. proc object is freed only when user thread dies or close() the fd
	BUG_ON(!proc);

	spin_lock(&proc->lock);
	list_for_each_entry_safe(req, temp, &proc->processing, list) {
		int err = get_user_resp_err(errs, num_err, req->ino);
		list_move(&req->list, &proc->submitted);
		dd_req_state(req, DD_REQ_SUBMITTED);
		spin_unlock(&proc->lock);

		dd_debug_req("req <submitted>", DD_DEBUG_PROCESS, req);
		if (err) {
			dd_error("req :%d (ino:%ld) failed err:%d\n", req->code, req->ino, err);
			abort_req(__func__, req, -EIO);
		} else {
			switch (req->code) {
			case DD_REQ_CRYPTO_BIO:
			{
				int dir = bio_data_dir(req->u.bio.orig);

				if (dir == WRITE) {
					dd_dump_bio_pages("inner encryption done", req->u.bio.clone);

					if (fscrypt_inode_uses_inline_crypto(req->info->inode)) {
						dd_verbose("skip oem s/w crypt. hw encryption enabled\n");
//						fscrypt_set_ice_dun(req->info->inode, req->u.bio.clone, 0/* temporary */);
					} else {
						if (dd_oem_crypto_bio_pages(req, WRITE, req->u.bio.clone)) {
							abort_req(__func__, req, -EIO);
							goto err_continue;
						}

						dd_dump_bio_pages("outter (s/w) encryption done", req->u.bio.clone);
					}

					req->u.bio.clone->bi_status = err;
					req->u.bio.clone->bi_end_io = dd_end_io;
					ret = submit_bio(req->u.bio.clone);
				} else {
					dd_dump_bio_pages("inner decryption done", req->u.bio.orig);

					bio_endio(req->u.bio.orig);
					put_req(__func__, req);
				}
			}
			break;
			case DD_REQ_CRYPTO_PAGE:
			case DD_REQ_PREPARE:
				/**
				 * do nothing: this will wake up process waiting for user
				 * space request and it is kernel service's responsibility
				 * to free req object
				 */
				break;
			case DD_REQ_INVALID:
			default:
				break;
			}
		}

		wake_up_interruptible(&req->waitq);

err_continue:
		spin_lock(&proc->lock);
	}
	spin_unlock(&proc->lock);

	return 0;
}

struct ioc_set_xattr_work {
	struct work_struct work;
	struct inode *inode;
	char name[MAX_XATTR_NAME_LEN];
	char value[MAX_XATTR_LEN];
	int size;
};

static void dd_write_metadata_work(struct work_struct *work)
{
	struct ioc_set_xattr_work *ioc_work = container_of(work, struct ioc_set_xattr_work, work);

	dd_write_crypto_metadata(ioc_work->inode,
			ioc_work->name, ioc_work->value, ioc_work->size);

	dd_verbose("dd_write_metadata_work %ld complete (i_state:0x%x)\n",
			ioc_work->inode->i_ino, ioc_work->inode->i_state);

	iput(ioc_work->inode);
	kfree(ioc_work);
}

long dd_ioctl_add_crypto_proc(struct file *filp)
{
	struct dd_proc *proc = kzalloc(sizeof(*proc), GFP_KERNEL);
	int i;

	if (proc == NULL)
		return -ENOMEM;

	spin_lock_init(&proc->lock);

	proc->context = dd_context_global;

	INIT_LIST_HEAD(&proc->proc_node);

	proc->abort = 0;
	init_waitqueue_head(&proc->waitq);

	INIT_LIST_HEAD(&proc->pending);
	INIT_LIST_HEAD(&proc->processing);
	INIT_LIST_HEAD(&proc->submitted);

	filp->private_data = (void *) proc;
	proc->pid = current->pid;
	proc->tgid = current->tgid;
	proc->control_vma = NULL;
	proc->metadata_vma = NULL;
	proc->plaintext_vma = NULL;
	proc->ciphertext_vma = NULL;
	proc->num_control_page = 0;
	for (i = 0; i < MAX_NUM_CONTROL_PAGE; i++) {
		proc->control_page[i] = mempool_alloc(proc->context->page_pool, GFP_NOWAIT);
		if (!proc->control_page[i])
			goto nomem_out;
	}

	atomic_set(&proc->reqcount, 1);

	spin_lock(&dd_context_global->lock);
	list_add_tail(&proc->proc_node, &dd_context_global->procs);
	spin_unlock(&dd_context_global->lock);
	dd_info("process %p (pid:%d, tgid:%d) added\n", proc, proc->pid, proc->tgid);

	return 0;

nomem_out:
	for (i = 0; i < MAX_NUM_CONTROL_PAGE; i++)
		if (proc->control_page[i])
			mempool_free(proc->control_page[i], proc->context->page_pool);

	return -ENOMEM;
}

long dd_ioctl_remove_crypto_proc(int userid)
{
	struct dd_context *ctx = dd_context_global;
	struct dd_proc *proc = NULL;

	spin_lock(&dd_context_global->lock);
	list_for_each_entry(proc, &ctx->procs, proc_node) {
		proc->abort = 1;
		wake_up(&proc->waitq);
	}
	spin_unlock(&dd_context_global->lock);
	return 0;
}

static long dd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct dd_proc *proc = (struct dd_proc *) filp->private_data;
	struct dd_req *req = NULL;
	struct dd_ioc ioc;
	struct inode *inode;
	int err;

	if (copy_from_user(&ioc, (void __user *) arg, sizeof(struct dd_ioc)))
		return -EFAULT;

	switch (cmd) {
	case DD_IOCTL_REGISTER_CRYPTO_TASK:
	{
		dd_info("DD_IOCTL_REGISTER_CRYPTO_TASK");

		return dd_ioctl_add_crypto_proc(filp);
	}
	case DD_IOCTL_UNREGISTER_CRYPTO_TASK:
	{
		dd_info("DD_IOCTL_UNREGISTER_CRYPTO_TASK");
		return dd_ioctl_remove_crypto_proc(0);
	}
	case DD_IOCTL_GET_DEBUG_MASK:
	{
		dd_verbose("DD_IOCTL_GET_DEBUG_MASK");
		ioc.u.debug_mask = dd_debug_mask;
		if (copy_to_user((void __user *)arg, &ioc, sizeof(struct dd_ioc))) {
			return -EFAULT;
		}
		break;
	}
	case DD_IOCTL_SEND_LOG:
	{
		__dd_debug(ioc.u.log_msg.mask, "dualdard", "%s", ioc.u.log_msg.buf);
		break;
	}
	case DD_IOCTL_UPDATE_LOCK_STATE:
	{
		int old_state = dd_lock_state;
		dd_lock_state = ioc.u.lock.state;
		dd_verbose("DD_IOCTL_UPDATE_LOCK_STATE: %d\n", dd_lock_state);

		if (old_state != dd_lock_state) {
			if (dd_lock_state) {
				dd_error("ddar locked. trigger cache invalidation");
			}
		}

		return 0;
	}
	/* { KNOX_SUPPORT_DAR_DUAL_DO */
	case DD_IOCTL_GET_LOCK_STATE:
	{
		dd_verbose("DD_IOCTL_GET_LOCK_STATE : %u", dd_lock_state);

		ioc.u.lock.state = dd_lock_state;
		if (copy_to_user((void __user *)arg, &ioc, sizeof(unsigned int))) {
			return -EFAULT;
		}

		return 0;
	}
	/* } KNOX_SUPPORT_DAR_DUAL_DO */
#if USE_KEYRING
	case DD_IOCTL_ADD_KEY:
	case DD_IOCTL_EVICT_KEY:
		dd_error("use keyring (no driver support)\n");
		return -EOPNOTSUPP;
#else
	case DD_IOCTL_ADD_KEY:
		dd_info("DD_IOCTL_ADD_KEY");
		return dd_add_master_key(ioc.u.add_key.userid,
				ioc.u.add_key.key, ioc.u.add_key.len);
	case DD_IOCTL_EVICT_KEY:
		dd_info("DD_IOCTL_EVICT_KEY");
		dd_evict_master_key(ioc.u.evict_key.userid);
		return 0;
	case DD_IOCTL_DUMP_KEY:
		dd_info("DD_IOCTL_DUMP_KEY");
#ifdef CONFIG_SDP_KEY_DUMP
		err = dd_dump_key(ioc.u.dump_key.userid,
				ioc.u.dump_key.fileDescriptor);
		return err;
#else
		return 0;
#endif
#endif
	case DD_IOCTL_SKIP_DECRYPTION_BOTH:
	{
		struct fd f = {NULL, 0};
		struct inode *inode;
		struct dd_crypt_context crypt_context;

		dd_info("DD_IOCTL_SKIP_DECRYPTION_BOTH");

		f = fdget(ioc.u.dump_key.fileDescriptor);
		if (unlikely(f.file == NULL)) {
			dd_error("invalid fd : %d\n", ioc.u.dump_key.fileDescriptor);
			return -EINVAL;
		}
		inode = f.file->f_path.dentry->d_inode;
		if (!inode) {
			dd_error("invalid inode address\n");
			return -EBADF;
		}
		if (dd_read_crypt_context(inode, &crypt_context) != sizeof(struct dd_crypt_context)) {
			dd_error("failed to read dd crypt context - ino:%ld\n", inode->i_ino);
			return -EINVAL;
		}
		crypt_context.policy.flags |= DD_POLICY_SKIP_DECRYPTION_INNER;
		crypt_context.policy.flags |= DD_POLICY_SKIP_DECRYPTION_OUTER;
		if (dd_write_crypt_context(inode, &crypt_context, NULL)) {
			dd_error("failed to write dd crypt context - ino:%ld\n", inode->i_ino);
			return -EINVAL;
		}
		dd_info("updated policy - ino:%ld\n", inode->i_ino);

		return 0;
	}
	case DD_IOCTL_SKIP_DECRYPTION_INNER:
	{
		struct fd f = { NULL, 0 };
		struct inode *inode;
		struct dd_crypt_context crypt_context;

		dd_info("DD_IOCTL_SKIP_DECRYPTION_INNER");

		f = fdget(ioc.u.dump_key.fileDescriptor);
		if (unlikely(f.file == NULL)) {
			dd_error("invalid fd : %d\n", ioc.u.dump_key.fileDescriptor);
			return -EINVAL;
		}
		inode = f.file->f_path.dentry->d_inode;
		if (!inode) {
			dd_error("invalid inode address\n");
			return -EBADF;
		}
		if (dd_read_crypt_context(inode, &crypt_context) != sizeof(struct dd_crypt_context)) {
			dd_error("failed to read dd crypt context - ino:%ld\n", inode->i_ino);
			return -EINVAL;
		}
		crypt_context.policy.flags &= ~DD_POLICY_SKIP_DECRYPTION_OUTER;
		crypt_context.policy.flags |= DD_POLICY_SKIP_DECRYPTION_INNER;
		if (dd_write_crypt_context(inode, &crypt_context, NULL)) {
			dd_error("failed to write dd crypt context - ino:%ld\n", inode->i_ino);
		}
		dd_info("updated policy - ino:%ld\n", inode->i_ino);

		return 0;
	}
	case DD_IOCTL_NO_SKIP_DECRYPTION:
	{
		struct fd f = { NULL, 0 };
		struct inode *inode;
		struct dd_crypt_context crypt_context;

		dd_info("DD_IOCTL_NO_SKIP_DECRYPTION");

		f = fdget(ioc.u.dump_key.fileDescriptor);
		if (unlikely(f.file == NULL)) {
			dd_error("invalid fd : %d\n", ioc.u.dump_key.fileDescriptor);
			return -EINVAL;
		}
		inode = f.file->f_path.dentry->d_inode;
		if (!inode) {
			dd_error("invalid inode address\n");
			return -EBADF;
		}
		if (dd_read_crypt_context(inode, &crypt_context) != sizeof(struct dd_crypt_context)) {
			dd_error("failed to read dd crypt context - ino:%ld\n", inode->i_ino);
			return -EINVAL;
		}
		crypt_context.policy.flags &= ~DD_POLICY_SKIP_DECRYPTION_OUTER;
		crypt_context.policy.flags &= ~DD_POLICY_SKIP_DECRYPTION_INNER;
		if (dd_write_crypt_context(inode, &crypt_context, NULL)) {
			dd_error("failed to write dd crypt context - ino:%ld\n", inode->i_ino);
		}
		dd_info("updated policy - ino:%ld\n", inode->i_ino);

		return 0;
	}
	case DD_IOCTL_TRACE_DDAR_FILE: {
#ifdef CONFIG_SDP_KEY_DUMP
		struct fd f = { NULL, 0 };
		struct inode *inode;
		struct dd_crypt_context crypt_context;

		dd_info("DD_IOCTL_TRACE_DDAR_FILE");

		f = fdget(ioc.u.dump_key.fileDescriptor);
		if (unlikely(f.file == NULL)) {
			dd_error("invalid fd : %d\n", ioc.u.dump_key.fileDescriptor);
			return -EINVAL;
		}
		inode = f.file->f_path.dentry->d_inode;
		if (!inode) {
			dd_error("invalid inode address\n");
			return -EBADF;
		}
		if (dd_read_crypt_context(inode, &crypt_context) != sizeof(struct dd_crypt_context)) {
			dd_error("failed to read dd crypt context - ino:%ld\n", inode->i_ino);
			return -EINVAL;
		}
		crypt_context.policy.flags |= DD_POLICY_TRACE_FILE;
		if (dd_write_crypt_context(inode, &crypt_context, NULL)) {
			dd_error("failed to write dd crypt context - ino:%ld\n", inode->i_ino);
		}
		fscrypt_dd_trace_inode(inode);
		dd_info("updated policy - ino:%ld\n", inode->i_ino);
#endif

		return 0;
	}
	case DD_IOCTL_DUMP_REQ_LIST:
	{
		dd_info("DD_IOCTL_DUMP_REQ_LIST");

		dd_dump_debug_req_list(DD_DEBUG_INFO);
		return 0;
	}
	case DD_IOCTL_ABORT_PENDING_REQ_TIMEOUT:
	{
		dd_info("DD_IOCTL_ABORT_LONG_PENDING_REQ");

		dd_abort_pending_req_timeout(DD_DEBUG_INFO);
		return 0;
	}
	case DD_IOCTL_GET_MMAP_LAYOUT:
	{
		dd_verbose("DD_IOCTL_GET_MMAP_LAYOUT");
		memcpy(&ioc.u.layout, dd_context_global->layout, sizeof(struct dd_mmap_layout));
		if (copy_to_user((void __user *)arg, &ioc, sizeof(struct dd_ioc))) {
			return -EFAULT;
		}

		return 0;
	}
	case DD_IOCTL_WAIT_CRYPTO_REQUEST:
	{
		int rc;

		BUG_ON(!proc); // caller is not a crypto task
		rc = dd_ioctl_wait_crypto_request(proc, &ioc);
		if (rc < 0) {
			dd_error("DD_IOCTL_WAIT_CRYPTO_REQUEST failed :%d\n", rc);
			return rc;
		}

		if (copy_to_user((void __user *)arg, &ioc, sizeof(struct dd_ioc))) {
			return -EFAULT;
		}

		dd_verbose("DD_IOCTL_WAIT_CRYPTO_REQUEST finish rc:%d\n", rc);
		break;
	}
	case DD_IOCTL_SUBMIT_CRYPTO_RESULT:
	{
		BUG_ON(!proc); // caller is not a crypto task

		dd_verbose("DD_IOCTL_SUBMIT_CRYPTO_RESULT\n");
		return dd_ioctl_submit_crypto_result(proc, ioc.u.crypto_response.err,
				ioc.u.crypto_response.num_err);
	}
	case DD_IOCTL_ABORT_CRYPTO_REQUEST:
	{
		dd_verbose("DD_IOCTL_ABORT_CRYPTO_REQUEST\n");
		proc_abort_req_all("DD_IOCTL_ABORT_CRYPTO_REQUEST", proc);
		return 0;
	}
	case DD_IOCTL_GET_XATTR:
	{
		BUG_ON(!proc); // caller is not a crypto task

		req = find_req(proc, DD_REQ_PROCESSING, ioc.u.xattr.ino);
		if (!req) {
			dd_error("request not found for ino:%ld!\n", ioc.u.xattr.ino);
			return -EBADF;
		}
		inode = req->info->inode;
		if (!inode) {
			dd_error("DD_IOCTL_GET_XATTR: invalid info->inode address. Ignore\n");
			return -EBADF;
		}

		err = dd_read_crypto_metadata(inode,
				ioc.u.xattr.name, ioc.u.xattr.value, MAX_XATTR_LEN);
		if (err < 0) {
			dd_verbose("failed to read crypto metadata name:%s err:%d\n", ioc.u.xattr.name, err);
			return err;
		}

		ioc.u.xattr.size = err;
		if (copy_to_user((void __user *)arg, &ioc, sizeof(struct dd_ioc)))
			return -EFAULT;

		return 0;
	}
	case DD_IOCTL_SET_XATTR:
	{
		struct ioc_set_xattr_work *ioc_work = kmalloc(sizeof(struct ioc_set_xattr_work), GFP_KERNEL);
		if (!ioc_work) {
			dd_error("DD_IOCTL_SET_XATTR - failed to allocate memory\n");
			return -ENOMEM;
		}

		dd_verbose("DD_IOCTL_SET_XATTR %ld\n", ioc.u.xattr.ino);
		BUG_ON(!proc); // caller is not a crypto task

		if (ioc.u.xattr.size > MAX_XATTR_LEN) {
			dd_error("DD_IOCTL_SET_XATTR - invalid input\n");
			kfree(ioc_work);
			return -EINVAL;
		}

		req = find_req(proc, DD_REQ_PROCESSING, ioc.u.xattr.ino);
		if (!req) {
			dd_error("request not found for ino:%ld!\n", ioc.u.xattr.ino);
			kfree(ioc_work);
			return -EBADF;
		}
		inode = req->info->inode;
		if (!inode) {
			dd_error("DD_IOCTL_SET_XATTR: invalid info->inode address. Ignore\n");
			kfree(ioc_work);
			return -EBADF;
		}

		ioc_work->inode = req->info->inode;
		memcpy(ioc_work->name, ioc.u.xattr.name, MAX_XATTR_NAME_LEN);
		memcpy(ioc_work->value, ioc.u.xattr.value, ioc.u.xattr.size);
		ioc_work->size = ioc.u.xattr.size;

		if (!igrab(ioc_work->inode)) {
			dd_error("failed to grab inode refcount. this inode may be getting removed\n");
			kfree(ioc_work);
			return 0;
		}

		INIT_WORK(&ioc_work->work, dd_write_metadata_work);
		queue_work(dd_ioctl_workqueue, &ioc_work->work);

		req->need_xattr_flush = 1;
		return 0;
	}
	default:
		return -ENOTTY;
	}
	return 0;
}

static int dd_release(struct inode *node, struct file *filp)
{
	struct dd_proc *proc = filp->private_data;

	if (proc) {
		struct dd_context *ctx = proc->context;

		dd_info("process %p (pid:%d tgid:%d) released\n", proc, proc->pid, proc->tgid);

		spin_lock(&ctx->lock);
		list_del(&proc->proc_node);
		spin_unlock(&ctx->lock);

		proc_abort_req_all(__func__, proc);

		proc->abort = 1;
		dd_proc_try_free(proc);
	}

	return 0;
}

static ssize_t dd_read(struct file *filp, char __user *ubuf, size_t len, loff_t *offset)
{
	return 0;
}

ssize_t dd_write(struct file *filp, const char __user *ubuf, size_t len, loff_t *offset)
{
	return 0;
}

const struct file_operations dd_dev_operations = {
		.owner = THIS_MODULE,
		.unlocked_ioctl = dd_ioctl,
		.compat_ioctl = dd_ioctl,
		.mmap = dd_mmap,
		.open = dd_open,
		.release = dd_release,
		.read = dd_read,
		.write = dd_write,
};

static struct miscdevice dd_miscdevice = {
		.minor = MISC_DYNAMIC_MINOR,
		.name  = "dd",
		.fops = &dd_dev_operations,
};

static int enforce_caller_gid(uid_t uid)
{
	struct group_info *group_info;
	int i;

	if (!uid_is_app(uid)) {
		return 0;
	}

	group_info = get_current_groups();
	for (i = 0; i < group_info->ngroups; i++) {
		kgid_t gid = group_info->gid[i];
		if (gid.val == AID_VENDOR_DDAR_DE_ACCESS) {
			goto enforce;
		}
	}

	return 0;
enforce:
	{
		char msg[256];
		snprintf(msg, 128, "gid restricted uid:%d pid:%d gids:\n", uid, current->tgid);

		for (i = 0; i < group_info->ngroups; i++) {
			kgid_t gid = group_info->gid[i];
			if (gid.val == AID_VENDOR_DDAR_DE_ACCESS) {
				snprintf(msg, 128, "%s %d", msg, gid.val);
				break;
			}
		}
		dd_info("%s\n", msg);
	}
	return -1;
}

static struct kmem_cache *ext4_dd_info_cachep;

struct dd_info *alloc_dd_info(struct inode *inode,
				const struct dd_policy *dd_policy, struct dd_crypt_context *crypt_context)
{
	struct dd_info *info;
	uid_t calling_uid = from_kuid(&init_user_ns, current_uid());
	unsigned char master_key[256];
	int rc = 0;
	sdp_fs_command_t *cmd = NULL;

	if (!dd_policy) {
		dd_error("alloc_dd_info: dd_policy is null (ino:%ld)\n", inode->i_ino);
		return ERR_PTR(-EINVAL);
	}

	BUG_ON(!ext4_dd_info_cachep);

	if (S_ISREG(inode->i_mode)) {
		if (dd_policy_user_space_crypto(dd_policy->flags)) {
			if (dd_is_user_deamon_locked()) {
				dd_error("dd state locked (dd_lock_state:%d)\n", dd_lock_state);
				return ERR_PTR(-ENOKEY);
			}
		} else if (dd_policy_kernel_crypto(dd_policy->flags)) {
			rc = get_dd_master_key(dd_policy->userid, (void *)master_key);
			if (rc) {
				dd_error("dd state locked (can't find master key for user:%d)\n", dd_policy->userid);
				return ERR_PTR(-ENOKEY);
			}
		}
	}

	if (dd_policy_gid_restriction(dd_policy->flags)) {
		if (enforce_caller_gid(calling_uid)) {
			int partition_id = -1;
			struct dentry *de = NULL;
			de = d_find_alias(inode);
			if (de) {
				partition_id = fscrypt_ddar_get_storage_type(de);
			}

			cmd = sdp_fs_command_alloc(FSOP_AUDIT_FAIL_DE_ACCESS,
					current->tgid, dd_policy->userid, partition_id,
					inode->i_ino, -EACCES, GFP_KERNEL);
			if (cmd) {
				sdp_fs_request(cmd, NULL);
				sdp_fs_command_free(cmd);
			}
			dd_error("gid restricted.. calling-uid:%d ino:%ld\n", calling_uid, inode->i_ino);
			return ERR_PTR(-EACCES);
		}
	}

	if (dd_policy_secure_erase(dd_policy->flags)) {
		mapping_set_sensitive(inode->i_mapping);
	}

	info = kmem_cache_alloc(ext4_dd_info_cachep, GFP_NOFS);
	if (!info) {
		dd_error("failed to allocate dd info\n");
		return ERR_PTR(-ENOMEM);
	}
	memcpy(&info->policy, dd_policy, sizeof(struct dd_policy));

	info->context = (void *) dd_context_global;
	info->inode = inode;
	info->ino = inode->i_ino;
	info->ctfm = NULL;
	info->proc = NULL;
	info->mdpage = NULL;
	spin_lock_init(&info->lock);
	atomic_set(&info->reqcount, 0);
	atomic_set(&info->refcount, 1);

	if (dd_policy_user_space_crypto(dd_policy->flags)) {
		struct metadata_hdr *hdr;

		info->mdpage = alloc_page(GFP_KERNEL);
		hdr = (struct metadata_hdr *) page_address(info->mdpage);
		memset(hdr, 0, sizeof(struct metadata_hdr));
		hdr->ino = inode->i_ino;
		hdr->userid = dd_policy->userid;
		hdr->initialized = 0;

		if (crypt_context == NULL) {
			struct dd_crypt_context temp_crypt_context;
			memset(&temp_crypt_context, 0, sizeof(struct dd_crypt_context));
			memcpy(&temp_crypt_context.policy, dd_policy, sizeof(struct dd_policy));
			memcpy(&info->crypt_context, &temp_crypt_context, sizeof(struct dd_crypt_context));
		} else {
			memcpy(&info->crypt_context, crypt_context, sizeof(struct dd_crypt_context));
		}

#ifdef CONFIG_DDAR_USER_PREPARE
		if (dd_prepare(info)) {
			dd_info_try_free(info);
			return NULL;
		}
#endif
	} else if (dd_policy_kernel_crypto(dd_policy->flags) && S_ISREG(inode->i_mode)) {
		struct crypto_skcipher *ctfm;

		if (crypt_context == NULL) {
			struct dd_crypt_context temp_crypt_context;
			memset(&temp_crypt_context, 0, sizeof(struct dd_crypt_context));
			memcpy(&temp_crypt_context.policy, dd_policy, sizeof(struct dd_policy));
			rc = dd_generate_file_key(dd_policy->userid, &temp_crypt_context);
			if (rc) {
				dd_error("failed to generate file key (ino:%ld)\n", inode->i_ino);
				goto out;
			}
			memcpy(&info->crypt_context, &temp_crypt_context, sizeof(struct dd_crypt_context));
		} else {
			memcpy(&info->crypt_context, crypt_context, sizeof(struct dd_crypt_context));
		}

		ctfm = dd_alloc_ctfm(&info->crypt_context, (void *)master_key);
		if (!ctfm || IS_ERR(ctfm)) {
			rc = ctfm ? PTR_ERR(ctfm) : -ENOMEM;
			goto out;
		}

		info->ctfm = ctfm;

out:
		memzero_explicit(master_key, 256);

		if (rc) {
			dd_info_try_free(info);
			return ERR_PTR(rc);
		}
	} else if (dd_policy_gid_restriction(dd_policy->flags)
			|| dd_policy_kernel_crypto(dd_policy->flags)) {
		if (crypt_context == NULL) {
			struct dd_crypt_context temp_crypt_context;
			memset(&temp_crypt_context, 0, sizeof(struct dd_crypt_context));
			memcpy(&temp_crypt_context.policy, dd_policy, sizeof(struct dd_policy));
			memcpy(&info->crypt_context, &temp_crypt_context, sizeof(struct dd_crypt_context));
		} else {
			memcpy(&info->crypt_context, crypt_context, sizeof(struct dd_crypt_context));
		}
	} else {
		// nothing to do
	}

	dd_process("ino:%ld user:%d flags:0x%04x context:%p\n", inode->i_ino,
			dd_policy->userid, dd_policy->flags, info->context);
	return info;
}

int fscrypt_ddar_get_storage_type(struct dentry *target_dentry)
{
	if (!target_dentry)
		return FSCRYPT_DDAR_NAME_FUNC_ERROR;
	else {
		int p_type = FSCRYPT_DDAR_NAME_FUNC_ERROR;
		struct dentry *t_dentry = target_dentry;

		while (strcasecmp(t_dentry->d_name.name, "/")) {// "/" means "/data"
			if (!strcasecmp(t_dentry->d_name.name, "user")) {
				p_type = FSCRYPT_STORAGE_TYPE_DATA_CE;
			} else if (!strcasecmp(t_dentry->d_name.name, "media")) {
				p_type = FSCRYPT_STORAGE_TYPE_MEDIA_CE;
			} else if (!strcasecmp(t_dentry->d_name.name, "system_ce")) {
				p_type = FSCRYPT_STORAGE_TYPE_SYSTEM_CE;
			} else if (!strcasecmp(t_dentry->d_name.name, "misc_ce")) {
				p_type = FSCRYPT_STORAGE_TYPE_MISC_CE;
			} else if (!strcasecmp(t_dentry->d_name.name, "user_de")) {
				p_type = FSCRYPT_STORAGE_TYPE_DATA_DE;
			} else if (!strcasecmp(t_dentry->d_name.name, "system_de")) {
				p_type = FSCRYPT_STORAGE_TYPE_SYSTEM_DE;
			} else if (!strcasecmp(t_dentry->d_name.name, "misc_de")) {
				p_type = FSCRYPT_STORAGE_TYPE_MISC_DE;
			} else if (!strcasecmp(t_dentry->d_name.name, "enc_user")) {
				p_type = FSCRYPT_STORAGE_TYPE_SDP_ENC_USER;
			} else if (!strcasecmp(t_dentry->d_name.name, "knox")) {
				p_type = FSCRYPT_STORAGE_TYPE_SDP_ENC_EMULATED;
			} else {
				p_type = FSCRYPT_DDAR_NAME_FUNC_ERROR;
			}
			t_dentry = t_dentry->d_parent;
		}

		return p_type;
	}
}

static void dd_info_get(struct dd_info *info)
{
	atomic_inc(&info->refcount);
}

// decrease info->refcount. if new count is 0, free the object
void dd_info_try_free(struct dd_info *info)
{
	if (!info)
		return;

	dd_verbose("info refcount:%d, ino:%ld\n", atomic_read(&info->refcount), info->ino);
	if (atomic_dec_and_test(&info->refcount)) {
		dd_verbose("freeing dd info ino:%ld\n", info->ino);
		if (info->mdpage)
			__free_page(info->mdpage);

		if (info->ctfm)
			crypto_free_skcipher(info->ctfm);

		kmem_cache_free(ext4_dd_info_cachep, info);
	}
}

void dd_init_context(const char *name)
{
	struct dd_context *context = (struct dd_context *) kmalloc(sizeof(struct dd_context), GFP_KERNEL);

	if (context) {
		int ret = 0;
		dd_info("dd_init_context %s\n", name);
		strncpy(context->name, name, sizeof(context->name) - 1);
		context->name[sizeof(context->name) - 1] = 0;

		context->req_ctr = 0;
		spin_lock_init(&context->lock);
		spin_lock_init(&context->ctr_lock);

		INIT_LIST_HEAD(&context->procs);

		spin_lock_init(&context->bm_result.lock);
		/* Enable message ratelimiting. Default is 10 messages per 5 secs. */
		ratelimit_state_init(&context->bm_result.ratelimit_state, 5 * HZ, 10);
		__benchmark_init(&context->bm_result);

		context->layout = &default_mmap_layout;

		mutex_init(&context->bio_alloc_lock);
		context->bio_set = kzalloc(sizeof(struct bio_set), GFP_KERNEL);
		if (!context->bio_set) {
			dd_error("Failed to allocate bioset\n");
			return;
		}
		ret = bioset_init(context->bio_set, 64, 0, (BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER));
		if (ret) {
			dd_error("Failed to init bioset\n");
		}
		context->page_pool = mempool_create_page_pool(256, 0);

		dd_context_global = context;

		// TODO: remove me: this is temporary defence code to enable QA testing
//		abort_thread = kthread_run(abort_req_timeout_thread, NULL, "ddar_abort_req_timeoutd");
//		if (abort_thread) {
//			dd_info("abort req timeout thread created\n");
//		} else {
//			dd_error("Failed to create abort req timeout thread\n");
//		}
	} else {
		dd_error("dd_init_context %s failed\n", name);
	}
}

atomic64_t dd_count;

void set_ddar_count(long count)
{
	atomic64_set(&dd_count, count);
}

long get_ddar_count(void)
{
	long count = atomic64_read(&dd_count);
	return count;
}

void inc_ddar_count(void)
{
	atomic64_inc(&dd_count);
}

void dec_ddar_count(void)
{
	atomic64_dec(&dd_count);
}

static int __init dd_init(void)
{
	int err = -ENOMEM;

	BUG_ON(sizeof(struct metadata_hdr) != METADATA_HEADER_LEN);

	set_ddar_count(0);

	dd_free_req_workqueue = alloc_workqueue("dd_free_req_workqueue", WQ_HIGHPRI, 0);
	if (!dd_free_req_workqueue)
		goto out;

	dd_read_workqueue = alloc_workqueue("dd_read_workqueue", WQ_HIGHPRI, 0);
	if (!dd_read_workqueue)
		goto out;

	dd_ioctl_workqueue = alloc_workqueue("dd_ioctl_workqueue", WQ_HIGHPRI, 0);
	if (!dd_ioctl_workqueue)
		goto out;

	dd_req_cachep = KMEM_CACHE(dd_req, SLAB_RECLAIM_ACCOUNT);
	if (!dd_req_cachep)
		goto out_cache_clean;

	ext4_dd_info_cachep = KMEM_CACHE(dd_info, SLAB_RECLAIM_ACCOUNT);
	if (!ext4_dd_info_cachep)
		goto out_cache_clean;

	err = misc_register(&dd_miscdevice);
	if (err)
		goto out_cache_clean;

	dd_init_context("knox-ddar");

	return 0;

	out_cache_clean:
	destroy_workqueue(dd_free_req_workqueue);
	destroy_workqueue(dd_read_workqueue);
	destroy_workqueue(dd_ioctl_workqueue);
	kmem_cache_destroy(ext4_dd_info_cachep);
	kmem_cache_destroy(dd_req_cachep);
	out:
	return err;
}

module_init(dd_init);

unsigned int dd_debug_mask = 0x03;
module_param_named(debug_mask, dd_debug_mask, uint, 0600);
MODULE_PARM_DESC(debug_mask, "dd driver debug mask");

#define LOGBUF_MAX (512)
void dd_dump(const char *msg, char *buf, int len)
{
	unsigned char logbuf[LOGBUF_MAX];
	int i, j;

	if (!(dd_debug_mask & DD_DEBUG_MEMDUMP))
		return;

	if (len > LOGBUF_MAX)
		len = LOGBUF_MAX;
	memset(logbuf, 0, LOGBUF_MAX);
	i = 0;
	while (i < len) {
		int l = (len-i > 16) ? 16 : len-i;

		snprintf(logbuf, LOGBUF_MAX, "%s\t:", logbuf);

		for (j = 0; j < l; j++) {
			snprintf(logbuf, LOGBUF_MAX, "%s%02hhX", logbuf, buf[i+j]);
			if (j % 2)
				snprintf(logbuf, LOGBUF_MAX, "%s ", logbuf);
		}

		if (l < 16)
			for (j = 0; j < (16 - l); j++) {
				snprintf(logbuf, LOGBUF_MAX, "%s  ", logbuf);
				if (j % 2)
					snprintf(logbuf, LOGBUF_MAX, "%s ", logbuf);
			}

		snprintf(logbuf, LOGBUF_MAX, "%s\t\t", logbuf);

		for (j = 0; j < l; j++)
			snprintf(logbuf, LOGBUF_MAX,
					"%s%c", logbuf, isalnum(buf[i+j]) ? buf[i+j]:'.');

		snprintf(logbuf, LOGBUF_MAX, "%s\n", logbuf);

		i += l;
	}

	printk("knox-dd: %s (%p) %d bytes:\n%s\n", msg, buf, len, logbuf);
}

void dd_dump_bio_pages(const char *msg, struct bio *bio)
{
	struct bio_vec *bv;
	struct bvec_iter_all i;

	if (!(dd_debug_mask & DD_DEBUG_MEMDUMP))
		return;

	dd_verbose("%s: bio bi_flags:%x bi_opf:%x bi_status:%d\n",
			msg, bio->bi_flags, bio->bi_opf, bio->bi_status);

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		BUG_ON(!page); // empty bio
		dd_dump(msg, page_address(page), PAGE_SIZE);
	}
}


void __dd_debug(unsigned int mask,
		const char *func, const char *fmt, ...)
{
	if (dd_debug_bit_test(mask)) {
		struct va_format vaf;
		va_list args;
		int buf_len = 256;
		char buf[256];

		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;

		snprintf(buf, buf_len, "[%.2x:%16.s] %pV", mask, func, &vaf);
		va_end(args);
		printk("knox-dd%s\n", buf);

		if (mask & (DD_DEBUG_ERROR | DD_DEBUG_INFO)) {
			dek_add_to_log(-1, buf);
		}
	}
}
