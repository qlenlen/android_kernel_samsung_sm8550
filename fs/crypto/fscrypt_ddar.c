/*
 * fscrypt_ddar.c
 *
 *  Created on: Oct 15, 2018
 *      Author: olic.moon
 */

#include <linux/bio.h>
#include "fscrypt_private.h"
#include "ddar/ddar_crypto.h"

extern int dd_submit_bio(struct dd_info *info, struct bio *bio);

int update_encryption_context_with_dd_policy(
		struct inode *inode,
		const struct dd_policy *policy)
{
	union fscrypt_context ctx;
	int ret;

	dd_info("update encryption context with dd policy ino:%ld flag:%x\n", inode->i_ino, policy->flags);

	/**
	 * i_rwsem needs to be acquired while setting policy so that new files
	 * cannot be created in the directory during or after the empty_dir() check
	 */
	inode_lock(inode);

	ret = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	switch (ctx.version) {
	case FSCRYPT_CONTEXT_V1: {
		if (ret == offsetof(struct fscrypt_context_v1, knox_flags)) {
			ctx.v1.knox_flags = 0;
			ret = sizeof(ctx.v1);
		}
		break;
	}
	case FSCRYPT_CONTEXT_V2: {
		if (ret == offsetof(struct fscrypt_context_v2, knox_flags)) {
			ctx.v2.knox_flags = 0;
			ret = sizeof(ctx.v2);
		}
		break;
	}
	}

	if (ret == -ENODATA) {
		dd_error("failed to set dd policy. empty fscrypto context\n");
		ret = -EFAULT;
	} else if (ret == fscrypt_context_size(&ctx)) {
		struct fscrypt_info	*ci = inode->i_crypt_info;
		if (ci && ci->ci_policy.version == FSCRYPT_POLICY_V1) {
			ctx.v1.knox_flags |= policy->flags << FSCRYPT_KNOX_FLG_DDAR_SHIFT & FSCRYPT_KNOX_FLG_DDAR_MASK;
			dd_verbose("fscrypt_context.knox_flag:0x%08x\n", ctx.v1.knox_flags);
		} else if (ci && ci->ci_policy.version == FSCRYPT_POLICY_V2) {
			ctx.v2.knox_flags |= policy->flags << FSCRYPT_KNOX_FLG_DDAR_SHIFT & FSCRYPT_KNOX_FLG_DDAR_MASK;
			dd_verbose("fscrypt_context.knox_flag:0x%08x\n", ctx.v2.knox_flags);
		}
//		ctx.knox_flags |= policy->flags << FSCRYPT_KNOX_FLG_DDAR_SHIFT & FSCRYPT_KNOX_FLG_DDAR_MASK;
//		dd_verbose("fscrypt_context.knox_flag:0x%08x\n", ctx.knox_flags);
		ret = ((int (*)(struct inode*, const char*, const void*, size_t, void *))(inode->i_sb->s_cop->android_oem_data1[1]))(inode, NULL, &ctx, fscrypt_context_size(&ctx), NULL);
		dd_info("result of set knox context for ino(%ld) : %d\n", inode->i_ino, ret);
	} else {
		dd_error("failed to set dd policy. get_context rc:%d\n", ret);
		ret = -EEXIST;
	}

	ret = dd_create_crypt_context(inode, policy, NULL);

	inode_unlock(inode);

	if (!ret) {
		struct dd_crypt_context crypt_context;
		struct fscrypt_info	*ci = inode->i_crypt_info;
		if (!ci) {
			dd_error("failed to alloc dd_info: no fbe policy found\n");
			ret = -EINVAL;
		} else {
			if (dd_read_crypt_context(inode, &crypt_context) != sizeof(struct dd_crypt_context)) {
				dd_error("update_encryption_context_with_dd_policy: failed to read dd crypt context ino:%ld\n", inode->i_ino);
				ret = -EINVAL;
			} else {
				struct ext_fscrypt_info *ext_ci = GET_EXT_CI(ci);

				ext_ci->ci_dd_info = alloc_dd_info(inode, policy, &crypt_context);
				if (IS_ERR(ext_ci->ci_dd_info)) {
					dd_error("failed to alloc dd info:%ld\n", inode->i_ino);
					ret = -ENOMEM;
					ext_ci->ci_dd_info = NULL;
				} else {
					fscrypt_dd_inc_count();
				}
			}
		}
	}
	return ret;
}

int dd_oem_page_crypto_inplace(struct dd_info *info, struct page *page, int dir)
{
	return fscrypt_crypt_block(info->inode,
			(dir == WRITE) ? FS_ENCRYPT:FS_DECRYPT, 0, page, page, PAGE_SIZE, 0, GFP_NOFS);
}

/* { KNOX_SUPPORT_DAR_DUAL_DO */
int fscrypt_dd_has_policy(const struct inode *inode)
{
	struct fscrypt_info *ci = NULL;
	if (!inode)
		return 0;

	ci = inode->i_crypt_info;
	if (ci) {
		struct ext_fscrypt_info *ext_ci = GET_EXT_CI(ci);

		if (ext_ci->ci_dd_info) {
			if (dd_policy_encrypted(ext_ci->ci_dd_info->policy.flags))
				return 1;
		}
	}

	return 0;
}
/* } KNOX_SUPPORT_DAR_DUAL_DO */

int fscrypt_dd_encrypted_inode(const struct inode *inode)
{
	struct fscrypt_info *ci = NULL;
	if (!inode)
		return 0;

	ci = inode->i_crypt_info;
	if (!S_ISREG(inode->i_mode))
		return 0;

	if (ci) {
		struct ext_fscrypt_info *ext_ci = GET_EXT_CI(ci);

		if (ext_ci->ci_dd_info) {
			if (dd_policy_encrypted(ext_ci->ci_dd_info->policy.flags))
				return 1;
		}
	}

	return 0;
}
EXPORT_SYMBOL(fscrypt_dd_encrypted_inode);

#ifdef CONFIG_SDP_KEY_DUMP
int fscrypt_dd_is_traced_inode(const struct inode *inode)
{
	struct fscrypt_info *ci = NULL;
	if (!inode)
		return 0;

	ci = inode->i_crypt_info;
	if (!S_ISREG(inode->i_mode))
		return 0;

	if (ci) {
		struct ext_fscrypt_info *ext_ci = GET_EXT_CI(ci);

		if (ext_ci->ci_dd_info) {
			if (dd_policy_trace_file(ext_ci->ci_dd_info->policy.flags))
				return 1;
		}
	}

	return 0;
}
EXPORT_SYMBOL(fscrypt_dd_is_traced_inode);

void fscrypt_dd_trace_inode(const struct inode *inode)
{
	struct fscrypt_info *ci = NULL;
	if (!inode)
		return;

	ci = inode->i_crypt_info;
	if (ci) {
		struct ext_fscrypt_info *ext_ci = GET_EXT_CI(ci);

		if (ext_ci->ci_dd_info) {
			dd_info("update dd trace policy ino:%ld\n", inode->i_ino);
			ext_ci->ci_dd_info->policy.flags |= DD_POLICY_TRACE_FILE;
		}
	}
}
EXPORT_SYMBOL(fscrypt_dd_trace_inode);
#endif

struct inode *fscrypt_bio_get_inode(const struct bio *bio)
{
	if (!bio)
		return NULL;
	if (!bio_has_data((struct bio *)bio))
		return NULL;
	if (!bio->bi_io_vec)
		return NULL;
	if (!bio->bi_io_vec->bv_page)
		return NULL;

	if (PageAnon(bio->bi_io_vec->bv_page)) {
		struct inode *inode = NULL;

		/* Using direct-io (O_DIRECT) without page cache */
		// SDP - START BLOCK
		// inode = dio_bio_get_inode((struct bio *)bio);
		// dd_verbose("inode on direct-io, inode = 0x%pK.\n", inode);
		// SDP - END BLOCK

		return inode;
	}

	if (!page_mapping(bio->bi_io_vec->bv_page))
		return NULL;

	return page_mapping(bio->bi_io_vec->bv_page)->host;
}

/**
 * prevent merging bios from different files when either is ddar enabled
 */
bool fscrypt_dd_can_merge_bio(struct bio *bio, struct address_space *mapping)
{
	struct dd_info *info1, *info2;

	if (!bio)
		return true;

	info1 = dd_get_info(fscrypt_bio_get_inode(bio));
	info2 = dd_get_info(mapping->host);

	if (info1 || info2) {
		// either is ddar protected
		if (!info1)
			goto err_out;
		if (!info2)
			goto err_out;

		if (info1->ino == info2->ino) {
			dd_verbose("allowing bio merge ino:%ld\n", info1->ino);
			return true;
		}

err_out:
		dd_verbose("disallowing bio merge ino1:%ld ino2:%ld\n",
				info1 ? info1->ino : -1, info2 ? info2->ino : -1);
		return false;
	}

	// none is ddar enabled
	return true;
}

void *dd_get_info(const struct inode *inode)
{
	struct ext_fscrypt_info *ext_ci;

	if (!inode)
		return NULL;

	if (!inode->i_crypt_info)
		return NULL;

	ext_ci = GET_EXT_CI(inode->i_crypt_info);
	return ext_ci->ci_dd_info;
}

int fscrypt_dd_decrypt_page(struct inode *inode, struct page *page)
{
	struct ext_fscrypt_info *ext_ci = GET_EXT_CI(inode->i_crypt_info);

	return dd_page_crypto(ext_ci->ci_dd_info, DD_DECRYPT, page, page);
}

void fscrypt_dd_set_count(long count)
{
	set_ddar_count(count);
}

long fscrypt_dd_get_count(void)
{
	return get_ddar_count();
}

void fscrypt_dd_inc_count(void)
{
	inc_ddar_count();
}

void fscrypt_dd_dec_count(void)
{
	dec_ddar_count();
}

int fscrypt_dd_is_locked(void)
{
	return dd_is_user_deamon_locked();
}

long fscrypt_dd_ioctl(unsigned int cmd, unsigned long *arg, struct inode *inode)
{
	if (inode && S_ISDIR(inode->i_mode) && !fscrypt_has_encryption_key(inode)
			&& (cmd != FS_IOC_GET_DD_INODE_COUNT)) {
		if (fscrypt_prepare_readdir(inode)) {
			return -ENOTTY;
		}
	}

	switch (cmd) {
	case FS_IOC_GET_DD_POLICY: {
		struct dd_info *info;

		if (!fscrypt_dd_encrypted_inode(inode))
			return -ENOENT;

		info = dd_get_info(inode);
		if (copy_to_user((void __user *) (*arg), &info->policy,
				sizeof(struct dd_policy)))
			return -EFAULT;
		return 0;
	}
	case FS_IOC_SET_DD_POLICY: {
		struct dd_policy policy;

		if (fscrypt_dd_encrypted_inode(inode))
			return -EEXIST;

		if (copy_from_user(&policy, (struct dd_policy __user *) (*arg),
				sizeof(policy))) {
			return -EFAULT;
		}

		return update_encryption_context_with_dd_policy(inode, &policy);
	}
	case FS_IOC_GET_DD_INODE_COUNT: {
		long ret = fscrypt_dd_get_count();
		dd_info("FS_IOC_GET_DD_INODE_COUNT - dd_count : %ld", ret);

		if (copy_to_user((void __user *) (*arg), &ret, sizeof(long)))
			return -EFAULT;
		return 0;
	}
	/* { KNOX_SUPPORT_DAR_DUAL_DO */
	case FS_IOC_HAS_DD_POLICY: {
		if (!fscrypt_dd_has_policy(inode)) {
			dd_error("dd policy is not applied (ino:%ld)\n", inode->i_ino);
			return -ENOENT;
		}

		dd_info("dd policy is applied (ino:%ld)\n", inode->i_ino);
		return 0;
	}
	/* } KNOX_SUPPORT_DAR_DUAL_DO */
	}
	return 0;
}

int fscrypt_dd_submit_bio(struct inode *inode, struct bio *bio)
{
	return dd_submit_bio(dd_get_info(inode), bio);
}

int fscrypt_dd_may_submit_bio(struct bio *bio)
{
	struct inode *inode = fscrypt_bio_get_inode(bio);
	if (!fscrypt_dd_encrypted_inode(inode))
		return -EOPNOTSUPP;

	return fscrypt_dd_submit_bio(inode, bio);
}

long fscrypt_dd_get_ino(struct bio *bio)
{
	struct inode *inode = fscrypt_bio_get_inode(bio);
	if (fscrypt_dd_encrypted_inode(inode))
		return inode->i_ino;

	return 0;
}

int fscrypt_dd_encrypted(struct bio *bio)
{
	struct inode *inode = fscrypt_bio_get_inode(bio);
	return fscrypt_dd_encrypted_inode(inode);
}
EXPORT_SYMBOL(fscrypt_dd_encrypted);
