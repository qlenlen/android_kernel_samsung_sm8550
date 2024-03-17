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

#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <crypto/hash_info.h>

#include <linux/task_integrity.h>
#include "five.h"
#include "five_audit.h"
#include "five_hooks.h"
#include "five_tee_api.h"
#include "five_porting.h"
#include "five_cache.h"
#include "five_dmverity.h"

#define FIVE_RSA_SIGNATURE_MAX_LENGTH (2048/8)
/* Identify extend structure of integrity label */
#define FIVE_ID_INTEGRITY_LABEL_EX 0xFFFF
#define FIVE_LABEL_VERSION1 1
/* Maximum length of data integrity label.
 * This limit is applied because:
 * 1. TEEgris doesn't support signing data longer than 480 bytes;
 * 2. The label's length is limited to 3965 byte according to the data
 * transmission protocol between five_tee_driver and TA.
 */
#define FIVE_LABEL_MAX_LEN 256

/**
 * Extend structure of integrity label.
 * If field "len" equals 0xffff then it is extend integrity label,
 * otherwise simple integrity label.
 */
struct integrity_label_ex {
	uint16_t len;
	uint8_t version;
	uint8_t reserved[2];
	uint8_t hash_algo;
	uint8_t hash[64];
	struct integrity_label label;
} __packed;

#ifndef CONFIG_SAMSUNG_PRODUCT_SHIP
static const bool panic_on_error = true;
#else
static const bool panic_on_error;
#endif

static DECLARE_RWSEM(sign_fcntl_lock);

/*
 * five_collect_measurement - collect file measurement
 *
 * Must be called with iint->mutex held.
 *
 * Return 0 on success, error code otherwise.
 */
static int five_collect_measurement(struct file *file, u8 hash_algo,
			     u8 *hash, size_t hash_len)
{
	int result = 0;

	BUG_ON(!file || !hash);

	result = five_calc_file_hash(file, hash_algo, hash, &hash_len);
	if (result) {
		five_audit_err(current, file, "collect_measurement", 0,
				0, "calculate file hash failed", result);
	}
	return result;
}

static int get_integrity_label(struct five_cert *cert,
			void **label_data, size_t *label_len)
{
	int rc = -ENODATA;
	struct five_cert_header *header =
			(struct five_cert_header *)cert->body.header->value;

	if (header && header->signature_type == FIVE_XATTR_HMAC) {
		*label_data = cert->body.label->value;
		*label_len = cert->body.label->length;
		rc = 0;
	}
	return rc;
}

static int get_signature(struct five_cert *cert, void **sig,
		size_t *sig_len)
{
	int rc = -ENODATA;
	struct five_cert_header *header =
			(struct five_cert_header *)cert->body.header->value;

	if (header && header->signature_type == FIVE_XATTR_HMAC) {
		if (cert->signature->length == 0)
			return rc;
		*sig = cert->signature->value;
		*sig_len = cert->signature->length;

		rc = 0;
	}

	return rc;
}

static int update_label(struct integrity_iint_cache *iint,
		const void *label_data, size_t label_len)
{
	struct integrity_label *l;

	if (!label_data)
		return 0;

	l = kmalloc(sizeof(struct integrity_label) + label_len, GFP_NOFS);
	if (l) {
		l->len = label_len;
		memcpy(l->data, label_data, label_len);
		kfree(iint->five_label);
		iint->five_label = l;
	} else {
		return -ENOMEM;
	}

	return 0;
}

static int five_fix_xattr(struct task_struct *task,
			  struct dentry *dentry,
			  struct file *file,
			  void **raw_cert,
			  size_t *raw_cert_len,
			  struct integrity_iint_cache *iint,
			  struct integrity_label_ex *label)
{
	int rc = 0;
	u8 hash[FIVE_MAX_DIGEST_SIZE], *hash_file, *sig = NULL;
	size_t hash_len = sizeof(hash), hash_file_len, sig_len;
	void *file_label = label->label.data;
	u16 file_label_len = label->label.len;
	struct five_cert_body body_cert = {0};
	struct five_cert_header *header;

	BUG_ON(!task || !dentry || !file || !raw_cert || !(*raw_cert) || !iint);
	BUG_ON(!raw_cert_len);

	rc = five_cert_body_fillout(&body_cert, *raw_cert, *raw_cert_len);
	if (unlikely(rc))
		return -EINVAL;

	header = (struct five_cert_header *)body_cert.header->value;
	hash_file = body_cert.hash->value;
	hash_file_len = body_cert.hash->length;
	if (unlikely(!header || !hash_file))
		return -EINVAL;

	if (label->version == FIVE_LABEL_VERSION1) {
		rc = five_collect_measurement(file, header->hash_algo,
				      hash_file, hash_file_len);
		if (unlikely(rc))
			return rc;
	} else {
		memcpy(hash_file, label->hash, hash_file_len);
	}

	rc = five_cert_calc_hash(&body_cert, hash, &hash_len);
	if (unlikely(rc))
		return rc;

	sig_len = (size_t)body_cert.hash->length + file_label_len;

	sig = kzalloc(sig_len, GFP_NOFS);
	if (!sig)
		return -ENOMEM;

	rc = sign_hash(header->hash_algo, hash, hash_len,
		       file_label, file_label_len, sig, &sig_len);

	if (!rc) {
		rc = five_cert_append_signature(raw_cert, raw_cert_len,
						sig, sig_len);
		if (!rc) {
			int count = 1;

			do {
				rc = __vfs_setxattr_noperm(d_real_comp(dentry),
							XATTR_NAME_FIVE,
							*raw_cert,
							*raw_cert_len,
							0);
				count--;
			} while (count >= 0 && rc != 0);

			if (!rc) {
				rc = update_label(iint,
						file_label, file_label_len);
			}
		}
	} else if (panic_on_error) {
		panic("FIVE failed to sign %s (ret code = %d)",
		dentry->d_name.name, rc);
	} else {
		five_audit_sign_err(current, file, "fix_xattr", 0,
			0, "can't sign the file", rc);
	}

	kfree(sig);

	return rc;
}

int five_read_xattr(struct dentry *dentry, char **xattr_value)
{
	ssize_t ret;

	ret = vfs_getxattr_alloc(dentry, XATTR_NAME_FIVE, xattr_value,
			0, GFP_NOFS);
	if (ret < 0)
		ret = 0;

	return ret;
}

static bool bad_fs(struct inode *inode)
{
	if (inode->i_sb->s_magic == EXT4_SUPER_MAGIC ||
	    inode->i_sb->s_magic == F2FS_SUPER_MAGIC ||
	    inode->i_sb->s_magic == OVERLAYFS_SUPER_MAGIC ||
	    inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1)
		return false;

	return true;
}

static bool readonly_sb(struct inode *inode)
{
	if (inode->i_sb->s_flags & MS_RDONLY)
		return true;

	return false;
}

/*
 * five_is_fsverity_protected - checks if file is protected by FSVERITY
 *
 * Return true/false
 */
static bool five_is_fsverity_protected(const struct inode *inode)
{
	return IS_VERITY(inode);
}

/*
 * five_appraise_measurement - appraise file measurement
 *
 * Return 0 on success, error code otherwise
 */
int five_appraise_measurement(struct task_struct *task, int func,
			      struct integrity_iint_cache *iint,
			      struct file *file,
			      struct five_cert *cert)
{
	enum task_integrity_reset_cause cause = CAUSE_UNKNOWN;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	enum five_file_integrity status = FIVE_FILE_UNKNOWN;
	enum task_integrity_value prev_integrity;
	int rc = 0;
	u8 *file_hash;
	u8 stored_file_hash[FIVE_MAX_DIGEST_SIZE] = {0};
	size_t file_hash_len = 0;
	struct five_cert_header *header = NULL;

	BUG_ON(!task || !iint || !file);

	prev_integrity = task_integrity_read(TASK_INTEGRITY(task));
	dentry = file->f_path.dentry;
	inode = d_backing_inode(dentry);

	if (bad_fs(inode)) {
		status = FIVE_FILE_FAIL;
		cause = CAUSE_BAD_FS;
		rc = -ENOTSUPP;
		goto out;
	}

	if (!cert) {
		cause = CAUSE_NO_CERT;
		if (five_is_fsverity_protected(inode))
			status = FIVE_FILE_FSVERITY;
		else if (five_is_dmverity_protected(file))
			status = FIVE_FILE_DMVERITY;
		goto out;
	}

	header = (struct five_cert_header *)cert->body.header->value;
	file_hash = cert->body.hash->value;
	file_hash_len = cert->body.hash->length;
	if (file_hash_len > sizeof(stored_file_hash)) {
		cause = CAUSE_INVALID_HASH_LENGTH;
		rc = -EINVAL;
		goto out;
	}

	memcpy(stored_file_hash, file_hash, file_hash_len);

	if (unlikely(!header || !file_hash)) {
		cause = CAUSE_INVALID_HEADER;
		rc = -EINVAL;
		goto out;
	}

	rc = five_collect_measurement(file, header->hash_algo, file_hash,
				      file_hash_len);
	if (rc) {
		cause = CAUSE_CALC_HASH_FAILED;
		goto out;
	}

	switch (header->signature_type) {
	case FIVE_XATTR_HMAC: {
		u8 *sig = NULL;
		u8 algo = header->hash_algo;
		void *file_label_data;
		size_t file_label_len, sig_len = 0;
		u8 cert_hash[FIVE_MAX_DIGEST_SIZE] = {0};
		size_t cert_hash_len = sizeof(cert_hash);

		status = FIVE_FILE_FAIL;

		rc = get_integrity_label(cert, &file_label_data,
					 &file_label_len);
		if (unlikely(rc)) {
			cause = CAUSE_INVALID_LABEL_DATA;
			break;
		}

		if (unlikely(file_label_len > PAGE_SIZE)) {
			cause = CAUSE_INVALID_LABEL_DATA;
			break;
		}

		rc = get_signature(cert, (void **)&sig, &sig_len);
		if (unlikely(rc)) {
			cause = CAUSE_INVALID_SIGNATURE_DATA;
			break;
		}

		rc = five_cert_calc_hash(&cert->body, cert_hash,
							&cert_hash_len);
		if (unlikely(rc)) {
			cause = CAUSE_INVALID_CALC_CERT_HASH;
			break;
		}

		rc = verify_hash(algo, cert_hash,
				cert_hash_len,
				file_label_data, file_label_len,
				sig, sig_len);
		if (unlikely(rc)) {
			cause = CAUSE_INVALID_HASH;
			if (cert) {
				five_audit_hexinfo(file, "stored hash",
					stored_file_hash, file_hash_len);
				five_audit_hexinfo(file, "calculated hash",
					file_hash, file_hash_len);
				five_audit_hexinfo(file, "HMAC signature",
					sig, sig_len);
			}
			break;
		}

		rc = update_label(iint, file_label_data, file_label_len);
		if (unlikely(rc)) {
			cause = CAUSE_INVALID_UPDATE_LABEL;
			break;
		}

		status = FIVE_FILE_HMAC;

		break;
	}
	case FIVE_XATTR_DIGSIG: {
		u8 cert_hash[FIVE_MAX_DIGEST_SIZE] = {0};
		size_t cert_hash_len = sizeof(cert_hash);

		status = FIVE_FILE_FAIL;

		rc = five_cert_calc_hash(&cert->body, cert_hash,
							&cert_hash_len);
		if (unlikely(rc)) {
			cause = CAUSE_INVALID_CALC_CERT_HASH;
			break;
		}

		rc = five_digsig_verify(cert, cert_hash, cert_hash_len);

		if (rc) {
			cause = CAUSE_INVALID_SIGNATURE;
			if (cert) {
				five_audit_hexinfo(file, "stored hash",
					stored_file_hash, file_hash_len);
				five_audit_hexinfo(file, "calculated hash",
					file_hash, file_hash_len);
				five_audit_hexinfo(file, "RSA signature",
					cert->signature->value,
					cert->signature->length);
			}
			break;
		}

		status = FIVE_FILE_RSA;

		break;
	}
	default:
		status = FIVE_FILE_FAIL;
		cause = CAUSE_UKNOWN_FIVE_DATA;
		break;
	}

out:
	if (status == FIVE_FILE_FAIL || status == FIVE_FILE_UNKNOWN) {
		task_integrity_set_reset_reason(TASK_INTEGRITY(task),
						cause, file);
		five_audit_verbose(task, file, five_get_string_fn(func),
				prev_integrity, prev_integrity,
				tint_reset_cause_to_string(cause), rc);
	}

	five_set_cache_status(iint, status);

	return rc;
}

/*
 * five_update_xattr - update 'security.five' hash value
 */
static int five_update_xattr(struct task_struct *task,
		struct integrity_iint_cache *iint, struct file *file,
		struct integrity_label_ex *label)
{
	struct dentry *dentry;
	int rc = 0;
	uint8_t *hash;
	size_t hash_len;
	uint8_t *raw_cert;
	size_t raw_cert_len;
	struct five_cert_header header = {
			.version = FIVE_CERT_VERSION1,
			.privilege = FIVE_PRIV_DEFAULT,
			.hash_algo = five_hash_algo,
			.signature_type = FIVE_XATTR_HMAC };

	BUG_ON(!task || !iint || !file || !label);

	if (label->version == FIVE_LABEL_VERSION1) {
		hash_len = (size_t)hash_digest_size[five_hash_algo];
	} else {
		header.hash_algo = label->hash_algo;
		if (label->hash_algo >= HASH_ALGO__LAST)
			return -EINVAL;

		hash_len = (size_t)hash_digest_size[label->hash_algo];
		if (hash_len > sizeof(label->hash))
			return -EINVAL;
	}

	hash = kzalloc(hash_len, GFP_KERNEL);
	if (!hash)
		return -ENOMEM;

	dentry = file->f_path.dentry;

	/* do not collect and update hash for digital signatures */
	if (five_get_cache_status(iint) == FIVE_FILE_RSA) {
		char dummy[512];
		struct inode *inode = file_inode(file);

		rc = __vfs_getxattr(d_real_comp(dentry), inode, XATTR_NAME_FIVE,
				dummy, sizeof(dummy), XATTR_NOSECURITY);

		// Check if xattr is exist
		if (rc > 0 || rc != -ENODATA) {
			kfree(hash);
			return -EPERM;
		} else {	// xattr does not exist.
			five_set_cache_status(iint, FIVE_FILE_UNKNOWN);
			pr_err("FIVE: ERROR: Cache is unsynchronized");
		}
	}

	rc = five_cert_body_alloc(&header, hash, hash_len,
				  label->label.data, label->label.len,
				  &raw_cert, &raw_cert_len);
	if (rc)
		goto exit;

	if (task_integrity_allow_sign(TASK_INTEGRITY(task))) {
		rc = five_fix_xattr(task, dentry, file,
			(void **)&raw_cert, &raw_cert_len, iint, label);
		if (rc)
			pr_err("FIVE: Can't sign hash: rc=%d\n", rc);
	} else {
		rc = -EPERM;
	}

	five_hook_file_signed(task, file, raw_cert, raw_cert_len, rc);

	five_cert_free(raw_cert);

exit:
	kfree(hash);
	return rc;
}

static void five_reset_appraise_flags(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	struct integrity_iint_cache *iint;

	if (!S_ISREG(inode->i_mode))
		return;

	iint = integrity_iint_find(inode);
	if (iint)
		five_set_cache_status(iint, FIVE_FILE_UNKNOWN);
}

/**
 * five_inode_post_setattr - reflect file metadata changes
 * @dentry: pointer to the affected dentry
 *
 * Changes to a dentry's metadata might result in needing to appraise.
 *
 * This function is called from notify_change(), which expects the caller
 * to lock the inode's i_mutex.
 */
void five_inode_post_setattr(struct task_struct *task, struct dentry *dentry)
{
	five_reset_appraise_flags(dentry);
}

/*
 * five_protect_xattr - protect 'security.five'
 *
 * Ensure that not just anyone can modify or remove 'security.five'.
 */
static int five_protect_xattr(struct dentry *dentry, const char *xattr_name,
			     const void *xattr_value, size_t xattr_value_len)
{
	if (strcmp(xattr_name, XATTR_NAME_FIVE) == 0) {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return 1;
	}
	return 0;
}

int five_inode_setxattr(struct dentry *dentry, const char *xattr_name,
			const void *xattr_value, size_t xattr_value_len)
{
	int result = five_protect_xattr(dentry, xattr_name, xattr_value,
				   xattr_value_len);

	if (result == 1 && xattr_value_len == 0) {
		five_reset_appraise_flags(dentry);
		return 0;
	}

	if (result == 1) {
		bool digsig;
		struct five_cert_header *header;
		struct five_cert cert = { {0} };

		result = five_cert_fillout(&cert, xattr_value, xattr_value_len);
		if (result)
			return result;

		header = (struct five_cert_header *)cert.body.header->value;

		if (!xattr_value_len || !header ||
				(header->signature_type >= FIVE_XATTR_END))
			return -EINVAL;

		digsig = (header->signature_type == FIVE_XATTR_DIGSIG);
		if (!digsig)
			return -EPERM;

		five_reset_appraise_flags(dentry);
		result = 0;
	}

	return result;
}

int five_inode_removexattr(struct dentry *dentry, const char *xattr_name)
{
	int result;

	result = five_protect_xattr(dentry, xattr_name, NULL, 0);
	if (result == 1) {
		five_reset_appraise_flags(dentry);
		result = 0;
	}
	return result;
}

int five_reboot_notifier(struct notifier_block *nb,
			       unsigned long action, void *unused)
{
	down_write(&sign_fcntl_lock);
	/* Need to wait for five_fcntl_sign finish */
	up_write(&sign_fcntl_lock);

	return NOTIFY_DONE;
}

static int copy_label(const struct integrity_label __user *ulabel,
		      struct integrity_label_ex **out_label)
{
	u16 len;
	size_t label_len;
	int rc = 0;
	struct integrity_label_ex header = {0};
	struct integrity_label_ex *label = NULL;

	if (unlikely(!ulabel || !out_label)) {
		rc = -EINVAL;
		goto error;
	}

	if (unlikely(copy_from_user(&len, ulabel, sizeof(len)))) {
		rc = -EFAULT;
		goto error;
	}

	if (len == FIVE_ID_INTEGRITY_LABEL_EX) {
		if (unlikely(copy_from_user(&header, ulabel, sizeof(header)))) {
			rc = -EFAULT;
			goto error;
		}

		if (len != header.len ||
		    header.label.len > FIVE_LABEL_MAX_LEN ||
		    header.version <= FIVE_LABEL_VERSION1) {
			rc = -EINVAL;
			goto error;
		}

		label_len = sizeof(header) + header.label.len;

		label = kzalloc(label_len, GFP_NOFS);
		if (unlikely(!label)) {
			rc = -ENOMEM;
			goto error;
		}

		memcpy(label, &header, sizeof(header));
		if (unlikely(copy_from_user(&label->label.data[0],
				(const u8 __user *)ulabel + sizeof(header),
				label_len - sizeof(header)))) {
			rc = -EFAULT;
			goto error;
		}
	} else {
		if (len > FIVE_LABEL_MAX_LEN) {
			rc = -EINVAL;
			goto error;
		}

		label_len = sizeof(header) + len;

		label = kzalloc(label_len, GFP_NOFS);
		if (unlikely(!label)) {
			rc = -ENOMEM;
			goto error;
		}

		if (unlikely(copy_from_user(&label->label, ulabel,
					    sizeof(len) + len))) {
			rc = -EFAULT;
			goto error;
		}

		if (len != label->label.len) {
			rc = -EINVAL;
			goto error;
		}

		label->version = FIVE_LABEL_VERSION1;
	}

	*out_label = label;
error:
	if (rc)
		kfree(label);

	return rc;
}

/* Called from do_fcntl */
int five_fcntl_sign(struct file *file, struct integrity_label __user *label)
{
	struct integrity_iint_cache *iint;
	struct inode *inode = file_inode(file);
	struct integrity_label_ex *l = NULL;
	int rc = 0;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (readonly_sb(inode)) {
		pr_err("FIVE: Can't sign a file on RO FS\n");
		return -EROFS;
	}

	if (task_integrity_allow_sign(TASK_INTEGRITY(current))) {
		rc = copy_label(label, &l);
		if (rc) {
			pr_err("FIVE: Can't copy integrity label\n");
			return rc;
		}
	} else {
		enum task_integrity_value tint =
			task_integrity_read(TASK_INTEGRITY(current));

		five_audit_err(current, file, "fcntl_sign", tint, tint,
				"sign:no-perm", -EPERM);
		return -EPERM;
	}

	iint = integrity_inode_get(inode);
	if (!iint) {
		kfree(l);
		return -ENOMEM;
	}

	if (file->f_op && file->f_op->flush) {
		if (file->f_op->flush(file, current->files)) {
			kfree(l);
			return -EOPNOTSUPP;
		}
	}

	down_read(&sign_fcntl_lock);
	inode_lock(inode);
	rc = five_update_xattr(current, iint, file, l);
	iint->five_signing = false;
	inode_unlock(inode);
	up_read(&sign_fcntl_lock);

	kfree(l);

	return rc;
}

static int check_input_inode(struct inode *inode)
{
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (readonly_sb(inode)) {
		pr_err("FIVE: Can't sign a file on RO FS\n");
		return -EROFS;
	}

	return 0;
}

int five_fcntl_edit(struct file *file)
{
	int rc;
	struct dentry *dentry;
	uint8_t *raw_cert = NULL;
	size_t raw_cert_len = 0;
	struct integrity_iint_cache *iint;
	struct inode *inode = file_inode(file);

	rc = check_input_inode(inode);
	if (rc)
		return rc;

	if (!task_integrity_allow_sign(TASK_INTEGRITY(current)))
		return -EPERM;

	inode_lock(inode);
	dentry = file->f_path.dentry;
	rc = __vfs_setxattr_noperm(d_real_comp(dentry),
				   XATTR_NAME_FIVE,
				   raw_cert,
				   raw_cert_len,
				   0);
	iint = integrity_inode_get(inode);
	if (iint)
		iint->five_signing = true;
	inode_unlock(inode);

	return rc;
}

int five_fcntl_close(struct file *file)
{
	int rc;
	ssize_t xattr_len;
	struct dentry *dentry;
	struct integrity_iint_cache *iint;
	struct inode *inode = file_inode(file);

	rc = check_input_inode(inode);
	if (rc)
		return rc;

	inode_lock(inode);
	iint = integrity_inode_get(inode);
	if (!iint) {
		inode_unlock(inode);
		return -ENOMEM;
	}

	if (iint->five_signing) {
		dentry = file->f_path.dentry;
		xattr_len = __vfs_getxattr(d_real_comp(dentry), inode,
				XATTR_NAME_FIVE, NULL, 0, XATTR_NOSECURITY);
		if (xattr_len == 0)
			rc = __vfs_removexattr(d_real_comp(dentry),
				XATTR_NAME_FIVE);

		iint->five_signing = false;
	}
	inode_unlock(inode);

	return rc;
}
