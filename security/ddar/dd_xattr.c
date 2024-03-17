/**
 * dd_xattr.c
 *
 * get/set sdp context to xattr
 */

#ifndef FSCRYPT_NEED_OPS
#define FSCRYPT_NEED_OPS
#endif

#define __FS_HAS_ENCRYPTION IS_ENABLED(CONFIG_EXT4_FS_ENCRYPTION)
#include <linux/fscrypt.h>
#include <linux/xattr.h>
#include "dd_common.h"

static inline int __get_xattr(struct inode *inode,
		const char *name, void *buffer, size_t buffer_size) {
	if (inode->i_sb->s_cop->android_oem_data1[0])
		return ((int (*)(struct inode*, const char*, void*, size_t))(inode->i_sb->s_cop->android_oem_data1[0]))(
				inode, name, buffer, buffer_size);

	return -EOPNOTSUPP;
}

static inline int __set_xattr(struct inode *inode,
		const char *name, const void *value, size_t size, void *fs_data) {
	if (inode->i_sb->s_cop->android_oem_data1[1])
		return ((int (*)(struct inode*, const char*, const void*, size_t, void *))(inode->i_sb->s_cop->android_oem_data1[1]))(
				inode, name, value, size, fs_data);

	return -EOPNOTSUPP;
}

#define EXT4_XATTR_NAME_DD_POLICY "dd:p"

int dd_read_crypto_metadata(struct inode *inode, const char *name, void *buffer, size_t buffer_size)
{
   return __get_xattr(inode, name, buffer, buffer_size);
}

int dd_write_crypto_metadata(struct inode *inode, const char *name, const void *buffer, size_t len)
{
   return __set_xattr(inode, name, buffer, len, NULL);
}

int dd_read_crypt_context(struct inode *inode, struct dd_crypt_context *context)
{
   return __get_xattr(inode, EXT4_XATTR_NAME_DD_POLICY, context, sizeof(struct dd_crypt_context));
}

int dd_write_crypt_context(struct inode *inode, const struct dd_crypt_context *context, void *fs_data)
{
   return __set_xattr(inode, EXT4_XATTR_NAME_DD_POLICY, context, sizeof(struct dd_crypt_context), fs_data);
}
