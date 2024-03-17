/*
 * Wrappers for backward compatibility with old Kernels.
 *
 * Copyright (C) 2019 Samsung Electronics, Inc.
 *
 * Egor Uleyskiy, <e.uleyskiy@samsung.com>
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

#ifndef __LINUX_FIVE_CRYPTO_COMP_H
#define __LINUX_FIVE_CRYPTO_COMP_H

#include <linux/version.h>
#include <crypto/public_key.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
static inline int five_verify_signature(struct key *key,
			  struct public_key_signature *pks,
			  struct five_cert *cert,
			  struct five_cert_header *header)
{
	int ret = -ENOMEM;

	pks->pkey_hash_algo = header->hash_algo;
	pks->nr_mpi = 1;
	pks->rsa.s = mpi_read_raw_data(cert->signature->value,
			cert->signature->length);

	if (pks->rsa.s)
		ret = verify_signature(key, pks);

	mpi_free(pks->rsa.s);

	return ret;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
static inline int five_verify_signature(struct key *key,
			  struct public_key_signature *pks,
			  struct five_cert *cert,
			  struct five_cert_header *header)
{
	int ret = -ENOMEM;

	pks->pkey_algo = "rsa";
	pks->hash_algo = hash_algo_name[header->hash_algo];
	pks->s = cert->signature->value;
	pks->s_size = cert->signature->length;

	ret = verify_signature(key, pks);

	return ret;
}
#else
static inline int five_verify_signature(struct key *key,
			  struct public_key_signature *pks,
			  struct five_cert *cert,
			  struct five_cert_header *header)
{
	int ret = -ENOMEM;

	pks->pkey_algo = "rsa";
	pks->encoding = "pkcs1";
	pks->hash_algo = hash_algo_name[header->hash_algo];
	pks->s = cert->signature->value;
	pks->s_size = cert->signature->length;

	ret = verify_signature(key, pks);

	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
static inline struct key *five_keyring_alloc(const char *description,
			  kuid_t uid, kgid_t gid, const struct cred *cred,
			  key_perm_t perm, unsigned long flags)
{
	return keyring_alloc(description, uid, gid, cred,
				perm, flags, NULL);
}
#else
static inline struct key *five_keyring_alloc(const char *description,
			  kuid_t uid, kgid_t gid, const struct cred *cred,
			  key_perm_t perm, unsigned long flags)
{
	return keyring_alloc(description, uid, gid, cred,
				perm, flags, NULL, NULL);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
#define keyring_search(keyring, type, desc, recurse) \
		keyring_search(keyring, type, desc)
#endif

#endif /* __LINUX_FIVE_CRYPTO_COMP_H */
