/*
 * Utility functions to work with PROCA certificate
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 * Hryhorii Tur, <hryhorii.tur@partner.samsung.com>
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

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/err.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <linux/version.h>
#include <linux/file.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#include "proca_log.h"
#include "proca_certificate.h"
#include "five_crypto.h"
#include "five_testing.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 42)
#include "proca_certificate.asn1.h"
#else
#include "proca_certificate-asn1.h"
#endif

static struct crypto_shash *g_validation_shash;

int proca_certificate_get_flags(void *context, size_t hdrlen,
				unsigned char tag,
				const void *value, size_t vlen)
{
	struct proca_certificate *parsed_cert = context;

	if (!value || !vlen)
		return -EINVAL;

	parsed_cert->flags = *(const uint8_t *)value;

	return 0;
}

int proca_certificate_get_app_name(void *context, size_t hdrlen,
				   unsigned char tag,
				   const void *value, size_t vlen)
{
	struct proca_certificate *parsed_cert = context;

	if (!value || !vlen)
		return -EINVAL;

	parsed_cert->app_name = kmalloc(vlen + 1, GFP_KERNEL);
	if (!parsed_cert->app_name)
		return -ENOMEM;

	memcpy(parsed_cert->app_name, value, vlen);
	parsed_cert->app_name[vlen] = '\0';
	parsed_cert->app_name_size = vlen;

	return 0;
}

int proca_certificate_get_five_signature_hash(void *context, size_t hdrlen,
					      unsigned char tag,
					      const void *value, size_t vlen)
{
	struct proca_certificate *parsed_cert = context;

	if (!value || !vlen)
		return -EINVAL;

	parsed_cert->five_signature_hash = kmalloc(vlen, GFP_KERNEL);
	if (!parsed_cert->five_signature_hash)
		return -ENOMEM;

	memcpy(parsed_cert->five_signature_hash, value, vlen);
	parsed_cert->five_signature_hash_size = vlen;

	return 0;
}

int parse_proca_certificate(const char *certificate_buff,
			    const size_t buff_size,
			    struct proca_certificate *parsed_cert)
{
	int rc = 0;

	memset(parsed_cert, 0, sizeof(*parsed_cert));

	rc = asn1_ber_decoder(&proca_certificate_decoder, parsed_cert,
			      certificate_buff,
			      buff_size);
	if (!parsed_cert->app_name || !parsed_cert->five_signature_hash) {
		PROCA_INFO_LOG("Failed to parse proca certificate.\n");
		deinit_proca_certificate(parsed_cert);
		return -EINVAL;
	}

	return rc;
}

void deinit_proca_certificate(struct proca_certificate *certificate)
{
	kfree(certificate->app_name);
	kfree(certificate->five_signature_hash);
}

int init_certificate_validation_hash(void)
{
	g_validation_shash = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(g_validation_shash)) {
		PROCA_WARN_LOG("can't alloc sha256 alg, rc - %ld.\n",
			PTR_ERR(g_validation_shash));
		return PTR_ERR(g_validation_shash);
	}
	return 0;
}

int compare_with_five_signature(const struct proca_certificate *certificate,
				const void *five_signature,
				const size_t five_signature_size)
{
	SHASH_DESC_ON_STACK(sdesc, g_validation_shash);
	char five_sign_hash[SHA256_DIGEST_SIZE];
	int rc = 0;

	if (sizeof(five_sign_hash) != certificate->five_signature_hash_size) {
		PROCA_DEBUG_LOG(
			"Size of five sign hash is invalid %zu, expected %zu",
			 certificate->five_signature_hash_size,
			 sizeof(five_sign_hash));
		return rc;
	}

	sdesc->tfm = g_validation_shash;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
/*
 * flags was deleted from struct shash_desc in Android Kernel v5.2.0
 */
	sdesc->flags = 0;
#endif

	rc = crypto_shash_init(sdesc);
	if (rc != 0) {
		PROCA_WARN_LOG("crypto_shash_init failed, rc - %d.\n", rc);
		return 0;
	}

	rc = crypto_shash_digest(sdesc, five_signature,
				 five_signature_size, five_sign_hash);
	if (rc != 0) {
		PROCA_WARN_LOG("crypto_shash_digest failed, rc - %d.\n", rc);
		return 0;
	}

	return !memcmp(five_sign_hash,
		       certificate->five_signature_hash,
		       certificate->five_signature_hash_size);
}

int proca_certificate_copy(struct proca_certificate *dst,
			const struct proca_certificate *src)
{
	BUG_ON(!dst || !src);

	memset(dst, 0, sizeof(*dst));

	if (src->app_name) {
		/*
		 * app_name is NULL-terminated string with len == app_name_size,
		 * so we should duplicate app_name_size + 1 bytes
		 */
		dst->app_name = kmemdup(src->app_name, src->app_name_size + 1,
				GFP_KERNEL);
		dst->app_name_size = src->app_name_size;

		if (unlikely(!dst->app_name))
			return -ENOMEM;
	}

	if (src->five_signature_hash) {
		dst->five_signature_hash = kmemdup(
				src->five_signature_hash,
				src->five_signature_hash_size,
				GFP_KERNEL);
		dst->five_signature_hash_size = src->five_signature_hash_size;

		if (unlikely(!dst->five_signature_hash)) {
			kfree(dst->app_name);
			return -ENOMEM;
		}
	}

	return 0;
}

/* Copied from TA sources */
enum PaFlagBits {
	PaFlagBits_bitAndroid = 0,
	PaFlagBits_bitThirdParty = 1,
	PaFlagBits_bitHmac = 2
};

__visible_for_testing __mockable
bool check_native_pa_id(const struct proca_certificate *parsed_cert,
			struct task_struct *task)
{
	struct file *exe;
	char *path_buff;
	char *path;
	bool res = false;

	path_buff = kmalloc(parsed_cert->app_name_size + 1, GFP_KERNEL);
	if (!path_buff)
		return false;

	exe = get_task_exe_file(task);
	if (!exe)
		goto path_buff_cleanup;

	path = d_path(&exe->f_path, path_buff, parsed_cert->app_name_size + 1);
	if (IS_ERR(path))
		goto exe_file_cleanup;

	res = !strcmp(path, parsed_cert->app_name);
	if (!res)
		PROCA_WARN_LOG(
			"file path %s and cert app name %s doesn't match\n",
			path, parsed_cert->app_name);

exe_file_cleanup:
	fput(exe);

path_buff_cleanup:
	kfree(path_buff);

	return res;
}

bool is_certificate_relevant_to_task(
			const struct proca_certificate *parsed_cert,
			struct task_struct *task)
{
	const char system_server_app_name[] = "/system/framework/services.jar";
	const char system_server[] = "system_server";
	const size_t max_app_name = 1024;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(PROCA_KUNIT_ENABLED))
	char cmdline[1024 + 1];
#else
	char cmdline[max_app_name + 1];
#endif
	int cmdline_size;

	if (!(parsed_cert->flags & (1 << PaFlagBits_bitAndroid)))
		if (!check_native_pa_id(parsed_cert, task))
			return false;

	cmdline_size = get_cmdline(task, cmdline, max_app_name);
	cmdline[cmdline_size] = 0;

	// Special case for system_server
	if (!strncmp(parsed_cert->app_name, system_server_app_name,
			parsed_cert->app_name_size)) {
		if (strncmp(cmdline, system_server, sizeof(system_server)))
			return false;
	} else if (parsed_cert->app_name[0] != '/') {
		// Case for Android applications
		PROCA_DEBUG_LOG("Task %d has cmdline : %s\n",
			task->pid, cmdline);
		if (strncmp(cmdline, parsed_cert->app_name,
				parsed_cert->app_name_size))
			return false;
	}

	return true;
}

#define PROCA_MAX_DIGEST_SIZE 64

bool is_certificate_relevant_to_file(
			const struct proca_certificate *parsed_cert,
			struct file *file)
{
	int result = 0;
	u8 stored_file_hash[PROCA_MAX_DIGEST_SIZE] = {0};
	size_t hash_len = sizeof(stored_file_hash);

	BUG_ON(!file || !parsed_cert);

	result = five_calc_file_hash(file, HASH_ALGO_SHA1, stored_file_hash, &hash_len);
	if (result) {
		PROCA_WARN_LOG("File hash calculation is failed");
		return false;
	}

	return compare_with_five_signature(parsed_cert, stored_file_hash, hash_len);
}
