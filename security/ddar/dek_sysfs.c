/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *
 * Sensitive Data Protection
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/kernel.h>
#include <linux/stat.h>
#include <linux/string.h>

#include <ddar/dek_common.h>

static int g_asym_alg = SDPK_DEFAULT_ALGOTYPE;

#define ALG_NAME_RSA_NAME "RSA"
#define ALG_NAME_DH_NAME "DH"
#define ALG_NAME_ECDH_NAME "ECDH"

static ssize_t dek_show_asym_alg(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	switch (g_asym_alg) {
	case SDPK_ALGOTYPE_ASYMM_RSA:
		return sprintf(buf, "%s\n", ALG_NAME_RSA_NAME);
	case SDPK_ALGOTYPE_ASYMM_DH:
		return sprintf(buf, "%s\n", ALG_NAME_DH_NAME);
	case SDPK_ALGOTYPE_ASYMM_ECDH:
		return sprintf(buf, "%s\n", ALG_NAME_ECDH_NAME);
	default:
		return sprintf(buf, "unknown\n");
	}

	return 0;
}

static ssize_t dek_set_asym_alg(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	if (!strncmp(ALG_NAME_RSA_NAME, buf, strlen(ALG_NAME_RSA_NAME))) {
		g_asym_alg = SDPK_ALGOTYPE_ASYMM_RSA;
		return strlen(ALG_NAME_RSA_NAME);
	}

	if (!strncmp(ALG_NAME_DH_NAME, buf, strlen(ALG_NAME_DH_NAME))) {
		g_asym_alg = SDPK_ALGOTYPE_ASYMM_DH;
		return strlen(ALG_NAME_DH_NAME);
	}

	if (!strncmp(ALG_NAME_ECDH_NAME, buf, strlen(ALG_NAME_ECDH_NAME))) {
		g_asym_alg = SDPK_ALGOTYPE_ASYMM_ECDH;
		return strlen(ALG_NAME_ECDH_NAME);
	}

	return -1;
}

static DEVICE_ATTR(asym_alg, S_IRUSR | S_IWUSR, dek_show_asym_alg, dek_set_asym_alg);

int dek_create_sysfs_asym_alg(struct device *d)
{
	int error;

	if ((error = device_create_file(d, &dev_attr_asym_alg)))
		return error;

	return 0;
}

int get_sdp_sysfs_asym_alg(void)
{
	return g_asym_alg;
}

#ifdef CONFIG_SDP_KEY_DUMP
static int kek_dump = 0;

static ssize_t dek_show_key_dump(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", kek_dump);
}

static ssize_t dek_set_key_dump(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int flag = simple_strtoul(buf, NULL, 10);

	kek_dump = flag;

	return strlen(buf);
}

static DEVICE_ATTR(key_dump, 0664, dek_show_key_dump, dek_set_key_dump);

int dek_create_sysfs_key_dump(struct device *d)
{
	int error;

	if ((error = device_create_file(d, &dev_attr_key_dump)))
		return error;

	return 0;
}

int get_sdp_sysfs_key_dump(void)
{
	return kek_dump;
}
#else
int dek_create_sysfs_key_dump(struct device *d)
{
	printk("key_dump feature not available");

	return 0;
}

int get_sdp_sysfs_key_dump(void)
{
	printk("key_dump feature not available");

	return 0;
}
#endif
