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

#ifndef DEK_COMMON_H__
#define DEK_COMMON_H__

// ==== kernel configs
#include <linux/limits.h>
#include <linux/ioctl.h>
#include <linux/device.h>

#include <ddar/common.h>
#include "../../fs/crypto/ddar/ddar_crypto.h"

// ==== common configs
#define SDPK_DEFAULT_ALGOTYPE (SDPK_ALGOTYPE_ASYMM_ECDH)
#define SDPK_ALGOTYPE_ASYMM_RSA 0
#define SDPK_ALGOTYPE_ASYMM_DH  1
#define SDPK_ALGOTYPE_ASYMM_ECDH  2

//#define DEK_ENGINE_LOCAL_KEK
#define KEK_RSA_KEY_BITS        2048
#define KEK_MK_BITS             256
#define KEK_SS_BITS             256

#define DH_DEFAULT_GENERATOR	DH_GENERATOR_2
#define DH_MAXLEN				256

#define DEK_NAME_LEN            256
#define DEK_LEN             	32
#define DEK_MAXLEN          	400 // TODO : need to optimize the length of EDEK DEK_RSA_KEY_BITS/8 : 256 bytes , DH2236 : 280 bytes
#define DEK_PW_LEN              32
#define KEK_MAXLEN         		(KEK_RSA_KEY_BITS/4+4)
#define KEK_MK_LEN              (KEK_MK_BITS/8)
#define KEK_SS_LEN              (KEK_SS_BITS/8)
#define DEK_AES_HEADER          44
#define FEK_MAXLEN				32
#define EFEK_MAXLEN				(FEK_MAXLEN+16)

#define AES_BLOCK_SIZE 			16

// DEK types
#define DEK_TYPE_PLAIN          0
#define DEK_TYPE_RSA_ENC        1
#define DEK_TYPE_AES_ENC        2
//#define DEK_TYPE_DH_PUB       4
#define DEK_TYPE_DH_ENC         5
#define DEK_TYPE_ECDH256_ENC    6
#define DEK_TYPE_DUMMY          7
#define DEK_TYPE_SS             8
#define DEK_TYPE_SS_PAYLOAD     9

// KEK types
#define KEK_TYPE_SYM 		10
#define KEK_TYPE_RSA_PUB 	11
#define KEK_TYPE_RSA_PRIV 	12
#define KEK_TYPE_DH_PUB 	13
#define KEK_TYPE_DH_PRIV 	14
#define KEK_TYPE_ECDH256_PUB    15
#define KEK_TYPE_ECDH256_PRIV   16
#define KEK_TYPE_SS             17

#define SDPK_PATH_MAX	256
#define SDPK_PATH_FMT    "/data/system/users/%d/SDPK_%s"
#define SDPK_RPRI_NAME   "Rpri"
#define SDPK_RPUB_NAME   "Rpub"
#define SDPK_DPRI_NAME   "Dpri"
#define SDPK_DPUB_NAME   "Dpub"
#define SDPK_EDPRI_NAME   "EDpri"
#define SDPK_EDPUB_NAME   "EDpub"
#define SDPK_SYM_NAME     "sym"

typedef struct _password{
	unsigned int len;
	unsigned char buf[DEK_MAXLEN];
} password_t;

typedef struct _key{
	unsigned int type;
	unsigned int len;
	unsigned char buf[DEK_MAXLEN];
} dek_t;

typedef struct _kek{
	unsigned int type;
	unsigned int len;
	unsigned char buf[KEK_MAXLEN];
} kek_t;

typedef struct _payload{
	unsigned int efek_len;
	unsigned int dpub_len;
	unsigned char efek_buf[EFEK_MAXLEN];
	unsigned char dpub_buf[DH_MAXLEN];
} dh_payload;

typedef struct _ss_key {
	unsigned int len;
	unsigned char buf[KEK_SS_LEN];
} __attribute__((__packed__)) ssk_t;

typedef struct dh_key {
	unsigned int type;
	unsigned int len;
	unsigned char buf[DH_MAXLEN];
} __attribute__((__packed__)) dhk_t;

typedef struct _ss_payload {
	dhk_t dh;
	ssk_t ss;
} __attribute__((__packed__)) ss_payload;

/* Debug */
#define DEK_DEBUG		0

#if DEK_DEBUG
#define DEK_LOGD(...) printk("dek: "__VA_ARGS__)
#else
#define DEK_LOGD(...)
#endif /* DEK_DEBUG */
#define DEK_LOGI(...) printk(KERN_INFO "dek: "__VA_ARGS__)
#define DEK_LOGE(...) printk(KERN_ERR "dek: "__VA_ARGS__)

void hex_key_dump(const char *tag, uint8_t *data, size_t data_len);
void key_dump(unsigned char *buf, int len);

int is_kek_available(int userid, int kek_type);

int dek_create_sysfs_asym_alg(struct device *d);
int dek_create_sysfs_key_dump(struct device *d);
int get_sdp_sysfs_asym_alg(void);
int get_sdp_sysfs_key_dump(void);

int is_root(void);
int is_current_epmd(void);
int is_current_adbd(void);
int is_system_server(void);

#ifdef CONFIG_FSCRYPT_SDP
extern int fscrypt_sdp_cache_init(void);
extern void fscrypt_sdp_cache_drop_inode_mappings(int engine_id);
#endif

#endif
