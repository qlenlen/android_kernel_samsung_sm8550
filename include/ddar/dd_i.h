/*
 * File: include/ddar/dd.h
 *
 * Samsung dual DAR driver cache I/O relay to user space daemon interface
 *
 * Author: Olic Moon <olic.moon@samsung.com>
 */

#ifndef INCLUDE_DDAR_DD_I_H_
#define INCLUDE_DDAR_DD_I_H_

#include <linux/ioctl.h>

#define DDAR_DRIVER_VERSION_0	0	// SEC_PRODUCT_FEATURE_KNOX_CONFIG_DUALDAR_VERSION: NULL
#define DDAR_DRIVER_VERSION_1	1	// SEC_PRODUCT_FEATURE_KNOX_CONFIG_DUALDAR_VERSION: 1.0.1
/**
 * Use AES-CBC mode for en/decrypting data in DualDAR samsung-crypto.
 * In case of FOTA update, maintain AES-XTS mode.
 */
#define DDAR_DRIVER_VERSION_2	2
#define DDAR_DRIVER_VERISON_CURRENT (DDAR_DRIVER_VERSION_2)

#define DD_KEY_DESC_PREFIX		"ddar:"
#define DD_KEY_DESC_PREFIX_LEN 	5

#define DD_POLICY_ENABLED				(0x01)
#define DD_POLICY_USER_SPACE_CRYPTO 	(0x02)
#define DD_POLICY_KERNEL_CRYPTO 		(0x04)
#define DD_POLICY_GID_RESTRICTION		(0x08)
#define DD_POLICY_SKIP_DECRYPTION_INNER	(0x10)
#define DD_POLICY_SKIP_DECRYPTION_OUTER	(0x20)
#define DD_POLICY_TRACE_FILE			(0x40)
#define DD_POLICY_SECURE_ERASE			(0x80)

#define AID_VENDOR_DDAR_DE_ACCESS		(5300)
struct dd_policy {
	char version; // dualdar feature version
	char userid; // Android userid
	short flags; // policy flags
} __attribute__((__packed__));


static inline int dd_policy_enabled(char flags)
{
	return (flags & DD_POLICY_ENABLED) ? 1:0;
}

static inline int dd_policy_user_space_crypto(char flags)
{
	return (flags & DD_POLICY_USER_SPACE_CRYPTO) ? 1:0;
}

static inline int dd_policy_kernel_crypto(char flags)
{
	return (flags & DD_POLICY_KERNEL_CRYPTO) ? 1:0;
}

static inline int dd_policy_encrypted(char flags)
{
	if (dd_policy_user_space_crypto(flags) || dd_policy_kernel_crypto(flags))
		return 1;

	return 0;
}

static inline int dd_policy_gid_restriction(char flags)
{
	return (flags & DD_POLICY_GID_RESTRICTION) ? 1:0;
}

static inline int dd_policy_secure_erase(char flags)
{
	return (flags & DD_POLICY_SECURE_ERASE) ? 1:0;
}

static inline int dd_policy_skip_decryption_inner_and_outer(char flags)
{
	return ((flags & DD_POLICY_SKIP_DECRYPTION_INNER) ? 1:0)
			&& ((flags & DD_POLICY_SKIP_DECRYPTION_OUTER) ? 1:0);
}

static inline int dd_policy_skip_decryption_inner(char flags)
{
	return (flags & DD_POLICY_SKIP_DECRYPTION_INNER) ? 1:0;
}

static inline int dd_policy_trace_file(char flags)
{
	return (flags & DD_POLICY_TRACE_FILE) ? 1:0;
}

typedef enum {
	DD_ENCRYPT = 0,
	DD_DECRYPT,
} dd_crypto_direction_t;

typedef enum {
	DD_REQ_INVALID = 0,
	DD_REQ_PREPARE = 1,
	DD_REQ_CRYPTO_BIO = 2,
	DD_REQ_CRYPTO_PAGE = 3
} dd_request_code_t;

typedef enum {
	DD_RES_INVALID = 0,
	DD_RES_SUCCESS,
	DD_RES_FAILED,
} dd_response_code_t;

// BUG_ON(sizeof(struct metadata_hdr) != METADATA_HEADER_LEN)
#define METADATA_HEADER_LEN		64
struct metadata_hdr {
	unsigned long ino;
	unsigned char userid;
	unsigned char initialized;
	unsigned char reserved[54];
} __attribute__((__packed__));

struct dd_user_req {
    unsigned unique;
	char version;
	char userid;
	short policy_flag;
	unsigned long ino;
	dd_request_code_t code;

	union {
		struct {
			dd_crypto_direction_t rw;
			unsigned long index;
			unsigned long plain_addr;
			unsigned long cipher_addr;
		} bio;
		struct {
			unsigned long md_addr;
		} prepare;
	} u;
};

#define MAX_NUM_INO_PER_USER_REQUEST 64
#define MAX_NUM_CONTROL_PAGE 16
#define MAX_NUM_REQUEST_PER_CONTROL 64
struct dd_mmap_control {
	unsigned num_requests;
	struct dd_user_req requests[MAX_NUM_REQUEST_PER_CONTROL];
} __attribute__((__packed__));

struct dd_mmap_area {
	unsigned long start;
	unsigned long size;
} __attribute__((__packed__));

struct dd_mmap_layout {
	unsigned page_size;
	unsigned page_num_limit;
	struct dd_mmap_area control_area;
	struct dd_mmap_area metadata_area;
	struct dd_mmap_area plaintext_page_area;
	struct dd_mmap_area ciphertext_page_area;
} __attribute__((__packed__));

#define DD_METADATA_NAME "dd_metadata"
/**
 * ioctl flags
 */
#define DD_IOCTL_GET_DEBUG_MASK			_IO('O', 0x01)
#define DD_IOCTL_GET_MMAP_LAYOUT		_IO('O', 0x02)
#define DD_IOCTL_DUMP_REQ_LIST			_IO('O', 0x03)
#define DD_IOCTL_ABORT_PENDING_REQ_TIMEOUT _IO('O', 0x04)
#define DD_IOCTL_UPDATE_LOCK_STATE		_IO('L', 0x01)
#define DD_IOCTL_GET_LOCK_STATE			_IOR('L', 0x02, unsigned int) /* KNOX_SUPPORT_DAR_DUAL_DO */
#define DD_IOCTL_REGISTER_CRYPTO_TASK	_IO('C', 0x10)
#define DD_IOCTL_UNREGISTER_CRYPTO_TASK	_IO('C', 0x20)
#define DD_IOCTL_WAIT_CRYPTO_REQUEST	_IO('C', 0x01)
#define DD_IOCTL_SUBMIT_CRYPTO_RESULT	_IO('C', 0x02)
#define DD_IOCTL_ABORT_CRYPTO_REQUEST	_IO('C', 0x03)
#define DD_IOCTL_GET_XATTR				_IO('M', 0x01)
#define DD_IOCTL_SET_XATTR				_IO('M', 0x02)
#define DD_IOCTL_ADD_KEY				_IO('K', 0x01)
#define DD_IOCTL_EVICT_KEY				_IO('K', 0x02)
#define DD_IOCTL_DUMP_KEY				_IO('K', 0x03)
#define DD_IOCTL_SKIP_DECRYPTION_BOTH	_IO('K', 0x04)
#define DD_IOCTL_SKIP_DECRYPTION_INNER	_IO('K', 0x05)
#define DD_IOCTL_NO_SKIP_DECRYPTION		_IO('K', 0x06)
#define DD_IOCTL_TRACE_DDAR_FILE		_IO('K', 0x07)
#define DD_IOCTL_SEND_LOG				_IO('D', 0x01)

//#define EXT4_IOC_GET_DD_POLICY			_IO('P', 0x00)
//#define EXT4_IOC_SET_DD_POLICY			_IO('P', 0x01)
//#define FS_IOC_GET_DD_POLICY			_IO('P', 0x00)
//#define FS_IOC_SET_DD_POLICY			_IO('P', 0x01)

#define MAX_XATTR_NAME_LEN 32
#define MAX_XATTR_LEN 128
struct dd_user_resp {
	unsigned long ino;
	int err;
};

static inline int get_user_resp_err(struct dd_user_resp *err, int num_err, unsigned long ino)
{
	int i;
	if (num_err <= MAX_NUM_REQUEST_PER_CONTROL) {
		for (i = 0; i < num_err; i++)
			if (err[i].ino == ino)
				return err[i].err;
	}

	return -ENOENT;
}

#define DD_LOGBUF_MAX (256)
struct dd_ioc {
	union {
		struct {
			int num_control_page;
			int num_metadata_page;
		} crypto_request;
		struct {
			int num_err;
			struct dd_user_resp err[MAX_NUM_INO_PER_USER_REQUEST];
		} crypto_response;
		struct {
			unsigned long ino;
			char name[MAX_XATTR_NAME_LEN];
			char value[MAX_XATTR_LEN];
			unsigned int size;
		} xattr;
		struct {
			int state;
		} lock;
		struct {
			unsigned short userid;
			unsigned char key[128];
			unsigned short len;
		} add_key;
		struct {
			unsigned short userid;
		} evict_key;
		struct {
			unsigned short userid;
			int fileDescriptor;
		} dump_key;
		struct {
			unsigned short userid;
			unsigned short mask;
			unsigned char buf[DD_LOGBUF_MAX];
		} log_msg;
		struct dd_mmap_layout layout;
		unsigned int debug_mask;
		int user_error;
	} u;
} __attribute__((__packed__));

enum {
	DD_DEBUG_ERROR		= 1U << 0,
	DD_DEBUG_INFO		= 1U << 1,
	DD_DEBUG_VERBOSE	= 1U << 2,
	DD_DEBUG_MEMDUMP	= 1U << 3,
	DD_DEBUG_MEMORY		= 1U << 4,
	DD_DEBUG_BENCHMARK	= 1U << 5,
	DD_DEBUG_PROCESS	= 1U << 6,
	DD_DEBUG_CALL_STACK	= 1U << 7,
};

#endif /* INCLUDE_DDAR_DD_I_H_ */
