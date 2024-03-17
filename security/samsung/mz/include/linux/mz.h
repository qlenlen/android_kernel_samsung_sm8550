#ifndef _LINUX_MZ_H
#define _LINUX_MZ_H

typedef enum {
	MZ_SUCCESS = 1,
	MZ_GENERAL_ERROR = 0,
	MZ_MALLOC_ERROR = -1,
	MZ_IOCTL_OPEN_ERROR = -2,
	MZ_INVALID_INPUT_ERROR = -3,
	MZ_TA_FAIL = -4,
	MZ_NO_TARGET = -5,
	MZ_DRIVER_FAIL = -6,
	MZ_PROC_NAME_GET_ERROR = -7,
	MZ_GET_TS_ERROR = -8,
	MZ_LOCK_FAIL = -9,
	MZ_PAGE_FAIL = -10,
	MZ_CRYPTO_FAIL = -11,
} MzResult;

MzResult mz_exit(void);

struct mz_tee_driver_fns {
	MzResult (*encrypt)(uint8_t *pt, uint8_t *ct, uint8_t *iv);
};
MzResult register_mz_tee_crypto_driver(
		struct mz_tee_driver_fns *tee_driver_fns);
void unregister_mz_tee_crypto_driver(void);
extern MzResult (*load_trusted_app)(void);
extern void (*unload_trusted_app)(void);

#endif /* _LINUX_MZ_H */
