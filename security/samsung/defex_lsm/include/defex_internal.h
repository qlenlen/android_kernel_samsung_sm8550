/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
*/

#ifndef __CONFIG_SECURITY_DEFEX_INTERNAL_H
#define __CONFIG_SECURITY_DEFEX_INTERNAL_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/binfmts.h>
#include <linux/defex.h>
#include "defex_config.h"

#ifdef DEFEX_KUNIT_ENABLED
#include <kunit/mock.h>
#endif

#define DEFEX_MAJOR_VERSION			2
#define DEFEX_MINOR_VERSION			6
#define DEFEX_REVISION				"rel"

/* DEFEX Features */
#define FEATURE_NONE				0
#define FEATURE_CHECK_CREDS			(1 << 0)
#define FEATURE_CHECK_CREDS_SOFT		(1 << 1)
#define FEATURE_JAILHOUSE			(1 << 2) /* reserved for future use */
#define FEATURE_JAILHOUSE_SOFT			(1 << 3) /* reserved for future use */
#define FEATURE_RESTRICT_SYSCALL		(1 << 4) /* reserved for future use */
#define FEATURE_RESTRICT_SYSCALL_SOFT		(1 << 5) /* reserved for future use */
#define FEATURE_IMMUTABLE			(1 << 6)
#define FEATURE_IMMUTABLE_SOFT			(1 << 7)
#define FEATURE_SAFEPLACE			(1 << 8)
#define FEATURE_SAFEPLACE_SOFT			(1 << 9)
#define FEATURE_FIVE				(1 << 10) /* reserved for future use */
#define FEATURE_FIVE_SOFT			(1 << 11) /* reserved for future use */
#define FEATURE_TRUSTED_MAP			(1 << 12)
#define FEATURE_TRUSTED_MAP_SOFT		(1 << 13)
#define FEATURE_INTEGRITY			(1 << 14)
#define FEATURE_INTEGRITY_SOFT		(1 << 15)

#define FEATURE_CLEAR_ALL			(0xFF0000)

#define DEFEX_ALLOW				0
#define DEFEX_DENY				1

#define DEFEX_OK				0
#define DEFEX_NOK				1

#define DEFEX_STARTED				1


/* -------------------------------------------------------------------------- */
/* Integrity feature */
/* -------------------------------------------------------------------------- */

#define DEFEX_INTEGRITY_FAIL				(1 << 1)

/* -------------------------------------------------------------------------- */
/* PrivEsc feature */
/* -------------------------------------------------------------------------- */

#ifdef STRICT_UID_TYPE_CHECKS
#define CHECK_ROOT_CREDS(x) (uid_eq((x)->uid, GLOBAL_ROOT_UID) || \
		gid_eq((x)->gid, GLOBAL_ROOT_GID) || \
		uid_eq((x)->euid, GLOBAL_ROOT_UID) || \
		gid_eq((x)->egid, GLOBAL_ROOT_GID))

#define GLOBAL_SYS_UID KUIDT_INIT(1000)
#define GLOBAL_SYS_GID KGIDT_INIT(1000)

#define CHECK_SYS_CREDS(x) (uid_eq((x)->uid, GLOBAL_SYS_UID) || \
		gid_eq((x)->gid, GLOBAL_SYS_GID) || \
		uid_eq((x)->euid, GLOBAL_SYS_UID) || \
		gid_eq((x)->egid, GLOBAL_SYS_GID))

#define uid_get_value(x)	(x.val)
#define uid_set_value(x, v)	x.val = v

#else
#define CHECK_ROOT_CREDS(x) (((x)->uid == 0) || ((x)->gid == 0) || \
		((x)->euid == 0) || ((x)->egid == 0))
#define uid_get_value(x)	(x)
#define uid_set_value(x, v)	(x = v)
#endif /* STRICT_UID_TYPE_CHECKS */

#define CRED_FLAGS_PROOT    		(1 << 0)	/* parent is root */
#define CRED_FLAGS_MAIN_UPDATED		(1 << 1)	/* main thread's permission updated */
#define CRED_FLAGS_SUB_UPDATED		(1 << 2)	/* sub thread's permission updated */

#define GET_CREDS(ids_ptr, cred_data_ptr) do { uid = (ids_ptr)->uid; \
		fsuid = (ids_ptr)->fsuid; \
		egid = (ids_ptr)->egid; \
		cred_flags = (cred_data_ptr)->cred_flags; } while(0)

#define SET_CREDS(ids_ptr, cred_data_ptr) do { (ids_ptr)->uid = uid; \
		(ids_ptr)->fsuid = fsuid; \
		(ids_ptr)->egid = egid; \
		(cred_data_ptr)->cred_flags |= cred_flags; } while(0)

extern unsigned char global_privesc_status;

void get_task_creds(struct task_struct *p, unsigned int *uid_ptr, unsigned int *fsuid_ptr, unsigned int *egid_ptr, unsigned short *cred_flags_ptr);
int set_task_creds(struct task_struct *p, unsigned int uid, unsigned int fsuid, unsigned int egid, unsigned short cred_flags);
void set_task_creds_tcnt(struct task_struct *p, int addition);
int is_task_creds_ready(void);

/* -------------------------------------------------------------------------- */
/* Integrity feature */
/* -------------------------------------------------------------------------- */

extern unsigned char global_integrity_status;

/* -------------------------------------------------------------------------- */
/* SafePlace feature */
/* -------------------------------------------------------------------------- */

extern unsigned char global_safeplace_status;

/* -------------------------------------------------------------------------- */
/* Immutable feature */
/* -------------------------------------------------------------------------- */

extern unsigned char global_immutable_status;

/* -------------------------------------------------------------------------- */
/* Trusted Map feature */
/* -------------------------------------------------------------------------- */

extern unsigned char global_trusted_map_status;

enum trusted_map_status {
	DEFEX_TM_ENFORCING_MODE		= (1 << 0),
	DEFEX_TM_PERMISSIVE_MODE	= (1 << 1),
	DEFEX_TM_DEBUG_VIOLATIONS	= (1 << 2),
	DEFEX_TM_DEBUG_CALLS		= (1 << 3),
	DEFEX_TM_LAST_STATUS		= (1 << 4) - 1
};

static inline int defex_tm_mode_enabled(int mode_flag)
{
	return global_trusted_map_status & mode_flag;
}

struct defex_context;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
int defex_trusted_map_lookup(struct defex_context *dc, int argc, struct linux_binprm *bprm);
#else
int defex_trusted_map_lookup(struct defex_context *dc, int argc, void *argv);
#endif

/* -------------------------------------------------------------------------- */
/* Common Helper API */
/* -------------------------------------------------------------------------- */

struct defex_context {
	int syscall_no;
	struct task_struct *task;
	struct file *process_file;
	struct file *target_file;
	const struct path *process_dpath;
	const struct path *target_dpath;
	char *process_name;
	char *target_name;
	char *target_name_buff;
	char *process_name_buff;

	/* NB: cred must be the last field */
	struct cred *cred;
};

extern const char unknown_file[];

struct file *local_fopen(const char *fname, int flags, umode_t mode);
int local_fread(struct file *f, loff_t offset, void *ptr, unsigned long bytes);
int init_defex_context(struct defex_context *dc, int syscall, struct task_struct *p, struct file *f);
void release_defex_context(struct defex_context *dc);
struct file *get_dc_process_file(struct defex_context *dc);
const struct path *get_dc_process_dpath(struct defex_context *dc);
char *get_dc_process_name(struct defex_context *dc);
const struct path *get_dc_target_dpath(struct defex_context *dc);
char *get_dc_target_name(struct defex_context *dc);
struct file *defex_get_source_file(struct task_struct *p);
char *defex_get_filename(struct task_struct *p);
char* defex_resolve_filename(const char *name, char **out_buff);
int defex_files_identical(const struct file *f1, const struct file *f2);
static inline void safe_str_free(void *ptr)
{
	if (ptr && ptr != unknown_file)
		kfree(ptr);
}


/* -------------------------------------------------------------------------- */
/* Defex lookup API */
/* -------------------------------------------------------------------------- */

int rules_lookup(const char *target_file, int attribute, struct file *f);

/* -------------------------------------------------------------------------- */
/* Defex init API */
/* -------------------------------------------------------------------------- */

int __init defex_init_sysfs(void);
void __init creds_fast_hash_init(void);
int __init do_load_rules(void);

/* -------------------------------------------------------------------------- */
/* Defex debug API */
/* -------------------------------------------------------------------------- */

int immutable_status_store(const char *status_str);
int privesc_status_store(const char *status_str);
int safeplace_status_store(const char *status_str);
int integrity_status_store(const char *status_str);

extern bool boot_state_recovery __ro_after_init;
#ifdef DEFEX_DEPENDING_ON_OEMUNLOCK
extern bool boot_state_unlocked __ro_after_init;
extern int warranty_bit __ro_after_init;
#else
#define boot_state_unlocked	(0)
#define warranty_bit		(0)
#endif /* DEFEX_DEPENDING_ON_OEMUNLOCK */

#endif /* CONFIG_SECURITY_DEFEX_INTERNAL_H */
