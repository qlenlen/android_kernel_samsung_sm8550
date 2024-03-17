/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DEFEX_TEST_H
#define _DEFEX_TEST_H
#ifdef DEFEX_KUNIT_ENABLED
#include <kunit/mock.h>

#include <linux/types.h>
#include <linux/sysfs.h>

/* -------------------------------------------------------------------------- */
/* defex_debug */
/* -------------------------------------------------------------------------- */

extern struct kobj_attribute debug_attribute;

extern int set_user(struct cred *new_cred);
extern int set_cred(int target_id, int new_val);
extern ssize_t debug_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count);
extern ssize_t debug_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf);

/* -------------------------------------------------------------------------- */
/* defex_immutable */
/* -------------------------------------------------------------------------- */

extern int immutable_status_store(const char *status_str);

/* -------------------------------------------------------------------------- */
/* defex_priv */
/* -------------------------------------------------------------------------- */

extern int privesc_status_store(const char *status_str);

/* -------------------------------------------------------------------------- */
/* defex_safeplace */
/* -------------------------------------------------------------------------- */

extern int safeplace_status_store(const char *status_str);

/* -------------------------------------------------------------------------- */
/* defex_main */
/* -------------------------------------------------------------------------- */

struct defex_context;

extern struct task_struct *get_parent_task(const struct task_struct *p);

#ifdef DEFEX_DSMS_ENABLE
extern void defex_report_violation(const char *violation, uint64_t counter, struct defex_context *dc,
	uid_t stored_uid, uid_t stored_fsuid, uid_t stored_egid, int case_num);
#endif

#ifdef DEFEX_SAFEPLACE_ENABLE
extern long kill_process(struct task_struct *p);
#endif

#ifdef DEFEX_PED_ENABLE
extern long kill_process_group(struct task_struct *p, int tgid, int pid);
extern int task_defex_is_secured(struct defex_context *dc);
extern int at_same_group(unsigned int uid1, unsigned int uid2);
extern int at_same_group_gid(unsigned int gid1, unsigned int gid2);

#ifdef DEFEX_LP_ENABLE
extern int lower_adb_permission(struct defex_context *dc, unsigned short cred_flags);
#endif /* DEFEX_LP_ENABLE */
extern int task_defex_check_creds(struct defex_context *dc);
#endif /* DEFEX_PED_ENABLE */

#ifdef DEFEX_SAFEPLACE_ENABLE
extern int task_defex_safeplace(struct defex_context *dc);
#endif /* DEFEX_SAFEPLACE_ENABLE */

#ifdef DEFEX_IMMUTABLE_ENABLE
extern int task_defex_src_exception(struct defex_context *dc);
extern int task_defex_immutable(struct defex_context *dc, int attribute);
#endif /* DEFEX_IMMUTABLE_ENABLE */

#endif /* DEFEX_KUNIT_ENABLED */
#endif /* _DEFEX_TEST_H */
