/*
 * Copyright (c) 2020-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/delay.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "include/defex_internal.h"
#include "include/defex_rules.h"

#define DEFEX_RULES_FILE "/dpolicy"
#define DUMMY_DIR "/dummy"
#define ROOT_PATH "/"
#define INTEGRITY_DEFAULT "/system/bin/install-recovery.sh"
#define NOT_A_PATH "not_a_path"
#define SYSTEM_ROOT "/system_root"


#ifdef DEFEX_USE_PACKED_RULES
extern struct rule_item_struct *lookup_dir(struct rule_item_struct *base, const char *name, int l, int for_recovery,
	char *base_start);
extern int lookup_tree(const char *file_path, int attribute, struct file *f);
#ifdef DEFEX_RAMDISK_ENABLE
extern unsigned char packed_rules_primary[];
#endif /* DEFEX_RAMDISK_ENABLE */
#endif /* DEFEX_USE_PACKED_RULES */

#if defined(DEFEX_RAMDISK_ENABLE) && defined(DEFEX_KERNEL_ONLY)
extern int load_rules_late(void);
#endif /* DEFEX_RAMDISK_ENABLE && DEFEX_KERNEL_ONLY */

#ifdef DEFEX_INTEGRITY_ENABLE
#define SHA256_DIGEST_SIZE 32
extern int defex_check_integrity(struct file *f, unsigned char *hash);
extern int defex_integrity_default(const char *file_path);
#endif /* DEFEX_INTEGRITY_ENABLE */

extern int check_system_mount(void);

/* --------------------------------------------------------------------------*/
/* Auxiliary functions to find possible examples in the policy.              */
/* --------------------------------------------------------------------------*/

#if defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_RAMDISK_ENABLE)
static int rule_lookup_performed = 0;

char first_file[PATH_MAX];
int first_file_attr;
char second_file[PATH_MAX];
char existing_directory_no_features[PATH_MAX];
char existing_directory_path_open[PATH_MAX];
char existing_directory_path_write[PATH_MAX];

/* get_first_feature() - Get the first feature from an integer */
int get_first_feature(int feature_type)
{
#define TEST_FEATURE(ft) \
	if(feature_type & ft) {       \
		return ft;            \
	}
	TEST_FEATURE(feature_is_file);
	TEST_FEATURE(feature_for_recovery);
	TEST_FEATURE(feature_ped_path);
	TEST_FEATURE(feature_ped_exception);
	TEST_FEATURE(feature_ped_status);
	TEST_FEATURE(feature_safeplace_path);
	TEST_FEATURE(feature_safeplace_status);
	TEST_FEATURE(feature_immutable_path_open);
	TEST_FEATURE(feature_immutable_path_write);
	TEST_FEATURE(feature_immutable_src_exception);
	TEST_FEATURE(feature_immutable_status);
	TEST_FEATURE(feature_umhbin_path);

	return 0;
}

/**
 * find_paths() - Find example paths to be used in the test.
 * @node: The rule tree node being analyzed.
 * @current_path: The walked path so far.
 * @path_len: The path size so far.
 *
 * The method reads the packed_rules_primary policy array and find path and file
 * examples that are in the policy so the test can be performed correctly. The
 * lookup is done recursively, first horizontally and then vertically. This tree
 * walking strategy is done to make path string construction easier.
 *
 * The method finds and stores in static variables:
 * - Two different files that can be opened by the kunit without erros;
 *- A directory with no features;
 *- A directory with feature_immutable_path_open set;
 *- A directory with feature_immutable_path_write set.
 */
static void find_paths(struct rule_item_struct *node, char *current_path, size_t path_len)
{
	int attr;
	struct file *file_ptr;
	unsigned int is_system;
	static const unsigned char buff_zero[SHA256_DIGEST_SIZE] = {0};

	if (node->next_file) {
		find_paths(GET_ITEM_PTR(node->next_file, packed_rules_primary), current_path, path_len);
	}

	if (!strncmp(node->name, "tmp", node->size))
		return;

	/* If no more space in current_path is available, stop looking here. */
	if (PATH_MAX - path_len < node->size + 1)
		return;
	/* Append name to path */
	memset(current_path + path_len, 0, PATH_MAX - path_len);
	strncpy(current_path + path_len, "/", 1);
	strncpy(current_path + path_len + 1, node->name, node->size);
	path_len += node->size + 1;

	is_system = ((strncmp("/system/", current_path, 8) == 0) ||
			(strncmp("/product/", current_path, 9) == 0) ||
			(strncmp("/apex/", current_path, 6) == 0) ||
			(strncmp("/system_ext/", current_path, 12) == 0))?1:0;

	if (!(node->feature_type & feature_is_file)) {
		if (strlen(existing_directory_path_open) == 0 &&
			node->feature_type & feature_immutable_path_open) {
			strncpy(existing_directory_path_open, current_path, path_len);
		}
		if (strlen(existing_directory_path_write) == 0 &&
			node->feature_type & feature_immutable_path_write) {
			strncpy(existing_directory_path_write, current_path, path_len);
		}
		if (strlen(existing_directory_no_features) == 0 &&
			node->feature_type == 0) {
			strncpy(existing_directory_no_features, current_path, path_len);
		}
	}
	else {
		/* feature_is_file set */
		attr = get_first_feature(node->feature_type & feature_is_file);
#ifdef DEFEX_INTEGRITY_ENABLE
		/* Skip this file due to ZERO hash */
		if (!memcmp(buff_zero, node->integrity, SHA256_DIGEST_SIZE))
			attr = 0;
#endif
		if (attr && !is_system) {
			file_ptr = local_fopen(current_path, O_RDONLY, 0);
			if (!IS_ERR_OR_NULL(file_ptr)) {
				/* File with other feature */
				if (strlen(first_file) == 0) {
					strncpy(first_file, current_path,
						strlen(current_path));
					first_file_attr = attr;
				}
				else if (strlen(second_file) == 0) {
					strncpy(second_file, current_path,
						strlen(current_path));
				}
				filp_close(file_ptr, 0);
			}
		}
	}
	if (node->next_level) {
		find_paths(GET_ITEM_PTR(node->next_level, packed_rules_primary), current_path, path_len);
	}
}

/* Triggers the lookup process if DEFEX policy is loaded. */
static void find_rules_for_test(void)
{
	struct rule_item_struct *base;
	char *path;

	base = (struct rule_item_struct *)packed_rules_primary;
	if (!base || !base->data_size)
		/* Rules are not loaded --- can't find any paths */
		return;

	path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!path)
		return;

	find_paths(GET_ITEM_PTR(base->next_level, packed_rules_primary), path, 0);

	pr_info("kunit defex_rules_proc_test: Path results:");
	pr_info("kunit defex_rules_proc_test: first_file: %s", first_file);
	pr_info("kunit defex_rules_proc_test: second_file: %s", second_file);
	pr_info("kunit defex_rules_proc_test: existing_directory_no_features: %s",
		existing_directory_no_features);
	pr_info("kunit defex_rules_proc_test: existing_directory_path_open: %s",
		existing_directory_path_open);
	pr_info("kunit defex_rules_proc_test: existing_directory_path_write: %s",
		existing_directory_path_write);

	rule_lookup_performed = 1;
	kfree(path);
}
#endif /* DEFEX_USE_PACKED_RULES && DEFEX_RAMDISK_ENABLE */


static void rules_lookup_test(struct kunit *test)
{
#if (defined(DEFEX_SAFEPLACE_ENABLE) || defined(DEFEX_IMMUTABLE_ENABLE) || defined(DEFEX_PED_ENABLE))

#if defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_RAMDISK_ENABLE)
	/* If packed rules are being used, they need to be loaded before the test. */
	if (check_rules_ready() == 0) {
		kunit_info(test, "DEFEX policy not loaded: skip test.");
		return;
	}

	if (check_system_mount() == 1)
		KUNIT_EXPECT_EQ(test, 0, rules_lookup(SYSTEM_ROOT, 0, NULL));
	else
		KUNIT_EXPECT_EQ(test, 0, rules_lookup(NULL, 0, NULL));
#else
	/* Not able to build without packed rules --- Nothing to test for now. */
#endif /* DEFEX_USE_PACKED_RULES && DEFEX_RAMDISK_ENABLE*/
#endif /* DEFEX_SAFEPLACE_ENABLE || DEFEX_IMMUTABLE_ENABLE || DEFEX_PED_ENABLE */
	KUNIT_SUCCEED(test);
}


static void lookup_tree_test(struct kunit *test)
{
#if defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_RAMDISK_ENABLE)
	struct file *file_one, *file_two;

	/* If packed rules are being used, they need to be loaded before the test. */
	if (check_rules_ready() == 0) {
		kunit_info(test, "DEFEX policy not loaded: skip test.");
		return;
	}

	if (rule_lookup_performed == 0)
		/* If lookup not done yet, trigger it. */
		find_rules_for_test();

	/* T1: file_path = NULL or file_path[0] != '/' */
	KUNIT_EXPECT_EQ(test, 0, lookup_tree(NULL, 0, NULL));
	KUNIT_EXPECT_EQ(test, 0, lookup_tree(NOT_A_PATH, 0, NULL));

	if (strlen(first_file) > 0 && strlen(second_file) > 0) {
		/* Policy lookup fond examples. */
		file_one = local_fopen(first_file, O_RDONLY, 0);
		if (IS_ERR_OR_NULL(file_one))
			goto test_four;
		file_two = local_fopen(second_file, O_RDONLY, 0);
		if (IS_ERR_OR_NULL(file_two)) {
			filp_close(file_one, 0);
			goto test_four;
		}

		/* T2: file with attribute other than feature_is_file */
		KUNIT_EXPECT_EQ(test, 1, lookup_tree(first_file, first_file_attr, file_one));

		/* T3: file with different contents and without check integrity flag */
		KUNIT_EXPECT_EQ(test, 1, lookup_tree(first_file, first_file_attr, file_two));

		filp_close(file_one, 0);
		filp_close(file_two, 0);
	}
test_four:
	/* T4: Root path -> Does not look into the tree. */
	KUNIT_EXPECT_EQ(test, 0, lookup_tree(ROOT_PATH, 0, NULL));

	if (strlen(existing_directory_path_open) > 0) {
		/* T5: Path with feature_immutable_path_open */
		KUNIT_EXPECT_EQ(test, 0, lookup_tree(existing_directory_path_open, feature_immutable_path_open, NULL));

		/* T6: with other separator */
		existing_directory_path_open[strlen(existing_directory_path_open)] = '/';
		KUNIT_EXPECT_EQ(test, 0, lookup_tree(existing_directory_path_open, feature_immutable_path_open, NULL));
		existing_directory_path_open[strlen(existing_directory_path_open) - 1] = '\0';
	}

	if (strlen(existing_directory_path_write) > 0) {
		/* T7: Path with feature_immutable_path_write */
		KUNIT_EXPECT_EQ(test, 0, lookup_tree(existing_directory_path_write, feature_immutable_path_write, NULL));

		/* T8: with other separator */
		existing_directory_path_write[strlen(existing_directory_path_write)] = '/';
		KUNIT_EXPECT_EQ(test, 0, lookup_tree(existing_directory_path_write, feature_immutable_path_write, NULL));
		existing_directory_path_write[strlen(existing_directory_path_write) - 1] = '\0';
	}

	/* T9: Path not present in policy */
	KUNIT_EXPECT_EQ(test, 0, lookup_tree(DUMMY_DIR, feature_immutable_path_open, NULL));

#endif /* DEFEX_USE_PACKED_RULES && DEFEX_RAMDISK_ENABLE*/
	KUNIT_SUCCEED(test);
}


static void lookup_dir_test(struct kunit *test)
{
#if defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_RAMDISK_ENABLE)

	struct rule_item_struct *policy_item = NULL;
	struct rule_item_struct *policy_base = (struct rule_item_struct *)packed_rules_primary;
	char *path, *next_separator;
	int size;

	/* If packed rules are being used, they need to be loaded before the test. */
	if (check_rules_ready() == 0) {
		kunit_info(test, "DEFEX policy not loaded: skip test.");
		return;
	}

	if (rule_lookup_performed == 0)
		/* If lookup not done yet, trigger it. */
		find_rules_for_test();

	/* T1: !base || !base->next_level -> return NULL */
	KUNIT_EXPECT_PTR_EQ(test, (struct rule_item_struct *)NULL, lookup_dir(NULL, NULL, 0, 0, packed_rules_primary));

	/* T2: Existing directory */
	if (strlen(existing_directory_no_features) > 0) {
		/* Policy parse found directory */
		path = existing_directory_no_features + 1;
		/* Since we have the entire path,
		 * we need to iterate over each dir
		 */
		do {
			next_separator = strchr(path, '/');
			if (!next_separator)
				size = strlen(path);
			else
				size = next_separator - path;
			if (!size)
				KUNIT_FAIL(test, "Error in lookup: existing_directory_no_features");
			policy_item = lookup_dir(policy_base, path, size, 0, packed_rules_primary);
			KUNIT_ASSERT_PTR_NE(test, policy_item, (struct rule_item_struct *)NULL);
			KUNIT_EXPECT_EQ(test, 0, strncmp(policy_item->name, path, size));
			policy_base = policy_item;
			path += size;
			if (next_separator)
				path++;
		} while(*path);
	}

	/* T3: Non-existing directory */
	KUNIT_EXPECT_PTR_EQ(test, (struct rule_item_struct *)NULL, lookup_dir(policy_base, DUMMY_DIR, strlen(DUMMY_DIR), 0, packed_rules_primary));

#endif /* DEFEX_USE_PACKED_RULES && DEFEX_RAMDISK_ENABLE*/
	KUNIT_SUCCEED(test);
}


static void load_rules_late_test(struct kunit *test)
{
#if defined(DEFEX_RAMDISK_ENABLE) && defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_KERNEL_ONLY)

	/* The test cannot try to load the policy by its own,
	 * since it can compromise the system.
	 */

#endif /* DEFEX_RAMDISK_ENABLE && DEFEX_USE_PACKED_RULES && DEFEX_KERNEL_ONLY */
	KUNIT_SUCCEED(test);
}


static void do_load_rules_test(struct kunit *test)
{
	/* __init function */
	KUNIT_SUCCEED(test);
}


static void defex_load_rules_test(struct kunit *test)
{
	/* __init function */
	KUNIT_SUCCEED(test);
}


static void defex_integrity_default_test(struct kunit *test)
{
#ifdef DEFEX_INTEGRITY_ENABLE
	KUNIT_EXPECT_EQ(test, 0, defex_integrity_default(INTEGRITY_DEFAULT));
	KUNIT_EXPECT_NE(test, 0, defex_integrity_default(DUMMY_DIR));
#endif
	KUNIT_SUCCEED(test);
}


static void defex_init_rules_proc_test(struct kunit *test)
{
	/* __init function */
	KUNIT_SUCCEED(test);
}


static void defex_check_integrity_test(struct kunit *test)
{
#ifdef DEFEX_INTEGRITY_ENABLE
	unsigned char hash[SHA256_DIGEST_SIZE] = {0};
	struct file *test_file;
#if defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_RAMDISK_ENABLE)
	struct rule_item_struct *policy_item = NULL;
	struct rule_item_struct *policy_base = (struct rule_item_struct *)packed_rules_primary;
	char *path, *next_separator;
	int size;
#endif
	/* T1: hash zero - no check is done */
	KUNIT_EXPECT_EQ(test, 0, defex_check_integrity(NULL, hash));

	/* 'random' hash */
	memcpy((void *) hash, "A32CharacterStringForTestingThis", SHA256_DIGEST_SIZE);

	/* T2: file pointer is error */
	KUNIT_EXPECT_EQ(test, -1, defex_check_integrity(ERR_PTR(-1), hash));

	/* T3: Wrong hash */
	test_file = local_fopen(DEFEX_RULES_FILE, O_RDONLY, 0);
	if (!IS_ERR_OR_NULL(test_file)) {
		KUNIT_EXPECT_NE(test, 0, defex_check_integrity(test_file, hash));
		filp_close(test_file, NULL);
	}

#if defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_RAMDISK_ENABLE)
	/* T4: Right hash */
	if (strlen(first_file) > 0) {
		/* Find policy item for first file */
		path = first_file + 1;
		/* Since we have the entire path,
		 * we need to iterate over each dir
		 */
		do {
			next_separator = strchr(path, '/');
			if (!next_separator)
				size = strlen(path);
			else
				size = next_separator - path;
			if (!size)
				KUNIT_FAIL(test, "Error in lookup: existing_directory_no_features");
			policy_item = lookup_dir(policy_base, path, size, 0, packed_rules_primary);
			KUNIT_ASSERT_PTR_NE(test, policy_item, (struct rule_item_struct *)NULL);
			KUNIT_ASSERT_EQ(test, 0, strncmp(policy_item->name, path, size));
			policy_base = policy_item;
			path += size;
			if (next_separator)
				path++;
		} while(*path);

		test_file = local_fopen(first_file, O_RDONLY, 0);
		KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(test_file));
		KUNIT_EXPECT_EQ(test, 0, defex_check_integrity(test_file, policy_item->integrity));
		filp_close(test_file, NULL);
	}
#else
	/* Not able to build without packed rules --- Nothing to test for now. */
#endif /* DEFEX_USE_PACKED_RULES && DEFEX_RAMDISK_ENABLE*/
#endif /* DEFEX_INTEGRITY_ENABLE */
	KUNIT_SUCCEED(test);
}


static void check_system_mount_test(struct kunit *test)
{
	struct file *fp;
	fp = local_fopen(SYSTEM_ROOT, O_DIRECTORY | O_PATH, 0);

	if (!IS_ERR(fp)) {
		filp_close(fp, NULL);
		KUNIT_EXPECT_EQ(test, check_system_mount(), 1);
	} else {
		KUNIT_EXPECT_EQ(test, check_system_mount(), 0);
	}
	KUNIT_SUCCEED(test);
}


static void check_rules_ready_test(struct kunit *test)
{
#if defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_RAMDISK_ENABLE)
	struct rule_item_struct *base_struct = (struct rule_item_struct *)packed_rules_primary;

	if (!base_struct || !base_struct->data_size)
		KUNIT_EXPECT_EQ(test, 0, check_rules_ready());
	else
		KUNIT_EXPECT_EQ(test, 1, check_rules_ready());

#endif /* DEFEX_USE_PACKED_RULES && DEFEX_RAMDISK_ENABLE*/
	KUNIT_SUCCEED(test);
}


static void bootmode_setup_test(struct kunit *test)
{
	/* __init function */
	KUNIT_SUCCEED(test);
}


static int defex_rules_proc_test_init(struct kunit *test)
{
#if defined(DEFEX_USE_PACKED_RULES) && defined(DEFEX_RAMDISK_ENABLE)
	if(!rule_lookup_performed) {
		memset(first_file, 0, PATH_MAX);
		memset(second_file, 0, PATH_MAX);
		memset(existing_directory_no_features, 0, PATH_MAX);
		memset(existing_directory_path_open, 0, PATH_MAX);
		memset(existing_directory_path_write, 0, PATH_MAX);

		find_rules_for_test();
	}
#endif /* DEFEX_USE_PACKED_RULES && DEFEX_RAMDISK_ENABLE */
	return 0;
}

static void defex_rules_proc_test_exit(struct kunit *test)
{
}

static struct kunit_case defex_rules_proc_test_cases[] = {
	/* TEST FUNC DEFINES */
	KUNIT_CASE(rules_lookup_test),
	KUNIT_CASE(lookup_tree_test),
	KUNIT_CASE(lookup_dir_test),
	KUNIT_CASE(load_rules_late_test),
	KUNIT_CASE(do_load_rules_test),
	KUNIT_CASE(defex_load_rules_test),
	KUNIT_CASE(defex_integrity_default_test),
	KUNIT_CASE(defex_init_rules_proc_test),
	KUNIT_CASE(defex_check_integrity_test),
	KUNIT_CASE(check_system_mount_test),
	KUNIT_CASE(check_rules_ready_test),
	KUNIT_CASE(bootmode_setup_test),
	{},
};

static struct kunit_suite defex_rules_proc_test_module = {
	.name = "defex_rules_proc_test",
	.init = defex_rules_proc_test_init,
	.exit = defex_rules_proc_test_exit,
	.test_cases = defex_rules_proc_test_cases,
};
kunit_test_suites(&defex_rules_proc_test_module);

