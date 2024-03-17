#include <linux/kobject.h>

#include "include/defex_debug.h"
#include "include/defex_rules.h"

const char header_name[16] = {"DEFEX_RULES_FILE"};
struct rule_item_struct *defex_packed_rules;
static char work_path[512];
static int packfiles_size, global_data_size;


const struct feature_match_entry feature_match[] = {
	{"feature_safeplace_path", feature_safeplace_path},
	{"feature_ped_exception", feature_ped_exception},
	{"feature_immutable_path_open", feature_immutable_path_open},
	{"feature_immutable_path_write", feature_immutable_path_write},
	{"feature_immutable_src_exception", feature_immutable_src_exception},
	{"feature_umhbin_path", feature_umhbin_path},
	{"feature_integrity_check", feature_integrity_check},
};

const int feature_match_size = ARRAY_SIZE(feature_match);

static void feature_to_str(char *str, unsigned short flags)
{
	int i;

	str[0] = 0;
	for (i = 0; i < feature_match_size; i++)
		if (flags & feature_match[i].feature_num) {
			if (str[0])
				strcat(str, ", ");
			strcat(str, feature_match[i].feature_name);
		}
	if (flags & feature_for_recovery) {
		if (str[0])
			strcat(str, ", ");
		strcat(str, "feature_for_recovery");
	}
}

static int check_array_size(struct rule_item_struct *ptr)
{
	unsigned long offset = (unsigned long)ptr - (unsigned long)defex_packed_rules;
	int min_size = (global_data_size < packfiles_size)?global_data_size:packfiles_size;

	offset += sizeof(struct rule_item_struct);

	if (offset > min_size)
		return 1;

	offset += ptr->size;
	if (offset > min_size)
		return 2;
	return 0;
}

static int parse_items(struct rule_item_struct *base, int path_length, int level)
{
	int l, err, ret = 0;
	unsigned int offset;
	struct rule_item_struct *child_item;
	static char feature_list[128];

	if (level > 8) {
		defex_log_timeoff("Level is too deep");
		return -1;

	}
	if (path_length > (sizeof(work_path) - 128)) {
		defex_log_timeoff("Work path is too long");
		return -1;
	}
	while (base) {
		err = check_array_size(base);
		if (err) {
			defex_log_timeoff("%s/<?> - out of array bounds", work_path);
			return -1;
		}
		l = base->size;
		if (!l) {
			defex_log_timeoff("WARNING: Name field is incorrect, structure error!");
			return -1;

		}

		memcpy(work_path + path_length, base->name, l);
		l += path_length;
		work_path[l] = 0;
		offset = base->next_level;
		if (offset) {
			if (base->feature_type & feature_is_file) {
				defex_log_timeoff("%s - is a file, but has children, structure error!", work_path);
				ret = -1;
			} else if (base->feature_type != 0) {
				feature_to_str(feature_list, base->feature_type);
				defex_log_blob("%s%c - %s", work_path,
							((base->feature_type & feature_is_file)?' ':'/'), feature_list);
			}
			child_item = GET_ITEM_PTR(offset, defex_packed_rules);
			work_path[l++] = '/';
			work_path[l] = 0;
			err = check_array_size(child_item);
			if (!err) {
				err = parse_items(child_item, l, level + 1);
				if (err != 0)
					return err;
			} else {
				defex_log_timeoff("%s/<?> - out of array bounds", work_path);
				ret = -1;
			}
		} else {
			feature_to_str(feature_list, base->feature_type);
			defex_log_blob("%s%c - %s", work_path,
						((base->feature_type & feature_is_file)?' ':'/'), feature_list);
		}
		work_path[path_length] = 0;
		offset = base->next_file;
		base = (offset)?GET_ITEM_PTR(offset, defex_packed_rules):NULL;
	}
	return ret;
}

int defex_show_structure(void *packed_rules, int rules_size)
{
	struct rule_item_struct *base;
	int res, offset;
	int first_item_size = sizeof(struct rule_item_struct) + sizeof(header_name);

	defex_packed_rules = (struct rule_item_struct *)packed_rules;

	work_path[0] = '/';
	work_path[1] = 0;

	packfiles_size = rules_size;
	global_data_size = defex_packed_rules->data_size;

	defex_log_timeoff("Rules binary size: %d", packfiles_size);
	defex_log_timeoff("Rules internal data size: %d", global_data_size);

	if (global_data_size > packfiles_size)
		defex_log_timeoff("WARNING: Internal size is bigger than binary size, possible structure error!");

	if (packfiles_size < first_item_size) {
		defex_log_timeoff("ERROR: Too short binary size, can't continue!");
		return -1;
	}

	if (global_data_size < first_item_size)
		defex_log_timeoff("WARNING: Too short data size, possible structure error!");

	if (defex_packed_rules->size != sizeof(header_name))
		defex_log_timeoff("WARNING: incorrect size field (%d), possible structure error!",
						(int)defex_packed_rules->size);

	if (memcmp(header_name, defex_packed_rules->name, sizeof(header_name)) != 0)
		defex_log_timeoff("WARNING: incorrect name field, possible structure error!");

	defex_log_timeoff("File List:\n");
	offset = defex_packed_rules->next_level;
	base = (offset)?GET_ITEM_PTR(offset, defex_packed_rules):NULL;
	if (!base) {
		defex_log_timeoff("- empty list\n");
		return 0;
	} else if (check_array_size(base)) {
		defex_log_timeoff("- list is out of array bounds!");
		return -1;
	}

	res = parse_items(base, 1, 1);
	defex_log_timeoff("== End of File List ==");
	return res;
}

