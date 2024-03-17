#ifndef DM_VERITY_DEBUG_H
#define DM_VERITY_DEBUG_H

#include "dm-verity.h"
/*
 * If not use debug mode 
 * Please Command the Define(SEC_HEX_DEBUG) below
 */
#define SEC_HEX_DEBUG

#ifdef SEC_HEX_DEBUG
#define MAX_FC_BLKS_LIST 128 
#define MAX_DEV_NAME 16 
#define MAX_DEV_LIST 10
#define FOR_SAFE 20

struct blks_info{
    /* blks cnt info */
    atomic64_t total_blks;
    atomic64_t skipped_blks;
    atomic64_t fec_correct_blks; 
    atomic64_t corrupted_blks; 
    atomic64_t prev_total_blks;

    /* fec corrected blocks list */
    sector_t fc_blks_list[MAX_FC_BLKS_LIST + FOR_SAFE]; 
    char dev_name[MAX_FC_BLKS_LIST + FOR_SAFE][MAX_DEV_NAME];
    char fec_off_list[MAX_DEV_LIST][MAX_DEV_NAME];
    char dmv_ctr_list[MAX_DEV_LIST][MAX_DEV_NAME];
    /* The "list_idx" value is the location of the new correct_blk to be entered for fc_blks_list []. */
    int list_idx; 
    atomic_t fec_off_cnt;
    atomic_t dmv_ctr_cnt;
};
extern struct blks_info *b_info;

/* ignore_fs_panic is not ported.
   we may not need to ignore_fs_panic.
   verity_is_system_shutting_down is added.
 */
//extern int ignore_fs_panic;

extern int verity_handle_err_hex_debug(struct dm_verity *v, enum verity_block_type type,
					     unsigned long long block, struct dm_verity_io *io, struct bvec_iter *iter);


extern void free_b_info(void);
extern void print_blks_cnt(char* dev_name);
extern int empty_b_info(void);

/* get */
extern long long get_total_blks(void);
extern long long get_skipped_blks(void);
extern long long get_fec_correct_blks(void);
extern long long get_corrupted_blks(void);
extern long long get_prev_total_blks(void);
extern int get_fec_off_cnt(void);
extern int get_dmv_ctr_cnt(void);
extern struct blks_info * get_b_info(char* dev_name);
/* set */
extern void set_prev_total_blks(long long val);
/* add */
extern void add_total_blks(long long val);
extern void add_skipped_blks(void);
extern void add_fec_correct_blks(void);
extern void add_corrupted_blks(void);
extern void add_fc_blks_entry(sector_t cur_blk, char* dev_name);
extern void add_fec_off_cnt(char* dev_name);

#endif

#endif
