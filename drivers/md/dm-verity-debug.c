#include "dm-verity-debug.h"

#include <linux/module.h>
#include <linux/reboot.h>

#include <linux/ctype.h>

#define DM_MSG_PREFIX           "verity"

#define DM_VERITY_ENV_LENGTH        42
#define DM_VERITY_ENV_VAR_NAME      "DM_VERITY_ERR_BLOCK_NR"

#define DM_VERITY_DEFAULT_PREFETCH_SIZE 262144

#define DM_VERITY_MAX_CORRUPTED_ERRS    100

struct blks_info* b_info = 0;

int empty_b_info(void){
    return (b_info) ? 0 : 1;
}

struct blks_info * create_b_info(void){
    b_info = kzalloc(sizeof(struct blks_info),GFP_KERNEL);
    return b_info;
}

void free_b_info(void){
    if(empty_b_info())
        return;
    kfree(b_info);
}

/* get */
long long get_total_blks(void){
    if(!empty_b_info())
        return atomic64_read(&b_info->total_blks);
    return 0;
}

long long get_skipped_blks(void){
    if(!empty_b_info())
        return atomic64_read(&b_info->skipped_blks);
    return 0;
}

long long get_fec_correct_blks(void){
    if(!empty_b_info())
        return atomic64_read(&b_info->fec_correct_blks);
    return 0;
}

long long get_corrupted_blks(void){
    if(!empty_b_info())
        return atomic64_read(&b_info->corrupted_blks);
    return 0;
}

long long get_prev_total_blks(void){
    if(!empty_b_info())
        return atomic64_read(&b_info->prev_total_blks);
    return 0;
}
int get_fec_off_cnt(void){
    if(!empty_b_info())
        return atomic_read(&b_info->fec_off_cnt);
    return 0;
}

int get_dmv_ctr_cnt(void){
    if(!empty_b_info())
        return atomic_read(&b_info->dmv_ctr_cnt);
    return 0;
}

void add_dmv_ctr_entry(char* dev_name){
    int idx = get_dmv_ctr_cnt();

    if(!empty_b_info() && idx < MAX_DEV_LIST){
        snprintf(b_info->dmv_ctr_list[idx],MAX_DEV_NAME,"%s",dev_name);
        atomic_inc(&b_info->dmv_ctr_cnt);
    }
}

struct blks_info * get_b_info(char* dev_name){
    pr_err("dm-verity-debug : dev_name = %s\n",dev_name);

    if(empty_b_info()) {
        b_info = create_b_info();
        //add_dmv_ctr_entry(dev_name);
    }
    else{
        pr_info("dm-verity-debug : b_info already exists\n");
        //add_dmv_ctr_entry(dev_name);
        return b_info;
    }

    if(!b_info){
        pr_err("dm-verity-debug : Can't get b_info !\n");
        return 0;
    }

    pr_info("dm-verity-debug : get b_info successfully\n");
    return b_info;
}


/* set */
void set_prev_total_blks(long long val){
    if(!empty_b_info())
        atomic64_set(&b_info->prev_total_blks, val);
}
/* add */
void add_total_blks(long long val){
    if(!empty_b_info())
        atomic64_add(val, &b_info->total_blks);
}
void add_skipped_blks(void){
    if(!empty_b_info())
        atomic64_inc(&b_info->skipped_blks);
}
void add_fec_correct_blks(void){
    if(!empty_b_info())
        atomic64_inc(&b_info->fec_correct_blks);
}
void add_corrupted_blks(void){
    if(!empty_b_info())
        atomic64_inc(&b_info->corrupted_blks);
}
void add_fc_blks_entry(sector_t cur_blk, char* dev_name){
    if(empty_b_info()){
        pr_err("dm-verity-debug : b_info is empty !\n");
        return;
    }

    b_info->fc_blks_list[b_info->list_idx] = cur_blk;
    snprintf(b_info->dev_name[b_info->list_idx],MAX_DEV_NAME,"%s",dev_name);

    b_info->list_idx = (b_info->list_idx + 1) % MAX_FC_BLKS_LIST;
}
void add_fec_off_cnt(char* dev_name){
/*
    if(!empty_b_info()){
        int idx = get_fec_off_cnt();

        if(idx < MAX_DEV_LIST){
            snprintf(b_info->fec_off_list[idx],MAX_DEV_NAME,"%s",dev_name);
            atomic_inc(&b_info->fec_off_cnt);
        }
    }
*/
}

void print_blks_cnt(char* dev_name){
    if(empty_b_info()){
        return;
    }

    pr_err("dev_name = %s,total_blks = %llu,skipped_blks = %llu,corrupted_blks = %llu,fec_correct_blks = %llu",dev_name,get_total_blks(),get_skipped_blks(),get_corrupted_blks(),get_fec_correct_blks());
}

void print_fc_blks_list(void){
    int i = 0;

    if(empty_b_info()){
        return;
    }
    if(get_fec_correct_blks() == 0)
        return;

    pr_err("\n====== FC_BLKS_LIST START ======\n");

    if ((long long) MAX_FC_BLKS_LIST <= get_fec_correct_blks()){
        pr_err("%s %llu",b_info->dev_name[b_info->list_idx],(unsigned long long)b_info->fc_blks_list[b_info->list_idx]);
        i = (b_info->list_idx + 1) % MAX_FC_BLKS_LIST;
    }


    for( ; i != b_info->list_idx; i = (i + 1) % MAX_FC_BLKS_LIST)
        pr_err("%s %llu",b_info->dev_name[i],(unsigned long long)b_info->fc_blks_list[i]);

    pr_err("====== FC_BLKS_LIST END ======\n");
}

void print_dmv_ctr_list(void){
    int i = 0, ctr_cnt = get_dmv_ctr_cnt();

    if(empty_b_info()){
        return;
    }

    pr_err("\n====== DMV_CTR_LIST START ======\n");

    for( ; i < ctr_cnt; i++)
        pr_err("%s",b_info->dmv_ctr_list[i]);

    pr_err("====== DMV_CTR_LIST END ======\n");
}

static void print_block_data(unsigned long long blocknr, unsigned char *data_to_dump,
                            int start, int len)
{
    int i, j;
    int bh_offset = (start / 16) * 16;
    char row_data[17] = { 0, };
    char row_hex[50] = { 0, };
    char ch;

    if (blocknr == 0) {
        pr_err("printing Hash dump %dbyte, hash_to_dump 0x%p\n", len, (void *)data_to_dump);
    } else {
        pr_err("dm-verity corrupted, printing data in hex\n");
        pr_err(" dump block# : %llu, start offset(byte) : %d\n"
                , blocknr, start);
        pr_err(" length(byte) : %d, data_to_dump 0x%p\n"
                , len, (void *)data_to_dump);
        pr_err("-------------------------------------------------\n");
    }
    for (i = 0; i < (len + 15) / 16; i++) {
        for (j = 0; j < 16; j++) {
            ch = *(data_to_dump + bh_offset + j);
            if (start <= bh_offset + j
                    && start + len > bh_offset + j) {

                if (isascii(ch) && isprint(ch))
                    sprintf(row_data + j, "%c", ch);
                else
                    sprintf(row_data + j, ".");

                sprintf(row_hex + (j * 3), "%2.2x ", ch);
            } else {
                sprintf(row_data + j, " ");
                sprintf(row_hex + (j * 3), "-- ");
            }
        }

        pr_err("0x%4.4x : %s | %s\n"
                , bh_offset, row_hex, row_data);
        bh_offset += 16;
    }
    pr_err("---------------------------------------------------\n");
}

int verity_handle_err_hex_debug(struct dm_verity *v, enum verity_block_type type,
        unsigned long long block, struct dm_verity_io *io, struct bvec_iter *iter)
{
    char verity_env[DM_VERITY_ENV_LENGTH];
    char *envp[] = { verity_env, NULL };
    const char *type_str = "";
    struct dm_buffer *buf;
    struct mapped_device *md = dm_table_get_md(v->ti->table);
    struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_io_data_size);
    struct bio_vec bv;
    u8 *data;
    u8 *page;

    int i;
    char hex_str[65] = {0, };
    /* Corruption should be visible in device status in all modes */
    v->hash_failed = 1;

/* ignore_fs_panic is not ported.
   we may not need to ignore_fs_panic.
   verity_is_system_shutting_down is added.
 */
#if 0
    if (ignore_fs_panic) {
        DMERR("%s: Don't trigger a panic during cleanup for shutdown. Skipping %s",
                v->data_dev->name, __func__);
        return 0;
    }
#endif

    if (v->corrupted_errs >= DM_VERITY_MAX_CORRUPTED_ERRS)
        goto out;

    v->corrupted_errs++;

    switch (type) {
        case DM_VERITY_BLOCK_TYPE_DATA:
            type_str = "data";
            break;
        case DM_VERITY_BLOCK_TYPE_METADATA:
            type_str = "metadata";
            break;
        default:
            BUG();
    }

    if(empty_b_info()) {
        pr_err("dm-verity-debug : b_info is empty !\n");
    } else {
        print_dmv_ctr_list();
        print_blks_cnt(v->data_dev->name);
        print_fc_blks_list();
    }

    DMERR("%s: %s block %llu is corrupted", v->data_dev->name, type_str, block);

    for(i=0 ; i < v->salt_size; i++){
        sprintf(hex_str + (i * 2), "%02x", *(v->salt + i));
    }
    DMERR("dm-verity salt: %s", hex_str);

    if (!(strcmp(type_str, "metadata"))) {
        data = dm_bufio_read(v->bufio, block, &buf);
        print_block_data(0, (unsigned char *)(verity_io_real_digest(v, io)), 0, v->digest_size);
        print_block_data(0, (unsigned char *)(verity_io_want_digest(v, io)), 0, v->digest_size);
        print_block_data((unsigned long long)block, (unsigned char *)data, 0, PAGE_SIZE);
    } else if (!(strcmp(type_str, "data"))) {
        bv = bio_iter_iovec(bio, *iter);
        page = kmap_atomic(bv.bv_page);
        print_block_data(0, (unsigned char *)(verity_io_real_digest(v, io)), 0, v->digest_size);
        print_block_data(0, (unsigned char *)(verity_io_want_digest(v, io)), 0, v->digest_size);
        print_block_data((unsigned long long)block, (unsigned char *)page, 0, PAGE_SIZE);
        kunmap_atomic(page);
    } else {
        DMERR("%s: %s block : Unknown block type", v->data_dev->name, type_str);
    }

    panic("dmv corrupt");

    if (v->corrupted_errs == DM_VERITY_MAX_CORRUPTED_ERRS)
        DMERR("%s: reached maximum errors", v->data_dev->name);

    snprintf(verity_env, DM_VERITY_ENV_LENGTH, "%s=%d,%llu",
        DM_VERITY_ENV_VAR_NAME, type, block);

    kobject_uevent_env(&disk_to_dev(dm_disk(md))->kobj, KOBJ_CHANGE, envp);

out:
    if (v->mode == DM_VERITY_MODE_LOGGING)
        return 0;

    if (v->mode == DM_VERITY_MODE_RESTART) {
#ifdef CONFIG_DM_VERITY_AVB
        dm_verity_avb_error_handler();
#endif
        kernel_restart("dm-verity device corrupted");
    }

    return 1;
}
