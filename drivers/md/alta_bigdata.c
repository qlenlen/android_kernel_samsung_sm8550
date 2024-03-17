#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/highmem.h>
#include <linux/kdev_t.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>

#include "dm-verity-debug.h"

#define ALTA_BUF_SIZE    4096

static DEFINE_SPINLOCK(alta_lock);

char* alta_buf;
size_t * alta_offset,alta_size;

struct kobject *kobj_ref;


void set_print_buf(char * buf, size_t * offset, size_t size)
{
    alta_buf = buf;
    alta_offset = offset;
    alta_size = size;

    *alta_offset = 0;
}


void alta_print(const char *fmt, ...)
{
    size_t offset = *alta_offset;

    va_list aptr;
    va_start(aptr, fmt);
    *alta_offset += vscnprintf(alta_buf+offset,(size_t)alta_size - offset, fmt, aptr);
    va_end(aptr);
}

static void show_fc_blks_list(void)
{
    int i = 0;

    if (empty_b_info()) {
        return;
    }

    if (get_fec_correct_blks() == 0) {
        alta_print("\n");
        return;
    }

    if ((long long) MAX_FC_BLKS_LIST <= get_fec_correct_blks()) {  
        alta_print(",\"fc_dev\":\"%s\"",b_info->dev_name[b_info->list_idx]);
        alta_print(",\"fc_blk\":\"%llu\"",b_info->fc_blks_list[b_info->list_idx]);
        i = (b_info->list_idx + 1) % MAX_FC_BLKS_LIST;
    }


    for ( ;i != b_info->list_idx; i = (i + 1) % MAX_FC_BLKS_LIST) {
        alta_print(",\"fc_dev\":\"%s\"",b_info->dev_name[i]);
        alta_print(",\"fc_blk\":\"%llu\"",b_info->fc_blks_list[i]);
    }
    alta_print("\n");
}

static void show_dmv_ctr_list(void){
    int i = 0, ctr_cnt = get_dmv_ctr_cnt();

    if (empty_b_info()) {
        return;
    }

    alta_print(",\"dmv_dev_cnt\":\"%d\"",ctr_cnt);

    for ( ;i < ctr_cnt; i++)
        alta_print(",\"dmv_dev\":\"%s\"",b_info->dmv_ctr_list[i]);
}

static void show_blks_cnt(void){
    int i,foc = get_fec_off_cnt();

    if (empty_b_info()) {
        return;
    }
    alta_print("\"total_blks\":\"%llu\"",get_total_blks());
    alta_print(",\"skipped_blks\":\"%llu\"",get_skipped_blks());
    alta_print(",\"corrupted_blks\":\"%llu\"",get_corrupted_blks());
    alta_print(",\"fec_correct_blks\":\"%llu\"",get_fec_correct_blks());

    if (foc > 0) {
        alta_print(",\"fec_off_cnt\":\"%d\"",foc);
        for(i = 0 ; i < foc; i++)
            alta_print(",\"fec_off_dev\":\"%s\"",b_info->fec_off_list[i]);
    }
}


ssize_t alta_bigdata_read(struct file *filep, char __user *buf, size_t size, loff_t *offset){
    ssize_t ret;
    size_t proc_offset = 0;
    char* proc_buf = kzalloc(ALTA_BUF_SIZE, GFP_KERNEL);

	if (!proc_buf)
		return -ENOMEM;

	spin_lock(&alta_lock);
    set_print_buf(proc_buf,&proc_offset,ALTA_BUF_SIZE);

    /* Print DMV info */
    if (empty_b_info()) {
        alta_print("\"ERROR\":\"b_info_empty\"\n");
    } else {
        show_blks_cnt();
        show_dmv_ctr_list();
        show_fc_blks_list();
    }
	spin_unlock(&alta_lock);

    ret = simple_read_from_buffer(buf, size, offset, proc_buf, proc_offset);
    kfree(proc_buf);

    return ret; 
}

static ssize_t sysfs_show(struct kobject *kobj, 
        struct kobj_attribute *attr, char *buf)
{
    size_t sysfs_offset;
    set_print_buf(buf, &sysfs_offset, PAGE_SIZE);

    /* Print DMV info */
    if (empty_b_info()) {
        alta_print("\"ERROR\":\"b_info_empty\"\n");
    } else {
        show_blks_cnt();
        show_dmv_ctr_list();
        show_fc_blks_list();
    }

    return sysfs_offset;
}


static const struct proc_ops alta_proc_ops = {
    .proc_read           = alta_bigdata_read,
};

struct kobj_attribute alta_attr = __ATTR(dmv_info, 0444, sysfs_show, NULL);

static int __init alta_bigdata_init(void){
    if (proc_create("alta_bigdata",0444,NULL,&alta_proc_ops) == NULL) {
        printk(KERN_ERR "alta_bigdata: Error creating proc entry");
        goto bad_proc;
    }

    /*Creating a directory in /sys/kernel/ */
    kobj_ref = kobject_create_and_add("alta_bigdata",kernel_kobj);

    /*Creating sysfs file for dmv_info*/
    if (sysfs_create_file(kobj_ref,&alta_attr.attr)) {
        printk(KERN_INFO"alta_bigdata: Cannot create sysfs file......\n");
        goto bad_sysfs;
    }

    pr_info("alta_bigdata : create /proc/alta_bigdata");
    return 0;

bad_sysfs:
    kobject_put(kobj_ref); 
    sysfs_remove_file(kernel_kobj, &alta_attr.attr);

bad_proc:
    free_b_info();
    remove_proc_entry("alta_bigdata", NULL);

    return -1;
}

static void __exit alta_bigdata_exit(void){
    kobject_put(kobj_ref); 
    sysfs_remove_file(kernel_kobj, &alta_attr.attr);

    free_b_info();
    remove_proc_entry("alta_bigdata", NULL);
}
module_init(alta_bigdata_init);
module_exit(alta_bigdata_exit);
