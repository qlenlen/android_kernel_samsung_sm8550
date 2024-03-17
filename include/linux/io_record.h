#ifndef _LINUX_IO_RECORD_H
#define _LINUX_IO_RECORD_H

enum io_record_cmd_types {
	IO_RECORD_INIT = 1,
	IO_RECORD_START = 2,
	IO_RECORD_STOP = 3,
	IO_RECORD_POST_PROCESSING = 4,
	IO_RECORD_POST_PROCESSING_DONE = 5,
};

bool start_record(int pid);
bool stop_record(void);
bool post_processing_records(void);
bool init_record(void);
bool forced_init_record(void);

ssize_t read_record(char __user *buf, size_t count, loff_t *ppos);

void record_io_info(struct file *file, pgoff_t offset,
		    unsigned long req_size);

#endif /* _LINUX_IO_RECORD_H */
