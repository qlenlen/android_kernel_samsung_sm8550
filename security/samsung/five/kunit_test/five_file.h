#ifndef __LINUX_FIVE_FILE_H
#define __LINUX_FIVE_FILE_H

struct file *test_open_file(const char *filename);
void test_close_file(struct file *file);

#endif // __LINUX_FIVE_FILE_H
