#include <linux/fs.h>
#include <linux/shmem_fs.h>
#include <linux/buffer_head.h>

struct file *test_open_file(const char *filename)
{
	return shmem_kernel_file_setup(filename, 0, VM_NORESERVE);
}

void test_close_file(struct file *file)
{
	fput(file);
}
