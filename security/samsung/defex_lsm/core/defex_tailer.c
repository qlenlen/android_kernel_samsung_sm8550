/* Routines for handling archival-like files where each new contents is
 * appended and linked backwards - memory-only variants.
 */

#include <linux/string.h>
#include "include/defex_tailer.h"

/* Reads int from 4-byte big-endian */
static int be2int(const unsigned char *p)
{
	return (*p << 24) + (p[1] << 16) + (p[2] << 8) + p[3];
}

long defex_tailerp_has_suffix(const unsigned char *p, long size)
{
	return !p || size < TAIL_MAGIC_LEN + 8 + 1 + 2 ||
		memcmp(p + size - TAIL_MAGIC_LEN, TAIL_MAGIC, TAIL_MAGIC_LEN)
		? 0 : size - TAIL_MAGIC_LEN;
}

int defex_tailerp_iterate(const unsigned char *p, long size,
		    int (*task)(const char *title, int titleLen,
				const unsigned char *start, long size,
				void *data),
		    void *data)
{
	long start, offset = defex_tailerp_has_suffix(p, size);
	char buffer[TAIL_MAX_TITLE_LENGTH];

	if (!offset)
		return 0;
	for (offset -= 2; ; offset = start - 2) {
		int i, ttlLength;
		long size;

		/* Possibly change behavior depending on version
		 * (p[offset] and p[offset + 1])
		 */
		ttlLength = p[--offset];
		if (offset - 4 - 4 - ttlLength < 0)
			return -1;
		memcpy(buffer, p + (offset -= ttlLength), ttlLength);
		size = be2int(p + (offset -= 4));
		start = be2int(p + (offset -= 4));
		if (task) {
			i = (*task)(buffer, ttlLength,
				    p + start, size, data);
			if (i < 0)
				return i;
		}
		if (!start)
			break;
	}
	return 0;
}

/* Auxiliary data for finding an entry */
struct find_data {
	const char *title;
	int titleLen;
	int found;
	const unsigned char *start;
	long size;
};

static int tailerp_iteratefind(const char *title, int titleLen,
			       const unsigned char *start, long size,
			       void *data)
{
	struct find_data *fd = (struct find_data *)data;

	if (fd->titleLen == titleLen &&
	    !memcmp(title, fd->title, titleLen)) {
		fd->found = 1;
		fd->start = start;
		fd->size = size;
		return -1;
	}
	return 0;
}

const unsigned char *defex_tailerp_find(const unsigned char *p, long size,
				  const char *title, long *sizep)
{
	struct find_data fd;

	fd.title = title;
	fd.titleLen = strlen(title);
	fd.found = 0;
	if (!defex_tailerp_iterate(p, size, tailerp_iteratefind, &fd))
		return 0;
	if (fd.found) {
		if (sizep)
			*sizep = fd.size;
		return fd.start;
	}
	return 0;
}
