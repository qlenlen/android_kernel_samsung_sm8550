#ifndef __INCLUDE_TAILER_H__
#define __INCLUDE_TAILER_H__

/* Functions for managing a "tailer file", which is similar to a tar
 * archive but, in order to support ordinary unadorned files
 * - stores metainformation after each archived file
 * - stores a single magic number at the very end.
 */

/* Magic number, occurs only once at the end of tailer file. Should it
 * change, be sure to update TAIL_MAGIC_LEN
 */
#define TAIL_MAGIC "#TAIL_GUARD#"
#define TAIL_MAGIC_LEN 12
/* Maximum length of title associated with a stored file. Arbitrary, but
 * should it increase, metainfo size (currently 1 byte) must change
 * accordingly
 */
#define TAIL_MAX_TITLE_LENGTH 255

/* Each file's metainfo entry comprises (version 1,0):
 * - offset where actual contents start: 4-byte big-endian
 * - size of contents in bytes: 4-byte big-endian
 * - title, up to TAIL_MAX_TITLE_LENGTH bytes, non 0-terminated
 * - title length, 1 byte
 * - major/minor version number, 1 byte each
 *
 * A tailer file is either an unadorned one or a linked list of content+
 * metainfo entries which goes backwards from the magic number.
 */

/* Functions for handling tailer data as memory buffers */

/* If a memory buffer <p> with <size> given ends with the tailer magic
 * suffix, returns its offset, else returns -1
 */
extern long defex_tailerp_has_suffix(const unsigned char *p, long size);
/* Given buffer <p> of <size> given, returns address of last occurrence
 * of contents of given <title> (and if <sizep> sets *<sizep> to
 * contents size), or 0 if <p> is unadorned has no such
 * occurrences
 */
extern const unsigned char *defex_tailerp_find(const unsigned char *p, long size,
					 const char *title, long *sizep);
/* Given buffer <p> with <size> bytes, returns 0 if unadorned. Else,
 * executes <task> for each entry, from last to first, passing arguments
 * <title> (unterminated), title length, absolute <start> address and
 * <size> in bytes, plus <data>. Terminates immediately if <task> returns
 * negative. Returns last result of <task>.
 */
extern int defex_tailerp_iterate(const unsigned char *p, long size,
			   int (*task)(const char *title, int titleLen,
				       const unsigned char *start,
				       long size, void *data),
			   void *data);

#endif
