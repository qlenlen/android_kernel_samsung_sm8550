/*
 * Copyright (c) 2021-2022 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef __PTREE_H__

/* A "P-tree" is a n-ary search tree whose keys are strings. A p-tree
 * node may be associated with data like a string, a byte array or
 * an entry point for an additional search (unrelated to the node's
 * children).
 *
 * P-trees are represented in two variants:
 * - a "build" data structure with traditional structs and pointers, used for
 *   building, converting, merging or exporting
 * - a "portable" format packed with integer indices instead of pointers,
 *   stored as a byte array and used (read-only) by target applications.
 * In both, all strings are stored at a dictionary and represented in nodes
 * by indices, therefore child data have constant size; in addition, child
 * lists are sorted, allowing efficient search.
 */

/* Masks for data types. Should any be created, PTREE_DATA_MASK must
 * be updated accordingly
 */
#define PTREE_DATA_BYTES  1 /* byte array */
#define PTREE_DATA_STRING 2 /* zero-terminated string */
#define PTREE_DATA_PATH   4 /* subpath */
#define PTREE_DATA_INT1   8 /* byte */
#define PTREE_DATA_INT2  16 /* 2-byte short */
#define PTREE_DATA_INT4  32 /* 4-byte int */
#define PTREE_DATA_BITA  64 /* bit */
/* Bit A is stored directly in the bit below */
#define PTREE_DATA_BITA_MASK 128

#define PTREE_DATA_MASK 255 /* ORs all PTREE_DATA masks */

/* Modifiers for search behavior */
#define PTREE_FIND_CONTINUE 256 /* pptree_find should continue from
				 * previous result, if any
				 */
#define PTREE_FIND_PEEK 512 /* a successful search does not advance
			     * the context, therefore the next search
			     * will start from the same point
			     */
#define PTREE_FIND_PEEKED 1024 /* go to where a previous search would have
				* gone had it not used PTREE_FIND_PEEKED
				*/

/* ***************************************************************************
 * Declarations needed for _using_ exported P-trees
 * ***************************************************************************/

/* Header for portable P-tree. This is not the binary format, rather after
 * loading it caches the tree's details.
 */
struct PPTree {
	const unsigned char *data;
	struct {
		int fullSize;
		int size;
		char indexSize;
		const unsigned char *table;
	} sTable;
	struct {
		int fullSize;
		int size;
		char indexSize;
		const unsigned char *table;
	} bTable;
	struct {
		char offsetSize;
		char childCountSize;
		const unsigned char *root;
	} nodes;
	char allocated;
};

/* Magic number (fixed portion, plus two version bytes) */
#define PPTREE_MAGIC "PPTree-\1\0"
#define PPTREE_MAGIC_FIXEDSIZE 7

/* Sets a byte array as a p-tree's data. Returns 0 if successful. */
extern int pptree_set_data(struct PPTree *tree, const unsigned char *data);
/* Releases pptree data, if needed */
extern void pptree_free(struct PPTree *tree);

/* Context data for portable p-tree operations, especially searching.
 * Used for both input (key data) and output (result's place and data)
 * Search starts from root, or,
 * if .types is PPTREE_DATA_PATH and there's a subpath, from .value.childPath
 * if .types is PPTREE_FIND_CONTINUE, from latest sucessful search
 * If .types contains PTREE_DATA_PEEK, context does not advance even if
 * search is successful. It will advance (and no search will be done) if next
 * search include PTREE_DATA_PEEKED.
 */
struct PPTreeContext {
	int types;
	struct {
		struct {
			const unsigned char *bytes;
			int length;
		} bytearray;
		const char *string;
		int childPath;
		int int1;
		int int2;
		int int4;
		unsigned char bits;
	} value;
	const unsigned char *last, *lastPeeked;
	unsigned int childCount;
};
/* Search for given path. Return 0 if not found, 1 otherwise
 * (and fills in *ctx).
 * See PPTreeContext for where the search starts.
 */
extern int pptree_find(const struct PPTree *tree,
		       const char **path, int pathLen,
		       struct PPTreeContext *ctx);
/* Maximum key length, mostly an arbitrary limit against DoS */
#define PTREE_FINDPATH_MAX 8000
/* Search for a given path.
 * Similar to pptree_find, but splits <path> at every occurrence of <delim>
 * (unless delim is 0). In kernelspace, returns 0 if <path> length exceeds
 * PTREE_FINDPATH_MAX.
 */
extern int pptree_find_path(const struct PPTree *tree, const char *path,
			    char delim, struct PPTreeContext *ctx);
/* Returns number of children.
 * See PPTreeContext for which is the parent node.
 */
extern int pptree_child_count(const struct PPTree *tree,
			      struct PPTreeContext *ctx);
/* Iterates on immediate children.
 * See PPTreeContext for iteration root.
 * Executes <f> for all children until <f> returns nonzero. Returns
 * last return of <f>.
 */
extern int pptree_iterate_children(const struct PPTree *tree,
				   struct PPTreeContext *ctx,
				   int (*f)(const struct PPTree *tree,
					    const char *name,
					    const struct PPTreeContext *itemData,
					    void *data),
				   void *data);

/* Iterate on subpaths.
 * See PPTreeContext for iteration root.
 * Executes <f> for all subpaths ending on a leaf, stopping if <f>
 * returns nonzero.
 * Returns last result of <f>
 */
extern int pptree_iterate_paths(const struct PPTree *tree,
				 struct PPTreeContext *ctx,
				 int (*f)(const struct PPTree *tree,
					  const char **path,
					  int pathLen, void *data),
				 const char **path, int maxDepth,
				 void *data);
/* Dumps to stdout in human-readable format */
extern void pptree_dump(const struct PPTree *tree);

/* Maximum number of bytes for counters (practical reasonable limit) */
#define UPPER_COUNT_SIZE 4

#define __PTREE_H__
#endif
