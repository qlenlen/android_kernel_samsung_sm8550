/*
 * Copyright (c) 2021-2022 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/string.h>
#include "include/defex_debug.h"
#include "include/ptree.h"

/* Functions for "using" (i.e., loading and searching) p-tree in portable
 * variant.
 */

/* Big-endian uchar -> int */
static unsigned int charp2UInt(const unsigned char *p, int size)
{
	unsigned int i = *p;

	if (size > 1) {
		i = (i << 8) | p[1];
		if (size > 2) {
			i = (i << 8) | p[2];
			if (size > 3)
				i = (i << 8) | p[3];
		}
	}
	return i;
}

/* Checks magic number, loads important constants from prologue
 */
static int pptree_set_header(struct PPTree *tree)
{
	const unsigned char *pp = tree->data;

	/* Only PPTREE_MAGIC_FIXEDSIZE bytes are mandatory, remaining
	 * two can encode version information for compatibility
	 */
	if (strncmp((char *)pp, PPTREE_MAGIC, PPTREE_MAGIC_FIXEDSIZE)) {
		defex_log_warn("Ptree: Bad magic number");
		return -1;
	}
	pp += PPTREE_MAGIC_FIXEDSIZE + 2;
	tree->sTable.fullSize = charp2UInt(pp, UPPER_COUNT_SIZE);
	pp += UPPER_COUNT_SIZE;
	tree->sTable.size = charp2UInt(pp, UPPER_COUNT_SIZE);
	pp += UPPER_COUNT_SIZE;
	tree->sTable.indexSize = charp2UInt(pp++, 1);
	tree->sTable.table = pp;
	pp += tree->sTable.fullSize;

	tree->bTable.fullSize = charp2UInt(pp, UPPER_COUNT_SIZE);
	pp += UPPER_COUNT_SIZE;
	tree->bTable.size = charp2UInt(pp, UPPER_COUNT_SIZE);
	pp += UPPER_COUNT_SIZE;
	tree->bTable.indexSize = charp2UInt(pp++, 1);
	tree->bTable.table = pp;
	pp += tree->bTable.fullSize;

	tree->nodes.childCountSize = charp2UInt(pp++, 1);
	tree->nodes.offsetSize = charp2UInt(pp++, 1);
	tree->nodes.root = pp;
	return 0;
}

int pptree_set_data(struct PPTree *tree, const unsigned char *data)
{
	tree->data = data;
	tree->allocated = 0;
	return pptree_set_header(tree);
}

void pptree_free(struct PPTree *tree)
{
	if (tree->allocated && tree->data) {
		kfree((void *)tree->data);
		tree->data = 0;
		tree->allocated = 0;
	}
}

/* Gets a string (either a component of a search key or data associated
 * with an item) given index
 */
static const unsigned char *pptree_string(const struct PPTree *tree, int i)
{
	const unsigned char *sTable = tree->sTable.table;
	int index, bcs = tree->sTable.indexSize;

	if (i < 0 || i >= tree->sTable.size) {
		defex_log_warn("Ptree: bad string index: %d (max %d)", i, tree->sTable.size);
		return 0;
	}
	index = charp2UInt(sTable + i * bcs, bcs);
	return sTable + (1 + tree->sTable.size) * bcs + index;
}

/* Gets a bytearray given index */
static const unsigned char *pptree_bytearray(const struct PPTree *tree, int i,
					     int *length)
{
	const unsigned char *bTable = tree->bTable.table;
	int index, indexNext, bcs = tree->bTable.indexSize;

	if (i < 0 || i >= tree->bTable.size) {
		defex_log_warn("Ptree: Bad bytearray index: %d (max %d)", i, tree->bTable.size);
		if (length)
			*length = 0;
		return "";
	}
	index = charp2UInt(bTable + i * bcs, bcs);
	if (length) {
		indexNext = charp2UInt(bTable + (i + 1) * bcs, bcs);
		*length = indexNext - index;
	}
	return bTable + (1 + tree->bTable.size) * bcs + index;
}

/* Given a pointer to the start of a tree node, load important values
 * and advance pointer to the start of item index.
 */
static void load_node_prologue(const struct PPTree *tree,
			       const unsigned char **p,
			       unsigned int *itemSize,
			       unsigned int *dataTypes,
			       unsigned int *childCount)
{
	/* <dtTypes> is the |-ing of data masks of all items in this node,
	 * thus all possible data types associated to items.
	 * By extension, it determines <itSize>, which is the size in bytes
	 * of all items in this node.
	 */
	int dtTypes = charp2UInt((*p)++, 1),
		itSize = tree->sTable.indexSize + tree->nodes.offsetSize;
	if (dtTypes && itSize) {
		++itSize;
		if (dtTypes & PTREE_DATA_BYTES)
			itSize += tree->bTable.indexSize;
		if (dtTypes & PTREE_DATA_STRING)
			itSize += tree->sTable.indexSize;
		if (dtTypes & PTREE_DATA_INT1)
			itSize++;
		if (dtTypes & PTREE_DATA_INT2)
			itSize += 2;
		if (dtTypes & PTREE_DATA_INT4)
			itSize += 4;
		if (dtTypes & PTREE_DATA_PATH)
			itSize += tree->nodes.offsetSize;
	}
	if (childCount)
		*childCount = charp2UInt(*p, tree->nodes.childCountSize);
	*p += tree->nodes.childCountSize;
	if (dataTypes)
		*dataTypes = dtTypes;
	if (itemSize)
		*itemSize = itSize;
}

/* Calculate offset from root node. It depends on a previous search, if any */
static int pptree_get_offset(const struct PPTree *tree,
			     struct PPTreeContext *ctx)
{
	return ctx ?
		  /* Continue from the result of a previous search? */
		  (ctx->types & PTREE_FIND_CONTINUE) && ctx->last ?
		    ctx->last - tree->nodes.root :
		    /* Continue from subpath of a previous search, if any? */
		    ctx->types & PTREE_DATA_PATH ?
		      ctx->value.childPath :
		      0 :
		  0; /* No context, use root itself */
}

/* Load item-related data. <p> should be pointing to data type byte */
static const unsigned char *pptree_get_itemData(const struct PPTree *tree,
						const unsigned char *p,
						int dataTypes,
						struct PPTreeContext *ctx)
{
	memset(&ctx->value, 0, sizeof(ctx->value));
	ctx->types = (ctx->types & ~PTREE_DATA_MASK) | charp2UInt(p++, 1);
	if (dataTypes & PTREE_DATA_BYTES) {
		if (ctx->types & PTREE_DATA_BYTES)
			ctx->value.bytearray.bytes =
				pptree_bytearray(tree,
						 charp2UInt(p,
							    tree->bTable.indexSize),
						 &ctx->value.bytearray.length);
		p += tree->bTable.indexSize;
	}
	if (dataTypes & PTREE_DATA_STRING) {
		if (ctx->types & PTREE_DATA_STRING)
			ctx->value.string =
				(const char *)
				pptree_string(tree,
				       charp2UInt(p,
						  tree->sTable.indexSize));
		p += tree->sTable.indexSize;
	}
	if (dataTypes & PTREE_DATA_BITA)
		ctx->value.bits = (ctx->types & PTREE_DATA_BITA) &&
			(ctx->types & PTREE_DATA_BITA_MASK)
			? 1 : 0;
	if (dataTypes & PTREE_DATA_INT1) {
		if (ctx->types & PTREE_DATA_INT1)
			ctx->value.int1 = charp2UInt(p, 1);
		++p;
	}
	if (dataTypes & PTREE_DATA_INT2) {
		if (ctx->types & PTREE_DATA_INT2)
			ctx->value.int2 = charp2UInt(p, 2);
		p += 2;
	}
	if (dataTypes & PTREE_DATA_INT4) {
		if (ctx->types & PTREE_DATA_INT4)
			ctx->value.int4 = charp2UInt(p, 4);
		p += 4;
	}
	if (dataTypes & PTREE_DATA_PATH) {
		if (ctx->types & PTREE_DATA_PATH)
			ctx->value.childPath =
				charp2UInt(p, tree->nodes.offsetSize);
		p += tree->nodes.offsetSize;
	}
	return p;
}

int pptree_find(const struct PPTree *tree, const char **path, int pathLen,
		struct PPTreeContext *ctx)
{
	int depth;
	unsigned int dataTypes = 0;
	const unsigned char *pFound = 0,
		*p = tree->nodes.root + pptree_get_offset(tree, ctx);

	if (ctx->types & PTREE_FIND_PEEKED) {
		/* If a  previous call used PTREE_FIND_PEEK ignore <path>,
		 * only advance context's offset
		 */
		if (ctx->lastPeeked) {
			ctx->last = ctx->lastPeeked;
			ctx->lastPeeked = 0;
			return 1;
		}
		ctx->types &= ~(PTREE_FIND_PEEK | PTREE_FIND_PEEKED);
	}
	if (pathLen < 1)
		return 0;
	for (depth = 0; depth < pathLen; ++depth) {
		const char *s;
		int rCmp, sIndex, i;
		unsigned int itemSize, childCount;

		load_node_prologue(tree, &p, &itemSize, &dataTypes, &childCount);
		rCmp = -1;
		if (childCount < 5) { /* linear ordered search */
			for (i = 0; i < childCount; ++i) {
				sIndex = charp2UInt(p + i * itemSize,
						    tree->sTable.indexSize);
				rCmp = strncmp(path[depth],
					       (const char *)
					       pptree_string(tree, sIndex),
					       PTREE_FINDPATH_MAX);
				if (!rCmp)
					break;
				if (rCmp < 0)
					return 0;
			}
			if (i == childCount)
				return 0;
		} else { /* binary search */
			int l = 0, r = childCount - 1;

			while (l <= r) {
				i = l + (r - l) / 2;
				sIndex = charp2UInt(p + i * itemSize,
						    tree->sTable.indexSize);
				s = (const char *)pptree_string(tree, sIndex);
				rCmp = strncmp(path[depth], s,
					       PTREE_FINDPATH_MAX);
				if (rCmp < 0)
					r = i - 1;
				else
					if (rCmp)
						l = i + 1;
					else
						break;
			}
			if (rCmp)
				return 0;
		}
		pFound = p + i * itemSize + tree->sTable.indexSize;
		p = tree->nodes.root + charp2UInt(pFound,
						  tree->nodes.offsetSize);
	}
	if (ctx) {
		if (ctx->types & PTREE_FIND_PEEK)
			/* Don't advance context, just store it here */
			ctx->lastPeeked = p;
		else {
			ctx->last = p;
			ctx->lastPeeked = 0;
		}
		if (dataTypes)
			pptree_get_itemData(tree,
					    pFound + tree->nodes.offsetSize,
					    dataTypes, ctx);
		else
			/* Clear all bits for associated data */
			ctx->types &= ~PTREE_DATA_MASK;
	}
	return 1;
}

int pptree_find_path(const struct PPTree *tree, const char *path, char delim,
		     struct PPTreeContext *ctx)
{
	int i, itemCount, findRes, flags = ctx->types;
	char *ppath, *p, **pathItems;
	const char *q, *pathItems1[1];

	if (!path)
		return 0;
	/* Convenience: split <path> in components, invoke pptree_find */
	if (ctx->types & PTREE_FIND_PEEKED) {
		/* No path array to fill, just use last result */
		pathItems = 0;
		itemCount = 0;
	} else {
		if (!delim) {
			/* Special case, consider the whole string as
			 * a single component
			 */
			pathItems = (char **)pathItems1;
			pathItems1[0] = path;
			itemCount = 1;
		} else {
			ppath = kstrndup(path, PTREE_FINDPATH_MAX, GFP_KERNEL);
			if (!ppath)
				return 0;
			for (itemCount = *path ? 1 : 0, q = path; *q; ++q)
				if (*q == delim)
					++itemCount;
			pathItems = kmalloc((itemCount ? itemCount : 1) *
					    sizeof(const char *),
					    GFP_KERNEL);
			if (!pathItems) {
				kfree((void *)ppath);
				return 0;
			}
			*pathItems = ppath;
			for (i = 1, p = ppath; *p; ++p)
				if (*p == delim) {
					*p = 0;
					if (i < itemCount)
						pathItems[i++] = p + 1;
				}
		}
	}
	findRes = pptree_find(tree, (const char **)pathItems, itemCount, ctx);
	if (!(flags & PTREE_FIND_PEEKED) && delim) {
		kfree((void *) pathItems);
		kfree((void *) ppath);
	}
	return findRes;
}

int pptree_child_count(const struct PPTree *tree,
		      struct PPTreeContext *ctx)
{
	const unsigned char *p = tree->nodes.root +
		pptree_get_offset(tree, ctx);
	unsigned int childCount;

	load_node_prologue(tree, &p, 0, 0, &childCount);
	return childCount;
}

int pptree_iterate_children(const struct PPTree *tree,
			    struct PPTreeContext *ctx,
			    int (*f)(const struct PPTree *tree,
				     const char *name,
				     const struct PPTreeContext *itemData,
				     void *data),
			    void *data)
{
	const unsigned char *p;
	unsigned int i, childCount, itemSize, dataTypes, sIndex;
	int ret;

	if (!f)
		return 0;
	p = tree->nodes.root + pptree_get_offset(tree, ctx);
	load_node_prologue(tree, &p, &itemSize, &dataTypes, &childCount);
	for (ret = i = 0; i < childCount; ++i) {
		struct PPTreeContext itemData;

		sIndex = charp2UInt(p, tree->sTable.indexSize);
		if (dataTypes)
			pptree_get_itemData(tree,
					    p + tree->nodes.offsetSize +
					    tree->nodes.offsetSize,
					    dataTypes, &itemData);
		else
			itemData.types = 0;
		ret = (*f)(tree, (const char *)pptree_string(tree, sIndex),
			   &itemData, data);
		if (ret < 0)
			return ret;
		p += itemSize;
	}
	return ret;
}

/* Recursively traverses all children in subpath of a node given
 * by <tree>+<offset>, invoking <f> on all paths ending on a leaf.
 * Returns last result of <f>. Stops prematurely if <f> returns nonzero.
 */
static int pptree_iterate_subpaths(const struct PPTree *tree,
				   int offset, int pathDepth,
				   int (*f)(const struct PPTree *tree,
					    const char **path,
					    int pathLen, void *data),
				   const char **path, int maxDepth,
				   void *data)
{
	const unsigned char *p = tree->nodes.root + offset;
	unsigned int i, childCount, itemSize, dataTypes;

	load_node_prologue(tree, &p, &itemSize, &dataTypes, &childCount);
	for (i = 0; i < childCount; ++i) {
		const unsigned char *pp = p + i * itemSize;
		int sIndex, childIndex, j;

		sIndex = charp2UInt(pp, tree->sTable.indexSize);
		pp += tree->sTable.indexSize;
		childIndex = charp2UInt(pp, tree->nodes.offsetSize);
		pp += tree->nodes.offsetSize;
		path[pathDepth] = (const char *)pptree_string(tree, sIndex);
		if (childIndex) {
			if (pathDepth < maxDepth) {
				j = pptree_iterate_subpaths(tree, childIndex,
							    pathDepth + 1, f,
							    path, maxDepth,
							    data);
				if (j)
					return j;
			}
		} else
			if (f) {
				int j = (*f)(tree, path, pathDepth + 1, data);

				if (j)
					return j;
			}
	}
	return 0;
}

int pptree_iterate_paths(const struct PPTree *tree,
			 struct PPTreeContext *ctx,
			 int (*f)(const struct PPTree *tree,
				  const char **path,
				  int pathLen, void *data),
			 const char **path, int maxPathLen,
			 void *data)
{
	return pptree_iterate_subpaths(tree, pptree_get_offset(tree, ctx),
				       0, f, path, maxPathLen, data);
}

