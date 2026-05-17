#ifndef __LZ4DEFS_H__
#define __LZ4DEFS_H__

/*
 * lz4defs.h -- common and architecture specific defines for the kernel usage

 * LZ4 - Fast LZ compression algorithm
 * Copyright (C) 2011-2016, Yann Collet.
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *	* Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *	* Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * You can contact the author at :
 *	- LZ4 homepage : http://www.lz4.org
 *	- LZ4 source repository : https://github.com/lz4/lz4
 *
 *	Changed for kernel usage by:
 *	Sven Schmidt <4sschmid@informatik.uni-hamburg.de>
 */

#include <asm/unaligned.h>
#include <linux/string.h> /* memset, memcpy */

#define FORCE_INLINE __always_inline

/*-************************************
 *	Basic Types
 **************************************/
#include <linux/types.h>

typedef uint8_t BYTE;
typedef uint16_t U16;
typedef uint32_t U32;
typedef int32_t S32;
typedef uint64_t U64;
typedef uintptr_t uptrval;

/*-************************************
 *	Architecture specifics
 **************************************/
#if defined(CONFIG_64BIT)
#define LZ4_ARCH64 1
#else
#define LZ4_ARCH64 0
#endif

#if defined(__LITTLE_ENDIAN)
#define LZ4_LITTLE_ENDIAN 1
#else
#define LZ4_LITTLE_ENDIAN 0
#endif

#define DEBUGLOG(l, ...) \
	{                \
	} /* disabled */

#ifndef assert
#define assert(condition) ((void)0)
#endif

/*-************************************
 *	Constants
 **************************************/
#define LZ4_DISTANCE_ABSOLUTE_MAX 65535
#define LZ4_DISTANCE_MAX 65535
#define MINMATCH 4

#define WILDCOPYLENGTH 8
#define LASTLITERALS 5 /* see ../doc/lz4_Block_format.md#parsing-restrictions */
#define MFLIMIT 12 /* see ../doc/lz4_Block_format.md#parsing-restrictions */
#define MATCH_SAFEGUARD_DISTANCE \
	((2 * WILDCOPYLENGTH) -  \
	 MINMATCH) /* ensure it's possible to write 2 x wildcopyLength without overflowing output buffer */
#define FASTLOOP_SAFE_DISTANCE 64

#define HASH_UNIT sizeof(size_t)

#define KB (1 << 10)
#define MB (1 << 20)
#define GB (1U << 30)

#if defined(__x86_64__)
typedef U64 reg_t; /* 64-bits in x32 mode */
#else
typedef size_t reg_t; /* 32-bits in x32 mode */
#endif

#define STEPSIZE sizeof(size_t)

#define ML_BITS 4
#define ML_MASK ((1U << ML_BITS) - 1)
#define RUN_BITS (8 - ML_BITS)
#define RUN_MASK ((1U << RUN_BITS) - 1)

/*-************************************
 *	Reading and writing into memory
 **************************************/
static FORCE_INLINE U16 LZ4_read16(const void *ptr)
{
	return get_unaligned((const U16 *)ptr);
}

static FORCE_INLINE U32 LZ4_read32(const void *ptr)
{
	return get_unaligned((const U32 *)ptr);
}

static FORCE_INLINE size_t LZ4_read_ARCH(const void *ptr)
{
	return get_unaligned((const size_t *)ptr);
}

static FORCE_INLINE void LZ4_write16(void *memPtr, U16 value)
{
	put_unaligned(value, (U16 *)memPtr);
}

static FORCE_INLINE void LZ4_write32(void *memPtr, U32 value)
{
	put_unaligned(value, (U32 *)memPtr);
}

static FORCE_INLINE U16 LZ4_readLE16(const void *memPtr)
{
	return get_unaligned_le16(memPtr);
}

static FORCE_INLINE void LZ4_writeLE16(void *memPtr, U16 value)
{
	return put_unaligned_le16(value, memPtr);
}

/*
 * LZ4 relies on memcpy with a constant size being inlined. In freestanding
 * environments, the compiler can't assume the implementation of memcpy() is
 * standard compliant, so apply its specialized memcpy() inlining logic. When
 * possible, use __builtin_memcpy() to tell the compiler to analyze memcpy()
 * as-if it were standard compliant, so it can inline it in freestanding
 * environments. This is needed when decompressing the Linux Kernel, for example.
 */
#define LZ4_memcpy(dst, src, size) __builtin_memcpy(dst, src, size)
#define LZ4_memmove(dst, src, size) __builtin_memmove(dst, src, size)

/* customized variant of memcpy, which can overwrite up to 8 bytes beyond dstEnd */
static FORCE_INLINE void LZ4_wildCopy8(void *dstPtr, const void *srcPtr,
				       void *dstEnd)
{
	BYTE *d = (BYTE *)dstPtr;
	const BYTE *s = (const BYTE *)srcPtr;
	BYTE *const e = (BYTE *)dstEnd;

	do {
		LZ4_memcpy(d, s, 8);
		d += 8;
		s += 8;
	} while (d < e);
}

static FORCE_INLINE unsigned int LZ4_NbCommonBytes(reg_t val)
{
#if LZ4_LITTLE_ENDIAN
	return __ffs(val) >> 3;
#else
	return (BITS_PER_LONG - 1 - __fls(val)) >> 3;
#endif
}

static FORCE_INLINE unsigned int LZ4_count(const BYTE *pIn, const BYTE *pMatch,
					   const BYTE *pInLimit)
{
	const BYTE *const pStart = pIn;

	if (likely(pIn < pInLimit - (STEPSIZE - 1))) {
		reg_t const diff = LZ4_read_ARCH(pMatch) ^ LZ4_read_ARCH(pIn);
		if (!diff) {
			pIn += STEPSIZE;
			pMatch += STEPSIZE;
		} else {
			return LZ4_NbCommonBytes(diff);
		}
	}

	while (likely(pIn < pInLimit - (STEPSIZE - 1))) {
		reg_t const diff = LZ4_read_ARCH(pMatch) ^ LZ4_read_ARCH(pIn);
		if (!diff) {
			pIn += STEPSIZE;
			pMatch += STEPSIZE;
			continue;
		}
		pIn += LZ4_NbCommonBytes(diff);
		return (unsigned)(pIn - pStart);
	}

	if ((STEPSIZE == 8) && (pIn < (pInLimit - 3)) &&
	    (LZ4_read32(pMatch) == LZ4_read32(pIn))) {
		pIn += 4;
		pMatch += 4;
	}
	if ((pIn < (pInLimit - 1)) && (LZ4_read16(pMatch) == LZ4_read16(pIn))) {
		pIn += 2;
		pMatch += 2;
	}
	if ((pIn < pInLimit) && (*pMatch == *pIn))
		pIn++;
	return (unsigned)(pIn - pStart);
}

typedef enum {
	notLimited = 0,
	limitedOutput = 1,
	fillOutput = 2
} limitedOutput_directive;
typedef enum { clearedTable = 0, byPtr, byU32, byU16 } tableType_t;

typedef enum {
	noDict = 0,
	withPrefix64k,
	usingExtDict,
	usingDictCtx
} dict_directive;
typedef enum { noDictIssue = 0, dictSmall } dictIssue_directive;

typedef enum { endOnOutputSize = 0, endOnInputSize = 1 } endCondition_directive;
typedef enum { decode_full_block = 0, partial_decode = 1 } earlyEnd_directive;

#define LZ4_STATIC_ASSERT(c) BUILD_BUG_ON(!(c))

#endif
