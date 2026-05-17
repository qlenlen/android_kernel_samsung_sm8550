/*
 * LZ4 - Fast LZ compression algorithm
 * Copyright (C) 2011 - 2016, Yann Collet.
 * BSD 2 - Clause License (http://www.opensource.org/licenses/bsd - license.php)
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

/*-************************************
 *	Dependencies
 **************************************/
#include <linux/lz4.h>
#include "lz4defs.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unaligned.h>

static const int LZ4_minLength = (MFLIMIT + 1);
static const int LZ4_64Klimit = ((64 * KB) + (MFLIMIT - 1));
/* Increase this value ==> compression run slower on incompressible data */
static const U32 LZ4_skipTrigger = 6;

LZ4_stream_t *LZ4_initStream(void *buffer, size_t size);

/*-******************************
 *	Compression functions
 ********************************/
static FORCE_INLINE U32 LZ4_hash4(U32 sequence, tableType_t const tableType)
{
	if (tableType == byU16)
		return ((sequence * 2654435761U) >>
			((MINMATCH * 8) - (LZ4_HASHLOG + 1)));
	else
		return ((sequence * 2654435761U) >>
			((MINMATCH * 8) - LZ4_HASHLOG));
}

static FORCE_INLINE U32 LZ4_hash5(U64 sequence, tableType_t const tableType)
{
	const U32 hashLog = (tableType == byU16) ? LZ4_HASHLOG + 1 :
						   LZ4_HASHLOG;

#if LZ4_LITTLE_ENDIAN
	static const U64 prime5bytes = 889523592379ULL;

	return (U32)(((sequence << 24) * prime5bytes) >> (64 - hashLog));
#else
	static const U64 prime8bytes = 11400714785074694791ULL;

	return (U32)(((sequence >> 24) * prime8bytes) >> (64 - hashLog));
#endif
}

static FORCE_INLINE U32 LZ4_hashPosition(const void *p,
					 tableType_t const tableType)
{
#if LZ4_ARCH64
	if (tableType != byU16)
		return LZ4_hash5(LZ4_read_ARCH(p), tableType);
#endif

	return LZ4_hash4(LZ4_read32(p), tableType);
}

static FORCE_INLINE void LZ4_clearHash(U32 h, void *tableBase,
				       tableType_t const tableType)
{
	switch (tableType) {
	default: /* fallthrough */
	case clearedTable: { /* illegal! */
		assert(0);
		return;
	}
	case byPtr: {
		const BYTE **hashTable = (const BYTE **)tableBase;
		hashTable[h] = NULL;
		return;
	}
	case byU32: {
		U32 *hashTable = (U32 *)tableBase;
		hashTable[h] = 0;
		return;
	}
	case byU16: {
		U16 *hashTable = (U16 *)tableBase;
		hashTable[h] = 0;
		return;
	}
	}
}

static FORCE_INLINE void LZ4_putIndexOnHash(U32 idx, U32 h, void *tableBase,
					    tableType_t const tableType)
{
	switch (tableType) {
	default: /* fallthrough */
	case clearedTable: /* fallthrough */
	case byPtr: { /* illegal! */
		assert(0);
		return;
	}
	case byU32: {
		U32 *hashTable = (U32 *)tableBase;
		hashTable[h] = idx;
		return;
	}
	case byU16: {
		U16 *hashTable = (U16 *)tableBase;
		assert(idx < 65536);
		hashTable[h] = (U16)idx;
		return;
	}
	}
}

static void LZ4_putPositionOnHash(const BYTE *p, U32 h, void *tableBase,
				  tableType_t const tableType,
				  const BYTE *srcBase)
{
	switch (tableType) {
	case byPtr: {
		const BYTE **hashTable = (const BYTE **)tableBase;

		hashTable[h] = p;
		return;
	}
	case byU32: {
		U32 *hashTable = (U32 *)tableBase;

		hashTable[h] = (U32)(p - srcBase);
		return;
	}
	case byU16: {
		U16 *hashTable = (U16 *)tableBase;

		hashTable[h] = (U16)(p - srcBase);
		return;
	}
	case clearedTable: { /* fallthrough */
	}
	}
}

static FORCE_INLINE void LZ4_putPosition(const BYTE *p, void *tableBase,
					 tableType_t tableType,
					 const BYTE *srcBase)
{
	U32 const h = LZ4_hashPosition(p, tableType);

	LZ4_putPositionOnHash(p, h, tableBase, tableType, srcBase);
}

/* LZ4_getIndexOnHash() :
 * Index of match position registered in hash table.
 * hash position must be calculated by using base+index, or dictBase+index.
 * Assumption 1 : only valid if tableType == byU32 or byU16.
 * Assumption 2 : h is presumed valid (within limits of hash table)
 */
static FORCE_INLINE U32 LZ4_getIndexOnHash(U32 h, const void *tableBase,
					   tableType_t tableType)
{
	LZ4_STATIC_ASSERT(LZ4_MEMORY_USAGE > 2);
	if (tableType == byU32) {
		const U32 *const hashTable = (const U32 *)tableBase;
		assert(h < (1U << (LZ4_MEMORY_USAGE - 2)));
		return hashTable[h];
	}
	if (tableType == byU16) {
		const U16 *const hashTable = (const U16 *)tableBase;
		assert(h < (1U << (LZ4_MEMORY_USAGE - 1)));
		return hashTable[h];
	}
	assert(0);
	return 0; /* forbidden case */
}

static const BYTE *LZ4_getPositionOnHash(U32 h, void *tableBase,
					 tableType_t tableType,
					 const BYTE *srcBase)
{
	if (tableType == byPtr) {
		const BYTE **hashTable = (const BYTE **)tableBase;

		return hashTable[h];
	}

	if (tableType == byU32) {
		const U32 *const hashTable = (U32 *)tableBase;

		return hashTable[h] + srcBase;
	}

	{
		/* default, to ensure a return */
		const U16 *const hashTable = (U16 *)tableBase;

		return hashTable[h] + srcBase;
	}
}

static FORCE_INLINE const BYTE *LZ4_getPosition(const BYTE *p, void *tableBase,
						tableType_t tableType,
						const BYTE *srcBase)
{
	U32 const h = LZ4_hashPosition(p, tableType);

	return LZ4_getPositionOnHash(h, tableBase, tableType, srcBase);
}

static FORCE_INLINE void LZ4_prepareTable(LZ4_stream_t_internal *const cctx,
					  const int inputSize,
					  const tableType_t tableType)
{
	/* If the table hasn't been used, it's guaranteed to be zeroed out, and is
     * therefore safe to use no matter what mode we're in. Otherwise, we figure
     * out if it's safe to leave as is or whether it needs to be reset.
     */
	if ((tableType_t)cctx->tableType != clearedTable) {
		assert(inputSize >= 0);
		if ((tableType_t)cctx->tableType != tableType ||
		    ((tableType == byU16) &&
		     cctx->currentOffset + (unsigned)inputSize >= 0xFFFFU) ||
		    ((tableType == byU32) && cctx->currentOffset > 1 * GB) ||
		    tableType == byPtr || inputSize >= 4 * KB) {
			DEBUGLOG(4, "LZ4_prepareTable: Resetting table in %p",
				 cctx);
			memset(cctx->hashTable, 0, LZ4_HASHTABLESIZE);
			cctx->currentOffset = 0;
			cctx->tableType = (U32)clearedTable;
		} else {
			DEBUGLOG(
				4,
				"LZ4_prepareTable: Re-use hash table (no reset)");
		}
	}

	/* Adding a gap, so all previous entries are > LZ4_DISTANCE_MAX back,
     * is faster than compressing without a gap.
     * However, compressing with currentOffset == 0 is faster still,
     * so we preserve that case.
     */
	if (cctx->currentOffset != 0 && tableType == byU32) {
		DEBUGLOG(5, "LZ4_prepareTable: adding 64KB to currentOffset");
		cctx->currentOffset += 64 * KB;
	}

	/* Finally, clear history */
	cctx->dictCtx = NULL;
	cctx->dictionary = NULL;
	cctx->dictSize = 0;
}

/** LZ4_compress_generic() :
 *  inlined, to ensure branches are decided at compilation time.
 *  Presumed already validated at this stage:
 *  - source != NULL
 *  - inputSize > 0
 */
static FORCE_INLINE int LZ4_compress_generic_validated(
	LZ4_stream_t_internal *const cctx, const char *const source,
	char *const dest, const int inputSize,
	int *inputConsumed, /* only written when outputDirective == fillOutput */
	const int maxOutputSize, const limitedOutput_directive outputDirective,
	const tableType_t tableType, const dict_directive dictDirective,
	const dictIssue_directive dictIssue, const int acceleration)
{
	int result;
	const BYTE *ip = (const BYTE *)source;

	U32 const startIndex = cctx->currentOffset;
	const BYTE *base = (const BYTE *)source - startIndex;
	const BYTE *lowLimit;

	const LZ4_stream_t_internal *dictCtx =
		(const LZ4_stream_t_internal *)cctx->dictCtx;
	const BYTE *const dictionary = dictDirective == usingDictCtx ?
					       dictCtx->dictionary :
					       cctx->dictionary;
	const U32 dictSize = dictDirective == usingDictCtx ? dictCtx->dictSize :
							     cctx->dictSize;
	const U32 dictDelta =
		(dictDirective == usingDictCtx) ?
			startIndex - dictCtx->currentOffset :
			0; /* make indexes in dictCtx comparable with index in current context */

	int const maybe_extMem = (dictDirective == usingExtDict) ||
				 (dictDirective == usingDictCtx);
	U32 const prefixIdxLimit =
		startIndex -
		dictSize; /* used when dictDirective == dictSmall */
	const BYTE *const dictEnd = dictionary ? dictionary + dictSize :
						 dictionary;
	const BYTE *anchor = (const BYTE *)source;
	const BYTE *const iend = ip + inputSize;
	const BYTE *const mflimitPlusOne = iend - MFLIMIT + 1;
	const BYTE *const matchlimit = iend - LASTLITERALS;

	/* the dictCtx currentOffset is indexed on the start of the dictionary,
     * while a dictionary in the current context precedes the currentOffset */
	const BYTE *dictBase =
		(dictionary == NULL) ?
			NULL :
		(dictDirective == usingDictCtx) ?
			dictionary + dictSize - dictCtx->currentOffset :
			dictionary + dictSize - startIndex;

	BYTE *op = (BYTE *)dest;
	BYTE *const olimit = op + maxOutputSize;

	U32 offset = 0;
	U32 forwardH;

	DEBUGLOG(5, "LZ4_compress_generic_validated: srcSize=%i, tableType=%u",
		 inputSize, tableType);
	assert(ip != NULL);
	/* If init conditions are not met, we don't have to mark stream
     * as having dirty context, since no action was taken yet */
	if (outputDirective == fillOutput && maxOutputSize < 1) {
		return 0;
	} /* Impossible to store anything */
	if ((tableType == byU16) && (inputSize >= LZ4_64Klimit)) {
		return 0;
	} /* Size too large (not within 64K limit) */
	if (tableType == byPtr)
		assert(dictDirective ==
		       noDict); /* only supported use case with byPtr */
	assert(acceleration >= 1);

	lowLimit = (const BYTE *)source -
		   (dictDirective == withPrefix64k ? dictSize : 0);

	/* Update context state */
	if (dictDirective == usingDictCtx) {
		/* Subsequent linked blocks can't use the dictionary. */
		/* Instead, they use the block we just compressed. */
		cctx->dictCtx = NULL;
		cctx->dictSize = (U32)inputSize;
	} else {
		cctx->dictSize += (U32)inputSize;
	}
	cctx->currentOffset += (U32)inputSize;
	cctx->tableType = (U32)tableType;

	if (inputSize < LZ4_minLength)
		goto _last_literals; /* Input too small, no compression (all literals) */

	/* First Byte */
	LZ4_putPosition(ip, cctx->hashTable, tableType, base);
	ip++;
	forwardH = LZ4_hashPosition(ip, tableType);

	/* Main Loop */
	for (;;) {
		const BYTE *match;
		BYTE *token;
		const BYTE *filledIp;

		/* Find a match */
		if (tableType == byPtr) {
			const BYTE *forwardIp = ip;
			int step = 1;
			int searchMatchNb = acceleration << LZ4_skipTrigger;
			do {
				U32 const h = forwardH;
				ip = forwardIp;
				forwardIp += step;
				step = (searchMatchNb++ >> LZ4_skipTrigger);

				if (unlikely(forwardIp > mflimitPlusOne))
					goto _last_literals;
				assert(ip < mflimitPlusOne);

				match = LZ4_getPositionOnHash(
					h, cctx->hashTable, tableType, base);
				forwardH =
					LZ4_hashPosition(forwardIp, tableType);
				LZ4_putPositionOnHash(ip, h, cctx->hashTable,
						      tableType, base);

			} while ((match + LZ4_DISTANCE_MAX < ip) ||
				 (LZ4_read32(match) != LZ4_read32(ip)));

		} else { /* byU32, byU16 */

			const BYTE *forwardIp = ip;
			int step = 1;
			int searchMatchNb = acceleration << LZ4_skipTrigger;
			do {
				U32 const h = forwardH;
				U32 const cur = (U32)(forwardIp - base);
				U32 matchIndex = LZ4_getIndexOnHash(
					h, cctx->hashTable, tableType);
				assert(matchIndex <= cur);
				assert(forwardIp - base <
				       (ptrdiff_t)(2 * GB - 1));
				ip = forwardIp;
				forwardIp += step;
				step = (searchMatchNb++ >> LZ4_skipTrigger);

				if (unlikely(forwardIp > mflimitPlusOne))
					goto _last_literals;
				assert(ip < mflimitPlusOne);

				if (dictDirective == usingDictCtx) {
					if (matchIndex < startIndex) {
						/* there was no match, try the dictionary */
						assert(tableType == byU32);
						matchIndex = LZ4_getIndexOnHash(
							h, dictCtx->hashTable,
							byU32);
						match = dictBase + matchIndex;
						matchIndex +=
							dictDelta; /* make dictCtx index comparable with current context */
						lowLimit = dictionary;
					} else {
						match = base + matchIndex;
						lowLimit = (const BYTE *)source;
					}
				} else if (dictDirective == usingExtDict) {
					if (matchIndex < startIndex) {
						DEBUGLOG(
							7,
							"extDict candidate: matchIndex=%5u  <  startIndex=%5u",
							matchIndex, startIndex);
						assert(startIndex -
							       matchIndex >=
						       MINMATCH);
						assert(dictBase);
						match = dictBase + matchIndex;
						lowLimit = dictionary;
					} else {
						match = base + matchIndex;
						lowLimit = (const BYTE *)source;
					}
				} else { /* single continuous memory segment */
					match = base + matchIndex;
				}
				forwardH =
					LZ4_hashPosition(forwardIp, tableType);
				LZ4_putIndexOnHash(cur, h, cctx->hashTable,
						   tableType);

				DEBUGLOG(7,
					 "candidate at pos=%u  (offset=%u \n",
					 matchIndex, cur - matchIndex);
				if ((dictIssue == dictSmall) &&
				    (matchIndex < prefixIdxLimit)) {
					continue;
				} /* match outside of valid area */
				assert(matchIndex < cur);
				if (((tableType != byU16) ||
				     (LZ4_DISTANCE_MAX <
				      LZ4_DISTANCE_ABSOLUTE_MAX)) &&
				    (matchIndex + LZ4_DISTANCE_MAX < cur)) {
					continue;
				} /* too far */
				assert((cur - matchIndex) <=
				       LZ4_DISTANCE_MAX); /* match now expected within distance */

				if (LZ4_read32(match) == LZ4_read32(ip)) {
					if (maybe_extMem)
						offset = cur - matchIndex;
					break; /* match found */
				}

			} while (1);
		}

		/* Catch up */
		filledIp = ip;
		while (((ip > anchor) & (match > lowLimit)) &&
		       (unlikely(ip[-1] == match[-1]))) {
			ip--;
			match--;
		}

		/* Encode Literals */
		{
			unsigned const litLength = (unsigned)(ip - anchor);
			token = op++;
			if ((outputDirective ==
			     limitedOutput) && /* Check output buffer overflow */
			    (unlikely(op + litLength + (2 + 1 + LASTLITERALS) +
					      (litLength / 255) >
				      olimit))) {
				return 0; /* cannot compress within `dst` budget. Stored indexes in hash table are nonetheless fine */
			}
			if ((outputDirective == fillOutput) &&
			    (unlikely(
				    op + (litLength + 240) / 255 /* litlen */ +
					    litLength /* literals */ +
					    2 /* offset */ + 1 /* token */ +
					    MFLIMIT -
					    MINMATCH /* min last literals so last match is <= end - MFLIMIT */
				    > olimit))) {
				op--;
				goto _last_literals;
			}
			if (litLength >= RUN_MASK) {
				int len = (int)(litLength - RUN_MASK);
				*token = (RUN_MASK << ML_BITS);
				for (; len >= 255; len -= 255)
					*op++ = 255;
				*op++ = (BYTE)len;
			} else
				*token = (BYTE)(litLength << ML_BITS);

			/* Copy Literals */
			LZ4_wildCopy8(op, anchor, op + litLength);
			op += litLength;
			DEBUGLOG(6, "seq.start:%i, literals=%u, match.start:%i",
				 (int)(anchor - (const BYTE *)source),
				 litLength, (int)(ip - (const BYTE *)source));
		}

_next_match:
		/* at this stage, the following variables must be correctly set :
         * - ip : at start of LZ operation
         * - match : at start of previous pattern occurrence; can be within current prefix, or within extDict
         * - offset : if maybe_ext_memSegment==1 (constant)
         * - lowLimit : must be == dictionary to mean "match is within extDict"; must be == source otherwise
         * - token and *token : position to write 4-bits for match length; higher 4-bits for literal length supposed already written
         */

		if ((outputDirective == fillOutput) &&
		    (op + 2 /* offset */ + 1 /* token */ + MFLIMIT -
			     MINMATCH /* min last literals so last match is <= end - MFLIMIT */
		     > olimit)) {
			/* the match was too close to the end, rewind and go to last literals */
			op = token;
			goto _last_literals;
		}

		/* Encode Offset */
		if (maybe_extMem) { /* static test */
			DEBUGLOG(6,
				 "             with offset=%u  (ext if > %i)",
				 offset, (int)(ip - (const BYTE *)source));
			assert(offset <= LZ4_DISTANCE_MAX && offset > 0);
			LZ4_writeLE16(op, (U16)offset);
			op += 2;
		} else {
			DEBUGLOG(6,
				 "             with offset=%u  (same segment)",
				 (U32)(ip - match));
			assert(ip - match <= LZ4_DISTANCE_MAX);
			LZ4_writeLE16(op, (U16)(ip - match));
			op += 2;
		}

		/* Encode MatchLength */
		{
			unsigned matchCode;

			if ((dictDirective == usingExtDict ||
			     dictDirective == usingDictCtx) &&
			    (lowLimit ==
			     dictionary) /* match within extDict */) {
				const BYTE *limit = ip + (dictEnd - match);
				assert(dictEnd > match);
				if (limit > matchlimit)
					limit = matchlimit;
				matchCode = LZ4_count(ip + MINMATCH,
						      match + MINMATCH, limit);
				ip += (size_t)matchCode + MINMATCH;
				if (ip == limit) {
					unsigned const more = LZ4_count(
						limit, (const BYTE *)source,
						matchlimit);
					matchCode += more;
					ip += more;
				}
				DEBUGLOG(
					6,
					"             with matchLength=%u starting in extDict",
					matchCode + MINMATCH);
			} else {
				matchCode = LZ4_count(ip + MINMATCH,
						      match + MINMATCH,
						      matchlimit);
				ip += (size_t)matchCode + MINMATCH;
				DEBUGLOG(6, "             with matchLength=%u",
					 matchCode + MINMATCH);
			}

			if ((outputDirective) && /* Check output buffer overflow */
			    (unlikely(op + (1 + LASTLITERALS) +
					      (matchCode + 240) / 255 >
				      olimit))) {
				if (outputDirective == fillOutput) {
					/* Match description too long : reduce it */
					U32 newMatchCode =
						15 /* in token */ -
						1 /* to avoid needing a zero byte */ +
						((U32)(olimit - op) - 1 -
						 LASTLITERALS) *
							255;
					ip -= matchCode - newMatchCode;
					assert(newMatchCode < matchCode);
					matchCode = newMatchCode;
					if (unlikely(ip <= filledIp)) {
						/* We have already filled up to filledIp so if ip ends up less than filledIp
                         * we have positions in the hash table beyond the current position. This is
                         * a problem if we reuse the hash table. So we have to remove these positions
                         * from the hash table.
                         */
						const BYTE *ptr;
						DEBUGLOG(
							5,
							"Clearing %u positions",
							(U32)(filledIp - ip));
						for (ptr = ip; ptr <= filledIp;
						     ++ptr) {
							U32 const h =
								LZ4_hashPosition(
									ptr,
									tableType);
							LZ4_clearHash(
								h,
								cctx->hashTable,
								tableType);
						}
					}
				} else {
					assert(outputDirective ==
					       limitedOutput);
					return 0; /* cannot compress within `dst` budget. Stored indexes in hash table are nonetheless fine */
				}
			}
			if (matchCode >= ML_MASK) {
				*token += ML_MASK;
				matchCode -= ML_MASK;
				LZ4_write32(op, 0xFFFFFFFF);
				while (matchCode >= 4 * 255) {
					op += 4;
					LZ4_write32(op, 0xFFFFFFFF);
					matchCode -= 4 * 255;
				}
				op += matchCode / 255;
				*op++ = (BYTE)(matchCode % 255);
			} else
				*token += (BYTE)(matchCode);
		}
		/* Ensure we have enough space for the last literals. */
		assert(!(outputDirective == fillOutput &&
			 op + 1 + LASTLITERALS > olimit));

		anchor = ip;

		/* Test end of chunk */
		if (ip >= mflimitPlusOne)
			break;

		/* Fill table */
		LZ4_putPosition(ip - 2, cctx->hashTable, tableType, base);

		/* Test next position */
		if (tableType == byPtr) {
			match = LZ4_getPosition(ip, cctx->hashTable, tableType,
						base);
			LZ4_putPosition(ip, cctx->hashTable, tableType, base);
			if ((match + LZ4_DISTANCE_MAX >= ip) &&
			    (LZ4_read32(match) == LZ4_read32(ip))) {
				token = op++;
				*token = 0;
				goto _next_match;
			}

		} else { /* byU32, byU16 */

			U32 const h = LZ4_hashPosition(ip, tableType);
			U32 const cur = (U32)(ip - base);
			U32 matchIndex = LZ4_getIndexOnHash(h, cctx->hashTable,
							    tableType);
			assert(matchIndex < cur);
			if (dictDirective == usingDictCtx) {
				if (matchIndex < startIndex) {
					/* there was no match, try the dictionary */
					matchIndex = LZ4_getIndexOnHash(
						h, dictCtx->hashTable, byU32);
					match = dictBase + matchIndex;
					lowLimit =
						dictionary; /* required for match length counter */
					matchIndex += dictDelta;
				} else {
					match = base + matchIndex;
					lowLimit = (const BYTE *)
						source; /* required for match length counter */
				}
			} else if (dictDirective == usingExtDict) {
				if (matchIndex < startIndex) {
					assert(dictBase);
					match = dictBase + matchIndex;
					lowLimit =
						dictionary; /* required for match length counter */
				} else {
					match = base + matchIndex;
					lowLimit = (const BYTE *)
						source; /* required for match length counter */
				}
			} else { /* single memory segment */
				match = base + matchIndex;
			}
			LZ4_putIndexOnHash(cur, h, cctx->hashTable, tableType);
			assert(matchIndex < cur);
			if (((dictIssue == dictSmall) ?
				     (matchIndex >= prefixIdxLimit) :
				     1) &&
			    (((tableType == byU16) &&
			      (LZ4_DISTANCE_MAX == LZ4_DISTANCE_ABSOLUTE_MAX)) ?
				     1 :
				     (matchIndex + LZ4_DISTANCE_MAX >= cur)) &&
			    (LZ4_read32(match) == LZ4_read32(ip))) {
				token = op++;
				*token = 0;
				if (maybe_extMem)
					offset = cur - matchIndex;
				DEBUGLOG(
					6,
					"seq.start:%i, literals=%u, match.start:%i",
					(int)(anchor - (const BYTE *)source), 0,
					(int)(ip - (const BYTE *)source));
				goto _next_match;
			}
		}

		/* Prepare next loop */
		forwardH = LZ4_hashPosition(++ip, tableType);
	}

_last_literals:
	/* Encode Last Literals */
	{
		size_t lastRun = (size_t)(iend - anchor);
		if ((outputDirective) && /* Check output buffer overflow */
		    (op + lastRun + 1 + ((lastRun + 255 - RUN_MASK) / 255) >
		     olimit)) {
			if (outputDirective == fillOutput) {
				/* adapt lastRun to fill 'dst' */
				assert(olimit >= op);
				lastRun = (size_t)(olimit - op) - 1 /*token*/;
				lastRun -= (lastRun + 256 - RUN_MASK) /
					   256; /*additional length tokens*/
			} else {
				assert(outputDirective == limitedOutput);
				return 0; /* cannot compress within `dst` budget. Stored indexes in hash table are nonetheless fine */
			}
		}
		DEBUGLOG(6, "Final literal run : %i literals", (int)lastRun);
		if (lastRun >= RUN_MASK) {
			size_t accumulator = lastRun - RUN_MASK;
			*op++ = RUN_MASK << ML_BITS;
			for (; accumulator >= 255; accumulator -= 255)
				*op++ = 255;
			*op++ = (BYTE)accumulator;
		} else {
			*op++ = (BYTE)(lastRun << ML_BITS);
		}
		LZ4_memcpy(op, anchor, lastRun);
		ip = anchor + lastRun;
		op += lastRun;
	}

	if (outputDirective == fillOutput) {
		*inputConsumed = (int)(((const char *)ip) - source);
	}
	result = (int)(((char *)op) - dest);
	assert(result > 0);
	DEBUGLOG(5, "LZ4_compress_generic: compressed %i bytes into %i bytes",
		 inputSize, result);
	return result;
}

/** LZ4_compress_generic() :
 *  inlined, to ensure branches are decided at compilation time;
 *  takes care of src == (NULL, 0)
 *  and forward the rest to LZ4_compress_generic_validated */
static FORCE_INLINE int LZ4_compress_generic(
	LZ4_stream_t_internal *const cctx, const char *const src,
	char *const dst, const int srcSize,
	int *inputConsumed, /* only written when outputDirective == fillOutput */
	const int dstCapacity, const limitedOutput_directive outputDirective,
	const tableType_t tableType, const dict_directive dictDirective,
	const dictIssue_directive dictIssue, const int acceleration)
{
	DEBUGLOG(5, "LZ4_compress_generic: srcSize=%i, dstCapacity=%i", srcSize,
		 dstCapacity);

	if ((U32)srcSize > (U32)LZ4_MAX_INPUT_SIZE) {
		return 0;
	} /* Unsupported srcSize, too large (or negative) */
	if (srcSize == 0) { /* src == NULL supported if srcSize == 0 */
		if (outputDirective != notLimited && dstCapacity <= 0)
			return 0; /* no output, can't write anything */
		DEBUGLOG(5, "Generating an empty block");
		assert(outputDirective == notLimited || dstCapacity >= 1);
		assert(dst != NULL);
		dst[0] = 0;
		if (outputDirective == fillOutput) {
			assert(inputConsumed != NULL);
			*inputConsumed = 0;
		}
		return 1;
	}
	assert(src != NULL);

	return LZ4_compress_generic_validated(
		cctx, src, dst, srcSize,
		inputConsumed, /* only written into if outputDirective == fillOutput */
		dstCapacity, outputDirective, tableType, dictDirective,
		dictIssue, acceleration);
}

int LZ4_compress_fast_extState(void *state, const char *source, char *dest,
			       int inputSize, int maxOutputSize,
			       int acceleration)
{
	LZ4_stream_t_internal *const ctx =
		&LZ4_initStream(state, sizeof(LZ4_stream_t))->internal_donotuse;
	assert(ctx != NULL);
	if (acceleration < 1)
		acceleration = LZ4_ACCELERATION_DEFAULT;
	if (acceleration > LZ4_ACCELERATION_MAX)
		acceleration = LZ4_ACCELERATION_MAX;
	if (maxOutputSize >= LZ4_compressBound(inputSize)) {
		if (inputSize < LZ4_64Klimit) {
			return LZ4_compress_generic(ctx, source, dest,
						    inputSize, NULL, 0,
						    notLimited, byU16, noDict,
						    noDictIssue, acceleration);
		} else {
			const tableType_t tableType =
				((sizeof(void *) == 4) &&
				 ((uptrval)source > LZ4_DISTANCE_MAX)) ?
					byPtr :
					byU32;
			return LZ4_compress_generic(ctx, source, dest,
						    inputSize, NULL, 0,
						    notLimited, tableType,
						    noDict, noDictIssue,
						    acceleration);
		}
	} else {
		if (inputSize < LZ4_64Klimit) {
			return LZ4_compress_generic(
				ctx, source, dest, inputSize, NULL,
				maxOutputSize, limitedOutput, byU16, noDict,
				noDictIssue, acceleration);
		} else {
			const tableType_t tableType =
				((sizeof(void *) == 4) &&
				 ((uptrval)source > LZ4_DISTANCE_MAX)) ?
					byPtr :
					byU32;
			return LZ4_compress_generic(
				ctx, source, dest, inputSize, NULL,
				maxOutputSize, limitedOutput, tableType, noDict,
				noDictIssue, acceleration);
		}
	}
}

int LZ4_compress_fast(const char *source, char *dest, int inputSize,
		      int maxOutputSize, int acceleration, void *wrkmem)
{
	return LZ4_compress_fast_extState(wrkmem, source, dest, inputSize,
					  maxOutputSize, acceleration);
}
EXPORT_SYMBOL(LZ4_compress_fast);

int LZ4_compress_default(const char *source, char *dest, int inputSize,
			 int maxOutputSize, void *wrkmem)
{
	return LZ4_compress_fast(source, dest, inputSize, maxOutputSize,
				 LZ4_ACCELERATION_DEFAULT, wrkmem);
}
EXPORT_SYMBOL(LZ4_compress_default);

static int LZ4_compress_destSize_extState(LZ4_stream_t *state, const char *src,
					  char *dst, int *srcSizePtr,
					  int targetDstSize)
{
	void *const s = LZ4_initStream(state, sizeof(*state));
	assert(s != NULL);
	(void)s;

	if (targetDstSize >=
	    LZ4_compressBound(
		    *srcSizePtr)) { /* compression success is guaranteed */
		return LZ4_compress_fast_extState(state, src, dst, *srcSizePtr,
						  targetDstSize, 1);
	} else {
		if (*srcSizePtr < LZ4_64Klimit) {
			return LZ4_compress_generic(&state->internal_donotuse,
						    src, dst, *srcSizePtr,
						    srcSizePtr, targetDstSize,
						    fillOutput, byU16, noDict,
						    noDictIssue, 1);
		} else {
			tableType_t const addrMode =
				((sizeof(void *) == 4) &&
				 ((uptrval)src > LZ4_DISTANCE_MAX)) ?
					byPtr :
					byU32;
			return LZ4_compress_generic(&state->internal_donotuse,
						    src, dst, *srcSizePtr,
						    srcSizePtr, targetDstSize,
						    fillOutput, addrMode,
						    noDict, noDictIssue, 1);
		}
	}
}

int LZ4_compress_destSize(const char *src, char *dst, int *srcSizePtr,
			  int targetDstSize, void *wrkmem)
{
	return LZ4_compress_destSize_extState(wrkmem, src, dst, srcSizePtr,
					      targetDstSize);
}
EXPORT_SYMBOL(LZ4_compress_destSize);

/*-******************************
 *	Streaming functions
 ********************************/
static size_t LZ4_stream_t_alignment(void)
{
	typedef struct {
		char c;
		LZ4_stream_t t;
	} t_a;
	return sizeof(t_a) - sizeof(LZ4_stream_t);
}

static int LZ4_isAligned(const void *ptr, size_t alignment)
{
	return ((size_t)ptr & (alignment - 1)) == 0;
}

LZ4_stream_t *LZ4_initStream(void *buffer, size_t size)
{
	DEBUGLOG(5, "LZ4_initStream");
	if (buffer == NULL) {
		return NULL;
	}
	if (size < sizeof(LZ4_stream_t)) {
		return NULL;
	}
	if (!LZ4_isAligned(buffer, LZ4_stream_t_alignment()))
		return NULL;
	memset(buffer, 0, sizeof(LZ4_stream_t_internal));
	return (LZ4_stream_t *)buffer;
}

void LZ4_resetStream(LZ4_stream_t *LZ4_stream)
{
	memset(LZ4_stream, 0, sizeof(LZ4_stream_t_internal));
}

int LZ4_loadDict(LZ4_stream_t *LZ4_dict, const char *dictionary, int dictSize)
{
	LZ4_stream_t_internal *dict = &LZ4_dict->internal_donotuse;
	const tableType_t tableType = byU32;
	const BYTE *p = (const BYTE *)dictionary;
	const BYTE *const dictEnd = p + dictSize;
	const BYTE *base;

	DEBUGLOG(4, "LZ4_loadDict (%i bytes from %p into %p)", dictSize,
		 dictionary, LZ4_dict);

	/* It's necessary to reset the context,
     * and not just continue it with prepareTable()
     * to avoid any risk of generating overflowing matchIndex
     * when compressing using this dictionary */
	LZ4_resetStream(LZ4_dict);

	/* We always increment the offset by 64 KB, since, if the dict is longer,
     * we truncate it to the last 64k, and if it's shorter, we still want to
     * advance by a whole window length so we can provide the guarantee that
     * there are only valid offsets in the window, which allows an optimization
     * in LZ4_compress_fast_continue() where it uses noDictIssue even when the
     * dictionary isn't a full 64k. */
	dict->currentOffset += 64 * KB;

	if (dictSize < (int)HASH_UNIT) {
		return 0;
	}

	if ((dictEnd - p) > 64 * KB)
		p = dictEnd - 64 * KB;
	base = dictEnd - dict->currentOffset;
	dict->dictionary = p;
	dict->dictSize = (U32)(dictEnd - p);
	dict->tableType = (U32)tableType;

	while (p <= dictEnd - HASH_UNIT) {
		LZ4_putPosition(p, dict->hashTable, tableType, base);
		p += 3;
	}

	return (int)dict->dictSize;
}
EXPORT_SYMBOL(LZ4_loadDict);

static void LZ4_renormDictT(LZ4_stream_t_internal *LZ4_dict, int nextSize)
{
	assert(nextSize >= 0);
	if (LZ4_dict->currentOffset + (unsigned)nextSize >
	    0x80000000) { /* potential ptrdiff_t overflow (32-bits mode) */
		/* rescale hash table */
		U32 const delta = LZ4_dict->currentOffset - 64 * KB;
		const BYTE *dictEnd = LZ4_dict->dictionary + LZ4_dict->dictSize;
		int i;
		DEBUGLOG(4, "LZ4_renormDictT");
		for (i = 0; i < LZ4_HASH_SIZE_U32; i++) {
			if (LZ4_dict->hashTable[i] < delta)
				LZ4_dict->hashTable[i] = 0;
			else
				LZ4_dict->hashTable[i] -= delta;
		}
		LZ4_dict->currentOffset = 64 * KB;
		if (LZ4_dict->dictSize > 64 * KB)
			LZ4_dict->dictSize = 64 * KB;
		LZ4_dict->dictionary = dictEnd - LZ4_dict->dictSize;
	}
}

int LZ4_saveDict(LZ4_stream_t *LZ4_dict, char *safeBuffer, int dictSize)
{
	LZ4_stream_t_internal *const dict = &LZ4_dict->internal_donotuse;

	DEBUGLOG(5, "LZ4_saveDict : dictSize=%i, safeBuffer=%p", dictSize,
		 safeBuffer);

	if ((U32)dictSize > 64 * KB) {
		dictSize = 64 * KB;
	} /* useless to define a dictionary > 64 KB */
	if ((U32)dictSize > dict->dictSize) {
		dictSize = (int)dict->dictSize;
	}

	if (safeBuffer == NULL)
		assert(dictSize == 0);
	if (dictSize > 0) {
		const BYTE *const previousDictEnd =
			dict->dictionary + dict->dictSize;
		assert(dict->dictionary);
		LZ4_memmove(safeBuffer, previousDictEnd - dictSize,
			    (size_t)dictSize);
	}

	dict->dictionary = (const BYTE *)safeBuffer;
	dict->dictSize = (U32)dictSize;

	return dictSize;
}
EXPORT_SYMBOL(LZ4_saveDict);

int LZ4_compress_fast_continue(LZ4_stream_t *LZ4_stream, const char *source,
			       char *dest, int inputSize, int maxOutputSize,
			       int acceleration)
{
	const tableType_t tableType = byU32;
	LZ4_stream_t_internal *const streamPtr = &LZ4_stream->internal_donotuse;
	const char *dictEnd = streamPtr->dictSize ?
				      (const char *)streamPtr->dictionary +
					      streamPtr->dictSize :
				      NULL;

	DEBUGLOG(5, "LZ4_compress_fast_continue (inputSize=%i, dictSize=%u)",
		 inputSize, streamPtr->dictSize);

	LZ4_renormDictT(streamPtr, inputSize); /* fix index overflow */
	if (acceleration < 1)
		acceleration = LZ4_ACCELERATION_DEFAULT;
	if (acceleration > LZ4_ACCELERATION_MAX)
		acceleration = LZ4_ACCELERATION_MAX;

	/* invalidate tiny dictionaries */
	if ((streamPtr->dictSize <
	     4) /* tiny dictionary : not enough for a hash */
	    && (dictEnd != source) /* prefix mode */
	    &&
	    (inputSize >
	     0) /* tolerance : don't lose history, in case next invocation would use prefix mode */
	    && (streamPtr->dictCtx == NULL) /* usingDictCtx */
	) {
		DEBUGLOG(
			5,
			"LZ4_compress_fast_continue: dictSize(%u) at addr:%p is too small",
			streamPtr->dictSize, streamPtr->dictionary);
		/* remove dictionary existence from history, to employ faster prefix mode */
		streamPtr->dictSize = 0;
		streamPtr->dictionary = (const BYTE *)source;
		dictEnd = source;
	}

	/* Check overlapping input/dictionary space */
	{
		const char *const sourceEnd = source + inputSize;
		if ((sourceEnd > (const char *)streamPtr->dictionary) &&
		    (sourceEnd < dictEnd)) {
			streamPtr->dictSize = (U32)(dictEnd - sourceEnd);
			if (streamPtr->dictSize > 64 * KB)
				streamPtr->dictSize = 64 * KB;
			if (streamPtr->dictSize < 4)
				streamPtr->dictSize = 0;
			streamPtr->dictionary =
				(const BYTE *)dictEnd - streamPtr->dictSize;
		}
	}

	/* prefix mode : source data follows dictionary */
	if (dictEnd == source) {
		if ((streamPtr->dictSize < 64 * KB) &&
		    (streamPtr->dictSize < streamPtr->currentOffset))
			return LZ4_compress_generic(
				streamPtr, source, dest, inputSize, NULL,
				maxOutputSize, limitedOutput, tableType,
				withPrefix64k, dictSmall, acceleration);
		else
			return LZ4_compress_generic(
				streamPtr, source, dest, inputSize, NULL,
				maxOutputSize, limitedOutput, tableType,
				withPrefix64k, noDictIssue, acceleration);
	}

	/* external dictionary mode */
	{
		int result;
		if (streamPtr->dictCtx) {
			/* We depend here on the fact that dictCtx'es (produced by
             * LZ4_loadDict) guarantee that their tables contain no references
             * to offsets between dictCtx->currentOffset - 64 KB and
             * dictCtx->currentOffset - dictCtx->dictSize. This makes it safe
             * to use noDictIssue even when the dict isn't a full 64 KB.
             */
			if (inputSize > 4 * KB) {
				/* For compressing large blobs, it is faster to pay the setup
                 * cost to copy the dictionary's tables into the active context,
                 * so that the compression loop is only looking into one table.
                 */
				LZ4_memcpy(streamPtr, streamPtr->dictCtx,
					   sizeof(*streamPtr));
				result = LZ4_compress_generic(
					streamPtr, source, dest, inputSize,
					NULL, maxOutputSize, limitedOutput,
					tableType, usingExtDict, noDictIssue,
					acceleration);
			} else {
				result = LZ4_compress_generic(
					streamPtr, source, dest, inputSize,
					NULL, maxOutputSize, limitedOutput,
					tableType, usingDictCtx, noDictIssue,
					acceleration);
			}
		} else { /* small data <= 4 KB */
			if ((streamPtr->dictSize < 64 * KB) &&
			    (streamPtr->dictSize < streamPtr->currentOffset)) {
				result = LZ4_compress_generic(
					streamPtr, source, dest, inputSize,
					NULL, maxOutputSize, limitedOutput,
					tableType, usingExtDict, dictSmall,
					acceleration);
			} else {
				result = LZ4_compress_generic(
					streamPtr, source, dest, inputSize,
					NULL, maxOutputSize, limitedOutput,
					tableType, usingExtDict, noDictIssue,
					acceleration);
			}
		}
		streamPtr->dictionary = (const BYTE *)source;
		streamPtr->dictSize = (U32)inputSize;
		return result;
	}
}
EXPORT_SYMBOL(LZ4_compress_fast_continue);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LZ4 compressor");
