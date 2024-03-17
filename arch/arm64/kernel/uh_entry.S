/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/linkage.h>
#include <linux/uh.h>

SYM_CODE_START(uh_call)
entry:
	stp x1, x0, [sp, #-16]!
        stp x3, x2, [sp, #-16]!
        stp x5, x4, [sp, #-16]!
        stp x7, x6, [sp, #-16]!
back:
	smc	#0x0
	/* save smc return result to x8 */
	mov	x8, x0
	/* interrupted case does not need x0-x7 be restored */
	cmp	x8, #0x1
	b.eq	back

        ldp x7, x6, [sp], #16
        ldp x5, x4, [sp], #16
        ldp x3, x2, [sp], #16
        ldp x1, x0, [sp], #16

	cmp	x8, #0x0
	/* busy return case does need x0-x7 be restored */
	b.ne	entry

	ret
SYM_CODE_END(uh_call)

