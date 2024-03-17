/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Mock IO functions.
 *
 * Copyright (C) 2018, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#ifndef _ASM_UM_IO_MOCK_H
#define _ASM_UM_IO_MOCK_H

#include <asm/io-mock-shared.h>
#include <kunit/mock.h>

DECLARE_FUNCTION_MOCK(readb,
		      RETURNS(u8), PARAMS(const volatile void __iomem *));

DECLARE_FUNCTION_MOCK(readw,
		      RETURNS(u16), PARAMS(const volatile void __iomem *));

DECLARE_FUNCTION_MOCK(readl,
		      RETURNS(u32), PARAMS(const volatile void __iomem *));

#ifdef CONFIG_64BIT
DECLARE_FUNCTION_MOCK(readq,
		      RETURNS(u64), PARAMS(const volatile void __iomem *));
#endif /* CONFIG_64BIT */

DECLARE_FUNCTION_MOCK_VOID_RETURN(writeb,
				  PARAMS(u8, const volatile void __iomem *));

DECLARE_FUNCTION_MOCK_VOID_RETURN(writew,
				  PARAMS(u16, const volatile void __iomem *));

DECLARE_FUNCTION_MOCK_VOID_RETURN(writel,
				  PARAMS(u32, const volatile void __iomem *));

#ifdef CONFIG_64BIT
DECLARE_FUNCTION_MOCK_VOID_RETURN(writeq,
				  PARAMS(u64, const volatile void __iomem *));
#endif /* CONFIG_64BIT */



DECLARE_FUNCTION_MOCK(readb_relaxed,
		      RETURNS(u8), PARAMS(const volatile void __iomem *));

DECLARE_FUNCTION_MOCK(readw_relaxed,
		      RETURNS(u16), PARAMS(const volatile void __iomem *));

DECLARE_FUNCTION_MOCK(readl_relaxed,
		      RETURNS(u32), PARAMS(const volatile void __iomem *));

#ifdef CONFIG_64BIT
DECLARE_FUNCTION_MOCK(readq_relaxed,
		      RETURNS(u64), PARAMS(const volatile void __iomem *));
#endif /* CONFIG_64BIT */

DECLARE_FUNCTION_MOCK_VOID_RETURN(writeb_relaxed,
				  PARAMS(u8, const volatile void __iomem *));

DECLARE_FUNCTION_MOCK_VOID_RETURN(writew_relaxed,
				  PARAMS(u16, const volatile void __iomem *));

DECLARE_FUNCTION_MOCK_VOID_RETURN(writel_relaxed,
				  PARAMS(u32, const volatile void __iomem *));

#ifdef CONFIG_64BIT
DECLARE_FUNCTION_MOCK_VOID_RETURN(writeq_relaxed,
				  PARAMS(u64, const volatile void __iomem *));
#endif /* CONFIG_64BIT */


#endif /* _ASM_UM_IO_MOCK_H */
