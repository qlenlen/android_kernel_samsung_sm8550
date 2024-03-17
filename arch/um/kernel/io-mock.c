// SPDX-License-Identifier: GPL-2.0
/*
 * Mock IO functions.
 *
 * Copyright (C) 2018, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <linux/mm.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <kunit/mock.h>

DEFINE_FUNCTION_MOCK(readb,
		     RETURNS(u8), PARAMS(const volatile void __iomem *));

DEFINE_FUNCTION_MOCK(readw,
		     RETURNS(u16), PARAMS(const volatile void __iomem *));

DEFINE_FUNCTION_MOCK(readl,
		     RETURNS(u32), PARAMS(const volatile void __iomem *));

#ifdef CONFIG_64BIT
DEFINE_FUNCTION_MOCK(readq,
		     RETURNS(u64), PARAMS(const volatile void __iomem *));
#endif /* CONFIG_64BIT */

DEFINE_FUNCTION_MOCK_VOID_RETURN(writeb,
				 PARAMS(u8, const volatile void __iomem *));

DEFINE_FUNCTION_MOCK_VOID_RETURN(writew,
				 PARAMS(u16, const volatile void __iomem *));

DEFINE_FUNCTION_MOCK_VOID_RETURN(writel,
				 PARAMS(u32, const volatile void __iomem *));

#ifdef CONFIG_64BIT
DEFINE_FUNCTION_MOCK_VOID_RETURN(writeq,
				 PARAMS(u64, const volatile void __iomem *));
#endif /* CONFIG_64BIT */
