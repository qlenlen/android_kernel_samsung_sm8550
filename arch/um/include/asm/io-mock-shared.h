/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_UM_IO_MOCK_SHARED_H
#define _ASM_UM_IO_MOCK_SHARED_H

#define readb readb
u8 readb(const volatile void __iomem *);

#define readw readw
u16 readw(const volatile void __iomem *);

#define readl readl
u32 readl(const volatile void __iomem *);

#ifdef CONFIG_64BIT
#define readq readq
u64 readq(const volatile void __iomem *);
#endif /* CONFIG_64BIT */

#define writeb writeb
void writeb(u8, const volatile void __iomem *);

#define writew writew
void writew(u16, const volatile void __iomem *);

#define writel writel
void writel(u32, const volatile void __iomem *);

#ifdef CONFIG_64BIT
#define writeq writeq
void writeq(u64, const volatile void __iomem *);
#endif /* CONFIG_64BIT */



#define readb_relaxed readb_relaxed
u8 readb_relaxed(const volatile void __iomem *);

#define readw_relaxed readw_relaxed
u16 readw_relaxed(const volatile void __iomem *);

#define readl_relaxed readl_relaxed
u32 readl_relaxed(const volatile void __iomem *);

#ifdef CONFIG_64BIT
#define readq_relaxed readq_relaxed
u64 readq_relaxed(const volatile void __iomem *);
#endif /* CONFIG_64BIT */

#define writeb_relaxed writeb_relaxed
void writeb_relaxed(u8, const volatile void __iomem *);

#define writew_relaxed writew_relaxed
void writew_relaxed(u16, const volatile void __iomem *);

#define writel_relaxed writel_relaxed
void writel_relaxed(u32, const volatile void __iomem *);

#ifdef CONFIG_64BIT
#define writeq_relaxed writeq_relaxed
void writeq_relaxed(u64, const volatile void __iomem *);
#endif /* CONFIG_64BIT */

#endif /* _ASM_UM_IO_MOCK_SHARED_H */
