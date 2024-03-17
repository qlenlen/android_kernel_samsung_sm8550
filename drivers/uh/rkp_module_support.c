#include <linux/rkp.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/kasan.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/moduleloader.h>

void *__vmalloc_node_range_for_module(unsigned long core_layout_size, unsigned long core_text_size,
			unsigned long align, unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller);

void *module_alloc_by_rkp(unsigned int core_layout_size, unsigned int core_text_size)
{
    u64 module_alloc_end = module_alloc_base + MODULES_VSIZE;
    gfp_t gfp_mask = GFP_KERNEL;
    void *p;

    /* Silence the initial allocation */
    if (IS_ENABLED(CONFIG_ARM64_MODULE_PLTS))
        gfp_mask |= __GFP_NOWARN;

    if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
        IS_ENABLED(CONFIG_KASAN_SW_TAGS))
        /* don't exceed the static module region - see below */
        module_alloc_end = MODULES_END;

    p = __vmalloc_node_range_for_module(core_layout_size, core_text_size, MODULE_ALIGN, module_alloc_base,
                module_alloc_end, gfp_mask, PAGE_KERNEL, VM_DEFER_KMEMLEAK,
                NUMA_NO_NODE, __builtin_return_address(0));

    if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
        (IS_ENABLED(CONFIG_KASAN_VMALLOC) ||
         (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
          !IS_ENABLED(CONFIG_KASAN_SW_TAGS))))
        /*
         * KASAN without KASAN_VMALLOC can only deal with module
         * allocations being served from the reserved module region,
         * since the remainder of the vmalloc region is already
         * backed by zero shadow pages, and punching holes into it
         * is non-trivial. Since the module region is not randomized
         * when KASAN is enabled without KASAN_VMALLOC, it is even
         * less likely that the module region gets exhausted, so we
         * can simply omit this fallback in that case.
         */
        p = __vmalloc_node_range_for_module(core_layout_size, core_text_size, MODULE_ALIGN, module_alloc_base,
                module_alloc_base + SZ_2G, GFP_KERNEL,
                PAGE_KERNEL, 0, NUMA_NO_NODE,
                __builtin_return_address(0));

    if (p && (kasan_alloc_module_shadow(p, core_layout_size, gfp_mask) < 0)) {
        vfree(p);
        return NULL;
    }

    /* Memory is intended to be executable, reset the pointer tag. */
    return kasan_reset_tag(p);
}
