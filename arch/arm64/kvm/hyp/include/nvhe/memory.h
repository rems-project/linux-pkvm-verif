// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_HYP_MEMORY_H
#define __KVM_HYP_MEMORY_H

#include <asm/page.h>

#include <linux/types.h>

struct hyp_pool;
struct hyp_page {
	unsigned int order;
	struct hyp_pool *pool;
	int refcount;
	union {
		/* allocated page */
		void *virt;
		/* free page */
		struct list_head node;
	};
	/* Range of 'sibling' pages (donated by the host at the same time) */
	phys_addr_t sibling_range_start;
	phys_addr_t sibling_range_end;
};

extern s64 hyp_physvirt_offset;
extern u64 __hyp_vmemmap;
#define hyp_vmemmap ((struct hyp_page *)__hyp_vmemmap)

#define __hyp_pa(virt)	((phys_addr_t)(virt) + hyp_physvirt_offset)
#define __hyp_va(virt)	(void*)((phys_addr_t)(virt) - hyp_physvirt_offset)

static inline void *hyp_phys_to_virt(phys_addr_t phys)
{
	return __hyp_va(phys);
}

static inline phys_addr_t hyp_virt_to_phys(void* addr)
{
	return __hyp_pa(addr);
}

#define hyp_phys_to_pfn(phys)	((phys) >> PAGE_SHIFT)
#define hyp_phys_to_page(phys)	&hyp_vmemmap[hyp_phys_to_pfn(phys)]
#define hyp_virt_to_page(virt)	hyp_phys_to_page(__hyp_pa(virt))

#define hyp_page_to_phys(page)  ((phys_addr_t)((page) - hyp_vmemmap) << PAGE_SHIFT)
#define hyp_page_to_virt(page)	__hyp_va(hyp_page_to_phys(page))
#define hyp_page_to_pool(page)	((struct hyp_page*)page)->pool

#endif /* __KVM_HYP_MEMORY_H */
