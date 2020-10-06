// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_pgtable.h>

#include <nvhe/early_alloc.h>
#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mm.h>
#include <nvhe/spinlock.h>

struct kvm_pgtable hyp_pgtable;

phys_addr_t __phys_hyp_pgd;
nvhe_spinlock_t __hyp_pgd_lock;
u64 __io_map_base;

int __hyp_create_mappings(unsigned long start, unsigned long size,
			  unsigned long phys, unsigned long prot)
{
	int err;

	nvhe_spin_lock(&__hyp_pgd_lock);
	err = kvm_pgtable_hyp_map(&hyp_pgtable, start, size, phys, prot);
	nvhe_spin_unlock(&__hyp_pgd_lock);

	return err;
}

unsigned long __hyp_create_private_mapping(phys_addr_t phys, size_t size,
					   unsigned long prot)
{
	unsigned long base;
	int ret;

	nvhe_spin_lock(&__hyp_pgd_lock);

	size = PAGE_ALIGN(size + offset_in_page(phys));
	base = __io_map_base;
	__io_map_base += size;

	/* Are we overflowing on the vmemmap ? */
	if (__io_map_base > __hyp_vmemmap) {
		__io_map_base -= size;
		base = 0;
		goto out;
	}

	ret = kvm_pgtable_hyp_map(&hyp_pgtable, base, size, phys, prot);
	if (ret) {
		base = 0;
		goto out;
	}

	base = base + offset_in_page(phys);

out:
	nvhe_spin_unlock(&__hyp_pgd_lock);
	return base;
}

int hyp_create_mappings(void *from, void *to, enum kvm_pgtable_prot prot)
{
	unsigned long start = (unsigned long)from;
	unsigned long end = (unsigned long)to;
	unsigned long virt_addr;
	phys_addr_t phys;

	start = start & PAGE_MASK;
	end = PAGE_ALIGN(end);

	for (virt_addr = start; virt_addr < end; virt_addr += PAGE_SIZE) {
		int err;

		phys = hyp_virt_to_phys((void *)virt_addr);
		err = __hyp_create_mappings(virt_addr, PAGE_SIZE, phys, prot);
		if (err)
			return err;
	}

	return 0;
}

int hyp_back_vmemmap_early(phys_addr_t phys, unsigned long size)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long start, end;
	struct hyp_page *p;
	phys_addr_t base;

	p = hyp_phys_to_page(phys);

	/* Find which portion of vmemmap needs to be backed up */
	start = (unsigned long)p;
	end = start + nr_pages * sizeof(struct hyp_page);
	start = ALIGN_DOWN(start, PAGE_SIZE);
	end = ALIGN(end, PAGE_SIZE);

	/* Allocate pages to back that portion */
	nr_pages = (end - start) >> PAGE_SHIFT;
	base = hyp_virt_to_phys(hyp_early_alloc_page(NULL));
	if (!base)
		return -ENOMEM;
	nr_pages--;
	while (nr_pages) {
		if (!hyp_early_alloc_page(NULL))
			return -ENOMEM;
		nr_pages--;
	}

	return __hyp_create_mappings(start, end - start, base, PAGE_HYP);
}

int hyp_create_idmap(void)
{
	unsigned long start, end;

	start = (unsigned long)__hyp_idmap_text_start;
	start = hyp_virt_to_phys((void *)start);
	start = ALIGN_DOWN(start, PAGE_SIZE);

	end = (unsigned long)__hyp_idmap_text_end;
	end = hyp_virt_to_phys((void *)end);
	end = ALIGN(end, PAGE_SIZE);

	/*
	 * One half of the VA space is reserved to linearly map portions of
	 * memory -- see va_layout.c for more details. The other half of the VA
	 * space contains the trampoline page, and needs some care. Split that
	 * second half in two and find the quarter of VA space not conflicting
	 * with the idmap to place the IOs and the vmemmap. IOs use the lower
	 * half of the quarter and the vmemmap the upper half.
	 */
	__io_map_base = start & BIT(hyp_va_bits - 2);
	__io_map_base ^= BIT(hyp_va_bits - 2);
	__hyp_vmemmap = __io_map_base | BIT(hyp_va_bits - 3);

	return __hyp_create_mappings(start, end - start, start, PAGE_HYP_EXEC);
}
