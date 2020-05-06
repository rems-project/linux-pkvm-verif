// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/spectre.h>

#include <nvhe/early_alloc.h>
#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mm.h>
#include <nvhe/spinlock.h>

struct kvm_pgtable hyp_pgtable;

hyp_spinlock_t __hyp_pgd_lock;
u64 __io_map_base;

struct hyp_memblock_region hyp_memory[HYP_MEMBLOCK_REGIONS];
int hyp_memblock_nr;

int __hyp_create_mappings(unsigned long start, unsigned long size,
			  unsigned long phys, unsigned long prot)
{
	int err;

	hyp_spin_lock(&__hyp_pgd_lock);
	err = kvm_pgtable_hyp_map(&hyp_pgtable, start, size, phys, prot);
	hyp_spin_unlock(&__hyp_pgd_lock);

	return err;
}

unsigned long __hyp_create_private_mapping(phys_addr_t phys, size_t size,
					   unsigned long prot)
{
	unsigned long addr;
	int ret;

	hyp_spin_lock(&__hyp_pgd_lock);

	size = PAGE_ALIGN(size + offset_in_page(phys));
	addr = __io_map_base;
	__io_map_base += size;

	/* Are we overflowing on the vmemmap ? */
	if (__io_map_base > __hyp_vmemmap) {
		__io_map_base -= size;
		addr = 0;
		goto out;
	}

	ret = kvm_pgtable_hyp_map(&hyp_pgtable, addr, size, phys, prot);
	if (ret) {
		addr = 0;
		goto out;
	}

	addr = addr + offset_in_page(phys);
out:
	hyp_spin_unlock(&__hyp_pgd_lock);

	return addr;
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

int hyp_back_vmemmap(phys_addr_t phys, unsigned long size, phys_addr_t back)
{
	unsigned long start, end;

	hyp_vmemmap_range(phys, size, &start, &end);

	return __hyp_create_mappings(start, end - start, back, PAGE_HYP);
}

static void *__hyp_bp_vect_base;
int hyp_cpu_set_vector(enum arm64_hyp_spectre_vector slot)
{
	void *vector;

	switch (slot) {
	case HYP_VECTOR_DIRECT: {
		vector = hyp_symbol_addr(__kvm_hyp_vector);
		break;
	}
	case HYP_VECTOR_SPECTRE_DIRECT: {
		vector = hyp_symbol_addr(__bp_harden_hyp_vecs);
		break;
	}
	case HYP_VECTOR_INDIRECT:
	case HYP_VECTOR_SPECTRE_INDIRECT: {
		vector = (void *)__hyp_bp_vect_base;
		break;
	}
	default:
		return -EINVAL;
	}

	vector = __kvm_vector_slot2addr(vector, slot);
	*this_cpu_ptr(&kvm_hyp_vector) = (unsigned long)vector;

	return 0;
}

int hyp_map_vectors(void)
{
	unsigned long bp_base;

	if (!cpus_have_const_cap(ARM64_SPECTRE_V3A))
		return 0;

	bp_base = (unsigned long)hyp_symbol_addr(__bp_harden_hyp_vecs);
	bp_base = __hyp_pa(bp_base);
	bp_base = __hyp_create_private_mapping(bp_base, __BP_HARDEN_HYP_VECS_SZ,
					       PAGE_HYP_EXEC);
	if (!bp_base)
		return -1;

	__hyp_bp_vect_base = (void *)bp_base;

	return 0;
}

int hyp_create_idmap(void)
{
	unsigned long start, end;

	start = (unsigned long)hyp_symbol_addr(__hyp_idmap_text_start);
	start = hyp_virt_to_phys((void *)start);
	start = ALIGN_DOWN(start, PAGE_SIZE);

	end = (unsigned long)hyp_symbol_addr(__hyp_idmap_text_end);
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
