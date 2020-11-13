/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_HYP_MM_H
#define __KVM_HYP_MM_H

#include <asm/kvm_pgtable.h>
#include <asm/spectre.h>
#include <linux/types.h>

#include <nvhe/memory.h>
#include <nvhe/spinlock.h>

extern struct hyp_memblock_region kvm_nvhe_sym(hyp_memory)[];
extern int kvm_nvhe_sym(hyp_memblock_nr);
extern struct kvm_pgtable hyp_pgtable;
extern hyp_spinlock_t __hyp_pgd_lock;
extern struct hyp_pool hpool;
extern u64 __io_map_base;
extern u32 hyp_va_bits;

int hyp_create_idmap(void);
int hyp_map_vectors(void);
int hyp_back_vmemmap(phys_addr_t phys, unsigned long size, phys_addr_t back);
int hyp_cpu_set_vector(enum arm64_hyp_spectre_vector slot);
int hyp_create_mappings(void *from, void *to, enum kvm_pgtable_prot prot);
int __hyp_create_mappings(unsigned long start, unsigned long size,
			  unsigned long phys, unsigned long prot);
unsigned long __hyp_create_private_mapping(phys_addr_t phys, size_t size,
					   unsigned long prot);

static inline void hyp_vmemmap_range(phys_addr_t phys, unsigned long size,
				     unsigned long *start, unsigned long *end)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct hyp_page *p = hyp_phys_to_page(phys);

	*start = (unsigned long)p;
	*end = *start + nr_pages * sizeof(struct hyp_page);
	*start = ALIGN_DOWN(*start, PAGE_SIZE);
	*end = ALIGN(*end, PAGE_SIZE);
}

static inline unsigned long __hyp_pgtable_max_pages(unsigned long nr_pages)
{
	unsigned long total = 0, i;

	/* Provision the worst case scenario with 4 levels of page-table */
	for (i = 0; i < 4; i++) {
		nr_pages = DIV_ROUND_UP(nr_pages, PTRS_PER_PTE);
		total += nr_pages;
	}

	return total;
}

static inline unsigned long __hyp_pgtable_total_size(void)
{
	struct hyp_memblock_region *reg;
	unsigned long nr_pages, res = 0;
	int i;

	for (i = 0; i < kvm_nvhe_sym(hyp_memblock_nr); i++) {
		reg = &kvm_nvhe_sym(hyp_memory)[i];
		nr_pages = (reg->end - reg->start) >> PAGE_SHIFT;
		nr_pages = __hyp_pgtable_max_pages(nr_pages);
		res += nr_pages << PAGE_SHIFT;
	}

	return res;
}

static inline unsigned long hyp_s1_pgtable_size(void)
{
	unsigned long res, nr_pages;

	if (kvm_nvhe_sym(hyp_memblock_nr) <= 0)
		return 0;

	res = __hyp_pgtable_total_size();

	/* Allow 1 GiB for private mappings */
	nr_pages = (1 << 30) >> PAGE_SHIFT;
	nr_pages = __hyp_pgtable_max_pages(nr_pages);
	res += nr_pages << PAGE_SHIFT;

	return res;
}

static inline unsigned long host_s2_mem_pgtable_size(void)
{
	unsigned long max_pgd_sz = 16 << PAGE_SHIFT;

	if (kvm_nvhe_sym(hyp_memblock_nr) <= 0)
		return 0;

	return __hyp_pgtable_total_size() + max_pgd_sz;
}

static inline unsigned long host_s2_dev_pgtable_size(void)
{
	if (kvm_nvhe_sym(hyp_memblock_nr) <= 0)
		return 0;

	/* Allow 1 GiB for private mappings */
	return __hyp_pgtable_max_pages((1 << 30) >> PAGE_SHIFT) << PAGE_SHIFT;
}

#endif /* __KVM_HYP_MM_H */
