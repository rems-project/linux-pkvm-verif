// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <linux/memblock.h>
#include <linux/sort.h>

#include <asm/kvm_host.h>

#include <nvhe/memory.h>
#include <nvhe/mm.h>

phys_addr_t hyp_mem_base;
phys_addr_t hyp_mem_size;

int __init early_init_dt_add_memory_hyp(u64 base, u64 size)
{
	struct hyp_memblock_region *reg;

	if (kvm_nvhe_sym(hyp_memblock_nr) >= HYP_MEMBLOCK_REGIONS)
		kvm_nvhe_sym(hyp_memblock_nr) = -1;

	if (kvm_nvhe_sym(hyp_memblock_nr) < 0)
		return -ENOMEM;

	reg = kvm_nvhe_sym(hyp_memory);
	reg[kvm_nvhe_sym(hyp_memblock_nr)].start = base;
	reg[kvm_nvhe_sym(hyp_memblock_nr)].end = base + size;
	kvm_nvhe_sym(hyp_memblock_nr)++;

	return 0;
}

static int cmp_hyp_memblock(const void *p1, const void *p2)
{
	const struct hyp_memblock_region *r1 = p1;
	const struct hyp_memblock_region *r2 = p2;

	return r1->start < r2->start ? -1 : (r1->start > r2->start);
}

static void __init sort_memblock_regions(void)
{
	sort(kvm_nvhe_sym(hyp_memory),
	     kvm_nvhe_sym(hyp_memblock_nr),
	     sizeof(struct hyp_memblock_region),
	     cmp_hyp_memblock,
	     NULL);
}

void __init kvm_hyp_reserve(void)
{
	u64 nr_pages, prev;

	if (!is_hyp_mode_available() || is_kernel_in_hyp_mode())
		return;

	if (kvm_get_mode() != KVM_MODE_PROTECTED)
		return;

	if (kvm_nvhe_sym(hyp_memblock_nr) <= 0) {
		kvm_err("Failed to register hyp memblocks\n");
		return;
	}

	sort_memblock_regions();

	hyp_mem_size += NR_CPUS << PAGE_SHIFT;
	hyp_mem_size += hyp_s1_pgtable_size();

	/*
	 * The hyp_vmemmap needs to be backed by pages, but these pages
	 * themselves need to be present in the vmemmap, so compute the number
	 * of pages needed by looking for a fixed point.
	 */
	nr_pages = 0;
	do {
		prev = nr_pages;
		nr_pages = (hyp_mem_size >> PAGE_SHIFT) + prev;
		nr_pages = DIV_ROUND_UP(nr_pages * sizeof(struct hyp_page), PAGE_SIZE);
		nr_pages += __hyp_pgtable_max_pages(nr_pages);
	} while (nr_pages != prev);
	hyp_mem_size += nr_pages << PAGE_SHIFT;

	hyp_mem_base = memblock_find_in_range(0, memblock_end_of_DRAM(),
					      hyp_mem_size, SZ_2M);
	if (!hyp_mem_base) {
		kvm_err("Failed to reserve hyp memory\n");
		return;
	}
	memblock_reserve(hyp_mem_base, hyp_mem_size);

	kvm_info("Reserved %lld MiB at 0x%llx\n", hyp_mem_size >> 20,
		 hyp_mem_base);
}
