// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <asm/kvm_pgtable.h>

#include <nvhe/memory.h>

struct kvm_pgtable_mm_ops hyp_early_alloc_mm_ops;
__ro_after_init s64 hyp_physvirt_offset;

static unsigned long base;
static unsigned long end;
static unsigned long cur;

unsigned long hyp_early_alloc_nr_pages(void)
{
	return (cur - base) >> PAGE_SHIFT;
}

extern void clear_page(void *to);

void *hyp_early_alloc_contig(unsigned int nr_pages)
{
	unsigned long ret = cur, i, p;

	if (!nr_pages)
		return NULL;

	cur += nr_pages << PAGE_SHIFT;
	if (cur > end) {
		cur = ret;
		return NULL;
	}

	for (i = 0; i < nr_pages; i++) {
		p = ret + (i << PAGE_SHIFT);
		clear_page((void *)(p));
	}

	return (void *)ret;
}

void *hyp_early_alloc_page(void *arg)
{
	return hyp_early_alloc_contig(1);
}

void hyp_early_alloc_init(unsigned long virt, unsigned long size)
{
	base = virt;
	end = virt + size;
	cur = virt;

	hyp_early_alloc_mm_ops.zalloc_page = hyp_early_alloc_page;
	hyp_early_alloc_mm_ops.phys_to_virt = hyp_phys_to_virt;
	hyp_early_alloc_mm_ops.virt_to_phys = hyp_virt_to_phys;
}
