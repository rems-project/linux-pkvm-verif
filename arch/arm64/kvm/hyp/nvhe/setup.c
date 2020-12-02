// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>

#include <nvhe/early_alloc.h>
#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mm.h>

struct hyp_pool hpool;
void *kvm_hyp_stacks[CONFIG_NR_CPUS];
#define hyp_percpu_size ((unsigned long)__per_cpu_end - (unsigned long)__per_cpu_start)

/* XXX - this modifies the host's bss directly */
extern void *__kvm_bp_vect_base;

static int hyp_map_memory(phys_addr_t phys, void* virt, unsigned long size,
			  phys_addr_t bp_vect_pa, unsigned long nr_cpus,
			  unsigned long *per_cpu_base)
{
	unsigned long addr;
	void *start, *end;
	int err, i;

	err = hyp_create_idmap();
	if (err)
		return err;

	err = hyp_create_mappings(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC);
	if (err)
		return err;

	err = hyp_create_mappings(__start_rodata, __end_rodata, PAGE_HYP_RO);
	if (err)
		return err;

	err = hyp_create_mappings(__bss_start, __hyp_bss_end, PAGE_HYP);
	if (err)
		return err;

	err = hyp_create_mappings(__hyp_bss_end, __bss_stop, PAGE_HYP_RO);
	if (err)
		return err;

	for (i = 0; i < nr_cpus; i++) {
		start = (void*)kern_hyp_va(per_cpu_base[i]);
		end = start + PAGE_ALIGN(hyp_percpu_size);
		err = hyp_create_mappings(start, end, PAGE_HYP);
		if (err)
			return err;
	}

	err = hyp_create_mappings(virt, virt + size - 1, PAGE_HYP);
	if (err)
		return err;

	err = hyp_back_vmemmap_early(phys, size);
	if (err)
		return err;

	if (!bp_vect_pa)
		return 0;

	addr = hyp_create_private_mapping(bp_vect_pa, __BP_HARDEN_HYP_VECS_SZ,
					  PAGE_HYP_EXEC);
	if (!addr)
		return -1;

	__kvm_bp_vect_base = (void*)addr;

	return 0;
}

static void *hyp_zalloc_hyp_page(void *arg)
{
	return hyp_alloc_pages(&hpool, HYP_GFP_ZERO, 0);
}
static struct kvm_pgtable_mm_ops hyp_pgtable_mm_ops;

void __noreturn __host_enter(struct kvm_cpu_context *host_ctxt);
void __noreturn __kvm_hyp_setup_finalise(phys_addr_t phys, unsigned long size)
{
	struct kvm_host_data *host_data = this_cpu_ptr(&kvm_host_data);
	struct kvm_cpu_context *host_ctxt = &host_data->host_ctxt;
	unsigned long nr_pages, used_pages;
	int ret;

	/* Now that the vmemmap is backed, install the full-fledged allocator */
	nr_pages = size >> PAGE_SHIFT;
	used_pages = hyp_early_alloc_nr_pages();

	hyp_pool_init(&hpool);
	ret = hyp_pool_extend_used(&hpool, phys, nr_pages, used_pages);

	host_ctxt->regs.regs[0] = SMCCC_RET_SUCCESS;
	host_ctxt->regs.regs[1] = ret;

	if (ret)
		goto out;

	/* Use the new allocator for the hyp page-table */
	hyp_pgtable_mm_ops.zalloc_page = hyp_zalloc_hyp_page;
	hyp_pgtable_mm_ops.get_page = hyp_get_page;
	hyp_pgtable_mm_ops.put_page = hyp_put_page;
	hyp_pgtable_mm_ops.phys_to_virt = hyp_phys_to_virt;
	hyp_pgtable_mm_ops.virt_to_phys = hyp_virt_to_phys;
	hyp_pgtable.mm_ops = &hyp_pgtable_mm_ops;

out:
	__host_enter(host_ctxt);
}

extern char __kvm_hyp_host_vector[];
int __kvm_hyp_setup(phys_addr_t phys, void* virt, unsigned long size,
		    phys_addr_t bp_vect_pa, unsigned long nr_cpus,
		    unsigned long *per_cpu_base)
{
	void (*fn)(phys_addr_t, unsigned long, phys_addr_t, void *, void *, void *);
	int ret, i;

	if (phys % PAGE_SIZE || size % PAGE_SIZE || (u64)virt % PAGE_SIZE)
		return -EINVAL;

	/* Initialise hyp data structures */
	hyp_physvirt_offset = (s64)phys - (s64)virt;
	nvhe_spin_lock_init(&__hyp_pgd_lock);
	hyp_early_alloc_init(virt, size);

	/* Allocate the stack pages */
	for (i = 0; i < nr_cpus; i++) {
		void *stack = hyp_early_alloc_page(NULL);
		if (!stack)
			return -ENOMEM;
		kvm_hyp_stacks[i] = stack + PAGE_SIZE;
	}

	/* Recreate the page tables using the reserved hyp memory */
	ret = kvm_pgtable_hyp_init(&hyp_pgtable, hyp_va_bits, &hyp_early_alloc_mm_ops);
	if (ret)
		return ret;
	__phys_hyp_pgd = __hyp_pa(hyp_pgtable.pgd);

	ret = hyp_map_memory(phys, virt, size, bp_vect_pa, nr_cpus, per_cpu_base);
	if (ret)
		return ret;

	/* Jump in the idmap page to switch to the new page tables */
	fn = (typeof(fn))__hyp_pa(__kvm_init_switch_pgd);
	fn(phys, size, __phys_hyp_pgd, kvm_hyp_stacks[0],
	   __kvm_hyp_host_vector, __kvm_hyp_setup_finalise);

	unreachable();
}
