// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>

#include <nvhe/early_alloc.h>
#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>

// PS HACK
#include <../debug-pl011.h>

// PS HACK
#include <nvhe/check-pkvm-pgtables.h>

struct hyp_pool hpool;
struct kvm_pgtable_mm_ops hyp_pgtable_mm_ops;
unsigned long hyp_nr_cpus;

#define hyp_percpu_size ((unsigned long)__per_cpu_end - \
			 (unsigned long)__per_cpu_start)

#ifdef CONFIG_KVM_ARM_HYP_DEBUG_UART
unsigned long arm64_kvm_hyp_debug_uart_addr;
static int create_hyp_debug_uart_mapping(void)
{
	phys_addr_t base = CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR;
	unsigned long haddr;

	haddr = __hyp_create_private_mapping(base, PAGE_SIZE, PAGE_HYP_DEVICE);
	if (!haddr)
		return -1;

	arm64_kvm_hyp_debug_uart_addr = haddr;

	return 0;
}
#else
static int create_hyp_debug_uart_mapping(void) { return 0; }
#endif

static void *stacks_base;
static void *vmemmap_base;
static void *hyp_pgt_base;
static void *host_s2_mem_pgt_base;
static void *host_s2_dev_pgt_base;

static int divide_memory_pool(void *virt, unsigned long size)
{
	unsigned long vstart, vend, nr_pages;

	hyp_early_alloc_init(virt, size);

	stacks_base = hyp_early_alloc_contig(hyp_nr_cpus);
	if (!stacks_base)
		return -ENOMEM;

	hyp_vmemmap_range(__hyp_pa(virt), size, &vstart, &vend);
	nr_pages = (vend - vstart) >> PAGE_SHIFT;
	vmemmap_base = hyp_early_alloc_contig(nr_pages);
	if (!vmemmap_base)
		return -ENOMEM;

	nr_pages = hyp_s1_pgtable_size() >> PAGE_SHIFT;
	hyp_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!hyp_pgt_base)
		return -ENOMEM;

	nr_pages = host_s2_mem_pgtable_size() >> PAGE_SHIFT;
	host_s2_mem_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!host_s2_mem_pgt_base)
		return -ENOMEM;

	nr_pages = host_s2_dev_pgtable_size() >> PAGE_SHIFT;
	host_s2_dev_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!host_s2_dev_pgt_base)
		return -ENOMEM;

	return 0;
}

static int recreate_hyp_mappings(phys_addr_t phys, unsigned long size,
				 unsigned long *per_cpu_base)
{
	void *start, *end, *virt = hyp_phys_to_virt(phys);
	int ret, i;

	/* Recreate the hyp page-table using the early page allocator */
	hyp_early_alloc_init(hyp_pgt_base, hyp_s1_pgtable_size());
	ret = kvm_pgtable_hyp_init(&hyp_pgtable, hyp_va_bits,
				   &hyp_early_alloc_mm_ops);
	if (ret)
		return ret;

	ret = hyp_create_idmap();
	if (ret)
		return ret;

	ret = hyp_map_vectors();
	if (ret)
		return ret;

	ret = hyp_back_vmemmap(phys, size, hyp_virt_to_phys(vmemmap_base));
	if (ret)
		return ret;

	ret = hyp_create_mappings(hyp_symbol_addr(__hyp_text_start),
				  hyp_symbol_addr(__hyp_text_end),
				  PAGE_HYP_EXEC);
	if (ret)
		return ret;

	ret = hyp_create_mappings(hyp_symbol_addr(__start_rodata),
				  hyp_symbol_addr(__end_rodata), PAGE_HYP_RO);
	if (ret)
		return ret;

	ret = hyp_create_mappings(hyp_symbol_addr(__hyp_data_ro_after_init_start),
				  hyp_symbol_addr(__hyp_data_ro_after_init_end),
				  PAGE_HYP_RO);
	if (ret)
		return ret;

	ret = hyp_create_mappings(hyp_symbol_addr(__bss_start),
				  hyp_symbol_addr(__hyp_bss_end), PAGE_HYP);
	if (ret)
		return ret;

	ret = hyp_create_mappings(hyp_symbol_addr(__hyp_bss_end),
				  hyp_symbol_addr(__bss_stop), PAGE_HYP_RO);
	if (ret)
		return ret;

	ret = hyp_create_mappings(virt, virt + size - 1, PAGE_HYP);
	if (ret)
		return ret;

	for (i = 0; i < hyp_nr_cpus; i++) {
		start = (void *)kern_hyp_va(per_cpu_base[i]);
		end = start + PAGE_ALIGN(hyp_percpu_size);
		ret = hyp_create_mappings(start, end, PAGE_HYP);
		if (ret)
			return ret;
	}

	ret = create_hyp_debug_uart_mapping();
	if (ret)
		return ret;

	return 0;
}

static void update_nvhe_init_params(void)
{
	struct kvm_nvhe_init_params *params;
	unsigned long i, stack;

	for (i = 0; i < hyp_nr_cpus; i++) {
		stack = (unsigned long)stacks_base + (i << PAGE_SHIFT);
		params = per_cpu_ptr(&kvm_init_params, i);
		params->stack_hyp_va = stack + PAGE_SIZE;
		params->pgd_pa = __hyp_pa(hyp_pgtable.pgd);
		__flush_dcache_area(params, sizeof(*params));
	}
}

static void *hyp_zalloc_hyp_page(void *arg)
{
	return hyp_alloc_pages(&hpool, HYP_GFP_ZERO, 0);
}

void __noreturn __kvm_hyp_protect_finalise(void)
{
	struct kvm_host_data *host_data = this_cpu_ptr(&kvm_host_data);
	struct kvm_cpu_context *host_ctxt = &host_data->host_ctxt;
	unsigned long nr_pages, used_pages;
	int ret;

	/* Now that the vmemmap is backed, install the full-fledged allocator */
	nr_pages = hyp_s1_pgtable_size() >> PAGE_SHIFT;
	used_pages = hyp_early_alloc_nr_pages();
	ret = hyp_pool_init(&hpool, __hyp_pa(hyp_pgt_base), nr_pages, used_pages);
	if (ret)
		goto out;

	/* Wrap the host with a stage 2 */
	ret = kvm_host_prepare_stage2(host_s2_mem_pgt_base, host_s2_dev_pgt_base);
	if (ret)
		goto out;

	hyp_pgtable_mm_ops.zalloc_page = hyp_zalloc_hyp_page;
	hyp_pgtable_mm_ops.phys_to_virt = hyp_phys_to_virt;
	hyp_pgtable_mm_ops.virt_to_phys = hyp_virt_to_phys;
	hyp_pgtable_mm_ops.get_page = hyp_get_page;
	hyp_pgtable_mm_ops.put_page = hyp_put_page;
	hyp_pgtable.mm_ops = &hyp_pgtable_mm_ops;

out:
	host_ctxt->regs.regs[0] = SMCCC_RET_SUCCESS;
	host_ctxt->regs.regs[1] = ret;

	__host_enter(host_ctxt);
}

int __kvm_hyp_protect(phys_addr_t phys, unsigned long size,
		      unsigned long nr_cpus, unsigned long *per_cpu_base)
{
	struct kvm_nvhe_init_params *params;
	void *virt = hyp_phys_to_virt(phys);
	void (*fn)(phys_addr_t params_pa, void *finalize_fn_va);
	int ret;

	if (phys % PAGE_SIZE || size % PAGE_SIZE || (u64)virt % PAGE_SIZE)
		return -EINVAL;

	hyp_spin_lock_init(&__hyp_pgd_lock);
	hyp_nr_cpus = nr_cpus;

	ret = divide_memory_pool(virt, size);
	if (ret)
		return ret;

	ret = recreate_hyp_mappings(phys, size, per_cpu_base);
	if (ret)
		return ret;

	update_nvhe_init_params();


        // PS HACK
	// check sample property of the putative mapping
	_Bool check = check_hyp_mappings(phys, size, nr_cpus, per_cpu_base);
	// can't actually output the result yet, as I've not got the uart working in QEMU

	// PS HACK
	//	hyp_putc('P');hyp_putc('S');hyp_putc('H');hyp_putc('A');hyp_putc('C');hyp_putc('k');hyp_putc('\n');
	
	/* Jump in the idmap page to switch to the new page-tables */
	params = this_cpu_ptr(&kvm_init_params);
	fn = (typeof(fn))__hyp_pa(hyp_symbol_addr(__kvm_init_switch_pgd));
	fn(__hyp_pa(params), hyp_symbol_addr(__kvm_hyp_protect_finalise));

	unreachable();
}
