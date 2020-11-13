// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_cpufeature.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/stage2_pgtable.h>

#include <hyp/switch.h>

#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>

extern unsigned long hyp_nr_cpus;
struct host_kvm host_kvm;

struct hyp_pool host_s2_mem;
struct hyp_pool host_s2_dev;

static void *host_s2_zalloc_pages_exact(size_t size)
{
	return hyp_alloc_pages(&host_s2_mem, HYP_GFP_ZERO, get_order(size));
}

static void *host_s2_zalloc_page(void *pool)
{
	return hyp_alloc_pages(pool, HYP_GFP_ZERO, 0);
}

static int prepare_s2_pools(void *mem_pgt_pool, void *dev_pgt_pool)
{
	unsigned long nr_pages;
	int ret;

	nr_pages = host_s2_mem_pgtable_size() >> PAGE_SHIFT;
	ret = hyp_pool_init(&host_s2_mem, __hyp_pa(mem_pgt_pool), nr_pages, 0);
	if (ret)
		return ret;

	nr_pages = host_s2_dev_pgtable_size() >> PAGE_SHIFT;
	ret = hyp_pool_init(&host_s2_dev, __hyp_pa(dev_pgt_pool), nr_pages, 0);
	if (ret)
		return ret;

	host_kvm.mm_ops.zalloc_pages_exact = host_s2_zalloc_pages_exact;
	host_kvm.mm_ops.zalloc_page = host_s2_zalloc_page;
	host_kvm.mm_ops.phys_to_virt = hyp_phys_to_virt;
	host_kvm.mm_ops.virt_to_phys = hyp_virt_to_phys;
	host_kvm.mm_ops.page_count = hyp_page_count;
	host_kvm.mm_ops.get_page = hyp_get_page;
	host_kvm.mm_ops.put_page = hyp_put_page;

	return 0;
}

static void prepare_host_vtcr(void)
{
	u32 parange, phys_shift;
	u64 mmfr0, mmfr1;

	mmfr0 = arm64_ftr_reg_id_aa64mmfr0_el1.sys_val;
	mmfr1 = arm64_ftr_reg_id_aa64mmfr1_el1.sys_val;

	/* The host stage 2 is id-mapped, so use parange for T0SZ */
	parange = kvm_get_parange(mmfr0);
	phys_shift = id_aa64mmfr0_parange_to_phys_shift(parange);

	host_kvm.arch.vtcr = kvm_get_vtcr(mmfr0, mmfr1, phys_shift);
}

int kvm_host_prepare_stage2(void *mem_pgt_pool, void *dev_pgt_pool)
{
	struct kvm_s2_mmu *mmu = &host_kvm.arch.mmu;
	struct kvm_nvhe_init_params *params;
	int ret, i;

	prepare_host_vtcr();
	hyp_spin_lock_init(&host_kvm.lock);

	ret = prepare_s2_pools(mem_pgt_pool, dev_pgt_pool);
	if (ret)
		return ret;

	ret = kvm_pgtable_stage2_init(&host_kvm.pgt, &host_kvm.arch,
				      &host_kvm.mm_ops);
	if (ret)
		return ret;

	mmu->pgd_phys = __hyp_pa(host_kvm.pgt.pgd);
	mmu->arch = &host_kvm.arch;
	mmu->pgt = &host_kvm.pgt;
	mmu->vmid.vmid_gen = 0;
	mmu->vmid.vmid = 0;

	for (i = 0; i < hyp_nr_cpus; i++) {
		params = per_cpu_ptr(&kvm_init_params, i);
		params->vttbr = kvm_get_vttbr(mmu);
		params->vtcr = host_kvm.arch.vtcr;
		params->hcr_el2 |= HCR_VM;
		__flush_dcache_area(params, sizeof(*params));
	}

	write_sysreg(this_cpu_ptr(&kvm_init_params)->hcr_el2, hcr_el2);
	__load_stage2(&host_kvm.arch.mmu, host_kvm.arch.vtcr);

	return 0;
}

static void host_stage2_unmap_dev_all(void)
{
	struct kvm_pgtable *pgt = &host_kvm.pgt;
	struct hyp_memblock_region *reg;
	u64 addr = 0;
	int i;

	/* Unmap all non-memory regions to recycle the pages */
	for (i = 0; i < hyp_memblock_nr; i++, addr = reg->end) {
		reg = &hyp_memory[i];
		kvm_pgtable_stage2_unmap(pgt, addr, reg->start - addr);
	}
	kvm_pgtable_stage2_unmap(pgt, addr, ULONG_MAX);
}

static bool ipa_is_memory(u64 ipa)
{
	int cur, left = 0, right = hyp_memblock_nr;
	struct hyp_memblock_region *reg;

	/* The list of memblock regions is sorted, binary search it */
	while (left < right) {
		cur = (left + right) >> 1;
		reg = &hyp_memory[cur];
		if (ipa < reg->start)
			right = cur;
		else if (ipa >= reg->end)
			left = cur + 1;
		else
			return true;
	}

	return false;
}

static int __host_stage2_map(u64 ipa, u64 size, enum kvm_pgtable_prot prot,
			     struct hyp_pool *p)
{
	return kvm_pgtable_stage2_map(&host_kvm.pgt, ipa, size, ipa, prot, p);
}

static int host_stage2_map(u64 ipa, u64 size, enum kvm_pgtable_prot prot)
{
	int ret, is_memory = ipa_is_memory(ipa);
	struct hyp_pool *pool;

	pool = is_memory ? &host_s2_mem : &host_s2_dev;

	hyp_spin_lock(&host_kvm.lock);
	ret = __host_stage2_map(ipa, size, prot, pool);
	if (ret == -ENOMEM && !is_memory) {
		host_stage2_unmap_dev_all();
		ret = __host_stage2_map(ipa, size, prot, pool);
	}
	hyp_spin_unlock(&host_kvm.lock);

	return ret;
}

void handle_host_mem_abort(struct kvm_cpu_context *host_ctxt)
{
	enum kvm_pgtable_prot prot;
	u64 far, hpfar, esr, ipa;
	int ret;

	esr = read_sysreg_el2(SYS_ESR);
	if (!__get_fault_info(esr, &far, &hpfar))
		hyp_panic();

	prot = KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W | KVM_PGTABLE_PROT_X;
	ipa = (hpfar & HPFAR_MASK) << 8;
	ret = host_stage2_map(ipa, PAGE_SIZE, prot);
	if (ret)
		hyp_panic();
}
