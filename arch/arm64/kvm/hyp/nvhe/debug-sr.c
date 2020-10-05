// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <hyp/debug-sr.h>

#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/debug-monitors.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

void __debug_save_spe(struct kvm_vcpu *vcpu)
{
	u64 reg;
	u64 *pmscr_el1;

	if (!vcpu->arch.ctxt.is_host)
		return;

	/* Clear pmscr in case of early return */
	pmscr_el1 = this_cpu_ptr(&kvm_host_pmscr_el1);
	*pmscr_el1 = 0;

	/* SPE present on this CPU? */
	if (!cpuid_feature_extract_unsigned_field(read_sysreg(id_aa64dfr0_el1),
						  ID_AA64DFR0_PMSVER_SHIFT))
		return;

	/* Yes; is it owned by EL3? */
	reg = read_sysreg_s(SYS_PMBIDR_EL1);
	if (reg & BIT(SYS_PMBIDR_EL1_P_SHIFT))
		return;

	/* No; is the host actually using the thing? */
	reg = read_sysreg_s(SYS_PMBLIMITR_EL1);
	if (!(reg & BIT(SYS_PMBLIMITR_EL1_E_SHIFT)))
		return;

	/* Yes; save the control register and disable data generation */
	*pmscr_el1 = read_sysreg_s(SYS_PMSCR_EL1);
	write_sysreg_s(0, SYS_PMSCR_EL1);
	isb();

	/* Now drain all buffered data to memory */
	psb_csync();
	dsb(nsh);
}

void __debug_restore_spe(struct kvm_vcpu *vcpu)
{
	u64 pmscr_el1;

	if (!vcpu->arch.ctxt.is_host)
		return;

	pmscr_el1 = __this_cpu_read(kvm_host_pmscr_el1);
	if (!pmscr_el1)
		return;

	/* The host page table is installed, but not yet synchronised */
	isb();

	/* Re-enable data generation */
	write_sysreg_s(pmscr_el1, SYS_PMSCR_EL1);
}

u32 __kvm_get_mdcr_el2(void)
{
	return read_sysreg(mdcr_el2);
}
