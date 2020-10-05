// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <hyp/debug-sr.h>
#include <hyp/switch.h>
#include <hyp/sysreg-sr.h>

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <uapi/linux/psci.h>

#include <kvm/arm_psci.h>

#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>

static void __activate_traps(struct kvm_vcpu *vcpu)
{
	u64 val;

	___activate_traps(vcpu);
	__activate_traps_common(vcpu);

	val = CPTR_EL2_DEFAULT;
	val |= CPTR_EL2_TTA | CPTR_EL2_TZ | CPTR_EL2_TAM;
	if (!update_fp_enabled(vcpu)) {
		val |= CPTR_EL2_TFP;
		__activate_traps_fpsimd32(vcpu);
	}

	write_sysreg(val, cptr_el2);
}

static void __deactivate_traps(struct kvm_vcpu *host_vcpu, struct kvm_vcpu *vcpu)
{
	___deactivate_traps(vcpu);

	__deactivate_traps_common();

	write_sysreg(host_vcpu->arch.mdcr_el2, mdcr_el2);
	write_sysreg(host_vcpu->arch.hcr_el2, hcr_el2);
	write_sysreg(CPTR_EL2_DEFAULT, cptr_el2);
}

static void __restore_stage2(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.hcr_el2 & HCR_VM)
		__activate_vm(kern_hyp_va(vcpu->arch.hw_mmu));
	else
		write_sysreg(0, vttbr_el2);
}

/* Save VGICv3 state on non-VHE systems */
static void __hyp_vgic_save_state(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.ctxt.is_host)
		return;

	if (static_branch_unlikely(&kvm_vgic_global_state.gicv3_cpuif)) {
		__vgic_v3_save_state(&vcpu->arch.vgic_cpu.vgic_v3);
		__vgic_v3_deactivate_traps(&vcpu->arch.vgic_cpu.vgic_v3);
	}
}

/* Restore VGICv3 state on non_VEH systems */
static void __hyp_vgic_restore_state(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.ctxt.is_host)
		return;

	if (static_branch_unlikely(&kvm_vgic_global_state.gicv3_cpuif)) {
		__vgic_v3_activate_traps(&vcpu->arch.vgic_cpu.vgic_v3);
		__vgic_v3_restore_state(&vcpu->arch.vgic_cpu.vgic_v3);
	}
}

/**
 * Disable host events, enable guest events
 */
static void __pmu_switch_to_guest(void)
{
	struct kvm_pmu_events *pmu = __hyp_this_cpu_ptr(kvm_pmu_events);

	if (pmu->events_host)
		write_sysreg(pmu->events_host, pmcntenclr_el0);

	if (pmu->events_guest)
		write_sysreg(pmu->events_guest, pmcntenset_el0);
}

/**
 * Disable guest events, enable host events
 */
static void __pmu_switch_to_host(void)
{
	struct kvm_pmu_events *pmu = __hyp_this_cpu_ptr(kvm_pmu_events);

	if (pmu->events_guest)
		write_sysreg(pmu->events_guest, pmcntenclr_el0);

	if (pmu->events_host)
		write_sysreg(pmu->events_host, pmcntenset_el0);
}

static void __kvm_vcpu_switch_to_guest(struct kvm_vcpu *host_vcpu,
				       struct kvm_vcpu *vcpu)
{
	/*
	 * Having IRQs masked via PMR when entering the guest means the GIC
	 * will not signal the CPU of interrupts of lower priority, and the
	 * only way to get out will be via guest exceptions.
	 * Naturally, we want to avoid this.
	 */
	if (system_uses_irq_prio_masking()) {
		gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);
		pmr_sync();
	}

	__pmu_switch_to_guest();

	__timer_enable_traps(vcpu);
}

static void __kvm_vcpu_switch_to_host(struct kvm_vcpu *host_vcpu,
				      struct kvm_vcpu *vcpu)
{
	__timer_disable_traps(vcpu);

	__pmu_switch_to_host();

	/* Returning to host will clear PSR.I, remask PMR if needed */
	if (system_uses_irq_prio_masking())
		gic_write_pmr(GIC_PRIO_IRQOFF);
}

static void __vcpu_save_state(struct kvm_vcpu *vcpu, bool save_debug)
{
	__sysreg_save_state_nvhe(&vcpu->arch.ctxt);
	__sysreg32_save_state(vcpu);
	__hyp_vgic_save_state(vcpu);

	__fpsimd_save_fpexc32(vcpu);

	__debug_save_spe(vcpu);

	if (save_debug)
		__debug_save_state(kern_hyp_va(vcpu->arch.debug_ptr),
				   &vcpu->arch.ctxt);
}

static void __vcpu_restore_state(struct kvm_vcpu *vcpu, bool restore_debug)
{
	struct kvm_vcpu *running_vcpu;

	/*
	 * Restoration is not yet pure so it still makes use of the previously
	 * running vcpu.
	 */
	running_vcpu = __hyp_this_cpu_read(kvm_hyp_running_vcpu);

	if (vcpu->arch.ctxt.is_host)
		__kvm_vcpu_switch_to_host(vcpu, running_vcpu);
	else
		__kvm_vcpu_switch_to_guest(running_vcpu, vcpu);

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		u64 val;

		/*
		 * Set the TCR and SCTLR registers to prevent any stage 1 or 2
		 * page table walks or TLB allocations. A generous sprinkling
		 * of isb() ensure that things happen in this exact order.
		 */
		val = read_sysreg_el1(SYS_TCR);
		write_sysreg_el1(val | TCR_EPD1_MASK | TCR_EPD0_MASK, SYS_TCR);
		isb();
		val = read_sysreg_el1(SYS_SCTLR);
		write_sysreg_el1(val | SCTLR_ELx_M, SYS_SCTLR);
		isb();
	}

	/*
	 * We must restore the 32-bit state before the sysregs, thanks to
	 * erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 *
	 * Also, and in order to deal with the speculative AT errata, we must
	 * ensure the S2 translation is restored before allowing page table
	 * walks and TLB allocations when the sysregs are restored.
	 */
	__restore_stage2(vcpu);
	__sysreg32_restore_state(vcpu);
	__sysreg_restore_state_nvhe(&vcpu->arch.ctxt);

	if (vcpu->arch.ctxt.is_host)
		__deactivate_traps(vcpu, running_vcpu);
	else
		__activate_traps(vcpu);

	__hyp_vgic_restore_state(vcpu);

	/*
	 * This must come after restoring the sysregs since SPE may make use if
	 * the TTBRs.
	 */
	__debug_restore_spe(vcpu);

	if (restore_debug)
		__debug_restore_state(kern_hyp_va(vcpu->arch.debug_ptr),
				      &vcpu->arch.ctxt);

	*__hyp_this_cpu_ptr(kvm_hyp_running_vcpu) = vcpu;
}

/* Switch to the guest for legacy non-VHE systems */
int __kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *hyp_ctxt;
	struct kvm_vcpu *running_vcpu;
	u64 exit_code;

	hyp_ctxt = __hyp_this_cpu_ptr(kvm_hyp_ctxt);
	running_vcpu = __hyp_this_cpu_read(kvm_hyp_running_vcpu);

	if (running_vcpu != vcpu) {
		bool switch_debug;

		if (!running_vcpu->arch.ctxt.is_host &&
		    !vcpu->arch.ctxt.is_host) {
			/*
			 * There are still assumptions that the switch will
			 * always be between a guest and the host so double
			 * check that is the case. If it isn't, pretending
			 * there was an interrupt is a harmless way to bail.
			 */
			return ARM_EXCEPTION_IRQ;
		}

		switch_debug = (vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY) &&
			(running_vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY);

		__vcpu_save_state(running_vcpu, switch_debug);
		__vcpu_restore_state(vcpu, switch_debug);
	}

	__set_vcpu_arch_workaround_state(vcpu);

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(vcpu, hyp_ctxt);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));

	__set_hyp_arch_workaround_state(vcpu);

	return exit_code;
}

void __noreturn hyp_panic(void)
{
	u64 spsr = read_sysreg_el2(SYS_SPSR);
	u64 elr = read_sysreg_el2(SYS_ELR);
	u64 par = read_sysreg(par_el1);
	struct kvm_vcpu *host_vcpu = __hyp_this_cpu_ptr(kvm_host_vcpu);
	struct kvm_vcpu *vcpu = __hyp_this_cpu_read(kvm_hyp_running_vcpu);
	unsigned long str_va;

	if (vcpu != host_vcpu) {
		__timer_disable_traps(vcpu);
		__deactivate_traps(host_vcpu, vcpu);
		__restore_stage2(host_vcpu);
		__sysreg_restore_state_nvhe(&host_vcpu->arch.ctxt);
	}

	/*
	 * Force the panic string to be loaded from the literal pool,
	 * making sure it is a kernel address and not a PC-relative
	 * reference.
	 */
	asm volatile("ldr %0, =%1" : "=r" (str_va) : "S" (__hyp_panic_string));

	__hyp_do_panic(str_va,
		       spsr, elr,
		       read_sysreg(esr_el2), read_sysreg_el2(SYS_FAR),
		       read_sysreg(hpfar_el2), par, vcpu);
	unreachable();
}

asmlinkage void kvm_unexpected_el2_exception(void)
{
	return __kvm_unexpected_el2_exception();
}
