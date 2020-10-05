// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <hyp/switch.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#include <kvm/arm_hypercalls.h>

static void handle_host_hcall(unsigned long func_id, struct kvm_vcpu *host_vcpu)
{
	unsigned long ret = 0;

	switch (func_id) {
	case KVM_HOST_SMCCC_FUNC(__kvm_flush_vm_context):
		__kvm_flush_vm_context();
		break;
	case KVM_HOST_SMCCC_FUNC(__kvm_tlb_flush_vmid_ipa): {
			struct kvm_s2_mmu *mmu =
				(struct kvm_s2_mmu *)smccc_get_arg1(host_vcpu);
			phys_addr_t ipa = smccc_get_arg2(host_vcpu);
			int level = smccc_get_arg3(host_vcpu);

			__kvm_tlb_flush_vmid_ipa(mmu, ipa, level);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_tlb_flush_vmid): {
			struct kvm_s2_mmu *mmu =
				(struct kvm_s2_mmu *)smccc_get_arg1(host_vcpu);

			__kvm_tlb_flush_vmid(mmu);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_tlb_flush_local_vmid): {
			struct kvm_s2_mmu *mmu =
				(struct kvm_s2_mmu *)smccc_get_arg1(host_vcpu);

			__kvm_tlb_flush_local_vmid(mmu);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_timer_set_cntvoff): {
			u64 cntvoff = smccc_get_arg1(host_vcpu);

			__kvm_timer_set_cntvoff(cntvoff);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_vcpu_run): {
			struct kvm_vcpu *vcpu =
				(struct kvm_vcpu *)smccc_get_arg1(host_vcpu);

			ret = __kvm_vcpu_run(vcpu);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_enable_ssbs):
		__kvm_enable_ssbs();
		break;
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_get_ich_vtr_el2):
		ret = __vgic_v3_get_ich_vtr_el2();
		break;
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_read_vmcr):
		ret = __vgic_v3_read_vmcr();
		break;
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_write_vmcr): {
			u32 vmcr = smccc_get_arg1(host_vcpu);

			__vgic_v3_write_vmcr(vmcr);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_init_lrs):
		__vgic_v3_init_lrs();
		break;
	case KVM_HOST_SMCCC_FUNC(__kvm_get_mdcr_el2):
		ret = __kvm_get_mdcr_el2();
		break;
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_save_aprs): {
			struct vgic_v3_cpu_if *cpu_if =
				(struct vgic_v3_cpu_if *)smccc_get_arg1(host_vcpu);

			__vgic_v3_save_aprs(cpu_if);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_restore_aprs): {
			struct vgic_v3_cpu_if *cpu_if =
				(struct vgic_v3_cpu_if *)smccc_get_arg1(host_vcpu);

			__vgic_v3_restore_aprs(cpu_if);
			break;
		}
	default:
		/* Invalid host HVC. */
		smccc_set_retval(host_vcpu, SMCCC_RET_NOT_SUPPORTED, 0, 0, 0);
		return;
	}

	smccc_set_retval(host_vcpu, SMCCC_RET_SUCCESS, ret, 0, 0);
}

static void handle_trap(struct kvm_vcpu *host_vcpu) {
	if (kvm_vcpu_trap_get_class(host_vcpu) == ESR_ELx_EC_HVC64) {
		unsigned long func_id = smccc_get_function(host_vcpu);

		handle_host_hcall(func_id, host_vcpu);
	}

	/* Other traps are ignored. */
}

void __noreturn kvm_hyp_main(void)
{
	/* Set tpidr_el2 for use by HYP */
	struct kvm_vcpu *host_vcpu;
	struct kvm_cpu_context *hyp_ctxt;

	host_vcpu = __hyp_this_cpu_ptr(kvm_host_vcpu);
	hyp_ctxt = &__hyp_this_cpu_ptr(kvm_host_data)->host_ctxt;

	kvm_init_host_cpu_context(&host_vcpu->arch.ctxt);

	host_vcpu->arch.flags = KVM_ARM64_HOST_VCPU_FLAGS;
	host_vcpu->arch.workaround_flags = VCPU_WORKAROUND_2_FLAG;

	/*
	 * The first time entering the host is seen by the host as the return
	 * of the initialization HVC so mark it as successful.
	 */
	smccc_set_retval(host_vcpu, SMCCC_RET_SUCCESS, 0, 0, 0);

	while (true) {
		u64 exit_code;

		/*
		 * Set the running cpu for the vectors to pass to __guest_exit
		 * so it can get the cpu context.
		 */
		*__hyp_this_cpu_ptr(kvm_hyp_running_vcpu) = host_vcpu;

		/*
		 * Enter the host now that we feel like we're in charge.
		 *
		 * This should merge with __kvm_vcpu_run as host becomes more
		 * vcpu-like.
		 */
		do {
			exit_code = __guest_enter(host_vcpu, hyp_ctxt);
		} while (fixup_guest_exit(host_vcpu, &exit_code));

		switch (ARM_EXCEPTION_CODE(exit_code)) {
		case ARM_EXCEPTION_TRAP:
			handle_trap(host_vcpu);
			break;
		case ARM_EXCEPTION_IRQ:
		case ARM_EXCEPTION_EL1_SERROR:
		case ARM_EXCEPTION_IL:
		default:
			/*
			 * These cases are not expected to be observed for the
			 * host so, in the event that they are seen, take a
			 * best-effort approach to keep things going.
			 *
			 * Ok, our expended effort comes to a grand total of
			 * diddly squat but the internet protocol has gotten
			 * away with the "best-effort" euphemism so we can too.
			 */
			break;
		}

	}
}
