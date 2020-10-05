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

typedef __noreturn unsigned long (*stub_hvc_handler_t)
	(unsigned long, unsigned long, unsigned long, unsigned long,
	 unsigned long, struct kvm_cpu_context *);

extern char __kvm_handle_stub_hvc_soft_restart[];
extern char __kvm_handle_stub_hvc_reset_vectors[];

static void handle_stub_hvc(unsigned long func_id, struct kvm_vcpu *host_vcpu)
{
	char *stub_hvc_handler_kern_va;
	stub_hvc_handler_t stub_hvc_handler;

	/*
	 * The handlers of the supported stub HVCs disable the MMU so they must
	 * be called in the idmap. We compute the idmap address by subtracting
	 * kimage_voffset from the kernel VA handler.
	 */
	switch (func_id) {
	case HVC_SOFT_RESTART:
		asm volatile("ldr %0, =%1"
			     : "=r" (stub_hvc_handler_kern_va)
			     : "S" (__kvm_handle_stub_hvc_soft_restart));
		break;
	case HVC_RESET_VECTORS:
		asm volatile("ldr %0, =%1"
			     : "=r" (stub_hvc_handler_kern_va)
			     : "S" (__kvm_handle_stub_hvc_reset_vectors));
		break;
	default:
		vcpu_set_reg(host_vcpu, 0, HVC_STUB_ERR);
		return;
	}

	stub_hvc_handler = (stub_hvc_handler_t)
		(stub_hvc_handler_kern_va - kimage_voffset);

	/* Preserve x0-x4, which may contain stub parameters. */
	stub_hvc_handler(func_id,
			 vcpu_get_reg(host_vcpu, 1),
			 vcpu_get_reg(host_vcpu, 2),
			 vcpu_get_reg(host_vcpu, 3),
			 vcpu_get_reg(host_vcpu, 4),
			 &host_vcpu->arch.ctxt);
}

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

			__kvm_tlb_flush_vmid_ipa(kern_hyp_va(mmu), ipa, level);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_tlb_flush_vmid): {
			struct kvm_s2_mmu *mmu =
				(struct kvm_s2_mmu *)smccc_get_arg1(host_vcpu);

			__kvm_tlb_flush_vmid(kern_hyp_va(mmu));
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_tlb_flush_local_vmid): {
			struct kvm_s2_mmu *mmu =
				(struct kvm_s2_mmu *)smccc_get_arg1(host_vcpu);

			__kvm_tlb_flush_local_vmid(kern_hyp_va(mmu));
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

			ret = __kvm_vcpu_run(kern_hyp_va(vcpu));
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

			__vgic_v3_save_aprs(kern_hyp_va(cpu_if));
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_restore_aprs): {
			struct vgic_v3_cpu_if *cpu_if =
				(struct vgic_v3_cpu_if *)smccc_get_arg1(host_vcpu);

			__vgic_v3_restore_aprs(kern_hyp_va(cpu_if));
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

		if (func_id < HVC_STUB_HCALL_NR)
			handle_stub_hvc(func_id, host_vcpu);
		else
			handle_host_hcall(func_id, host_vcpu);
	}

	/* Other traps are ignored. */
}

void __noreturn kvm_hyp_main(void)
{
	/* Set tpidr_el2 for use by HYP */
	struct kvm_vcpu *host_vcpu;

	host_vcpu = __hyp_this_cpu_ptr(kvm_host_vcpu);

	kvm_init_host_cpu_context(&host_vcpu->arch.ctxt);

	host_vcpu->arch.flags = KVM_ARM64_HOST_VCPU_FLAGS;
	host_vcpu->arch.workaround_flags = VCPU_WORKAROUND_2_FLAG;

	/*
	 * The first time entering the host is seen by the host as the return
	 * of the initialization HVC so mark it as successful.
	 */
	smccc_set_retval(host_vcpu, SMCCC_RET_SUCCESS, 0, 0, 0);

	/* The host is already loaded so note it as the running vcpu. */
	*__hyp_this_cpu_ptr(kvm_hyp_running_vcpu) = host_vcpu;

	while (true) {
		u64 exit_code;

		/* Enter the host now that we feel like we're in charge. */
		exit_code = __kvm_vcpu_run(host_vcpu);

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
