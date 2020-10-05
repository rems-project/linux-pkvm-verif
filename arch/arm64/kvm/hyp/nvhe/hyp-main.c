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

typedef unsigned long (*hypcall_fn_t)
	(unsigned long, unsigned long, unsigned long);

static void handle_trap(struct kvm_vcpu *host_vcpu) {
	if (kvm_vcpu_trap_get_class(host_vcpu) == ESR_ELx_EC_HVC64) {
		hypcall_fn_t func;
		unsigned long ret;

		/*
		 * __kvm_call_hyp takes a pointer in the host address space and
		 * up to three arguments.
		 */
		func = (hypcall_fn_t)kern_hyp_va(vcpu_get_reg(host_vcpu, 0));
		ret = func(vcpu_get_reg(host_vcpu, 1),
			   vcpu_get_reg(host_vcpu, 2),
			   vcpu_get_reg(host_vcpu, 3));
		vcpu_set_reg(host_vcpu, 0, ret);
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
