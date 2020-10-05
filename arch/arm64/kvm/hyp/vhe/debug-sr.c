// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <hyp/debug-sr.h>

#include <linux/kvm_host.h>

#include <asm/kvm_hyp.h>

void __debug_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	struct kvm_guest_debug_arch *host_dbg;
	struct kvm_guest_debug_arch *guest_dbg;

	if (!(vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY))
		return;

	host_ctxt = __hyp_this_cpu_ptr(kvm_host_ctxt);
	host_dbg = __hyp_this_cpu_ptr(kvm_host_debug_state);

	guest_ctxt = &vcpu->arch.ctxt;
	guest_dbg = kern_hyp_va(vcpu->arch.debug_ptr);

	__debug_save_state(host_dbg, host_ctxt);
	__debug_restore_state(guest_dbg, guest_ctxt);
}

void __debug_switch_to_host(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	struct kvm_guest_debug_arch *host_dbg;
	struct kvm_guest_debug_arch *guest_dbg;

	if (!(vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY))
		return;

	host_ctxt = __hyp_this_cpu_ptr(kvm_host_ctxt);
	host_dbg = __hyp_this_cpu_ptr(kvm_host_debug_state);

	guest_ctxt = &vcpu->arch.ctxt;
	guest_dbg = kern_hyp_va(vcpu->arch.debug_ptr);

	__debug_save_state(guest_dbg, guest_ctxt);
	__debug_restore_state(host_dbg, host_ctxt);
}

u32 __kvm_get_mdcr_el2(void)
{
	return read_sysreg(mdcr_el2);
}
