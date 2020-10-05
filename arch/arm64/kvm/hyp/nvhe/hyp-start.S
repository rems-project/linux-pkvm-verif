/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_ptrauth.h>

/*
 * Initialize ptrauth in the hyp ctxt by populating it with the keys of the
 * host, which are the keys currently installed.
 */
.macro ptrauth_hyp_ctxt_init hyp_ctxt, reg1, reg2, reg3
#ifdef CONFIG_ARM64_PTR_AUTH
alternative_if_not ARM64_HAS_ADDRESS_AUTH
	b	.L__skip_switch\@
alternative_else_nop_endif
	add	\reg1, \hyp_ctxt, #CPU_APIAKEYLO_EL1
	ptrauth_save_state	\reg1, \reg2, \reg3
.L__skip_switch\@:
#endif
.endm

SYM_CODE_START(__kvm_hyp_start)
	get_host_ctxt	x0, x1

	ptrauth_hyp_ctxt_init x0, x1, x2, x3

	/* Prepare a tail call from __guest_exit to kvm_hyp_main */
	adr	x1, kvm_hyp_main
	str	x1, [x0, #CPU_LR_OFFSET]

	/*
	 * The host's x0 and x1 are expected on the stack but they will be
	 * clobbered so there's no need to load real values.
	 */
	sub	sp, sp, 16

	hyp_adr_this_cpu x1, kvm_host_vcpu, x0
	mov	x0, #ARM_EXCEPTION_TRAP
	b	__guest_exit
SYM_CODE_END(__kvm_hyp_start)
