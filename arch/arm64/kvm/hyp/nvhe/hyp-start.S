/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <linux/linkage.h>

#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_asm.h>

SYM_CODE_START(__kvm_hyp_start)
	/* Hello, World! */
	eret
SYM_CODE_END(__kvm_hyp_start)
