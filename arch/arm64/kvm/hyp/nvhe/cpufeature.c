// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#define KVM_HYP_CPU_FTR_REG(id, name) struct arm64_ftr_reg name;
#include <asm/kvm_cpufeature.h>
