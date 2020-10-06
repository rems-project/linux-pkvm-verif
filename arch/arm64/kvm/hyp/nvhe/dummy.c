// Dummy definitions to produce a fully linked EL2 binary for analysis.

#define KVM_NVHE_ALIAS(sym)	unsigned long sym

// XXX: Following imported from image-vars.h

/*
 * KVM nVHE code has its own symbol namespace prefixed with __kvm_nvhe_, to
 * separate it from the kernel proper. The following symbols are legally
 * accessed by it, therefore provide aliases to make them linkable.
 * Do not include symbols which may not be safely accessed under hypervisor
 * memory mappings.
 */

/* Alternative callbacks for init-time patching of nVHE hyp code. */
KVM_NVHE_ALIAS(kvm_patch_vector_branch);
KVM_NVHE_ALIAS(kvm_update_va_mask);
KVM_NVHE_ALIAS(kvm_update_kimg_phys_offset);
KVM_NVHE_ALIAS(kvm_get_kimage_voffset);

/* Global kernel state accessed by nVHE hyp code. */
KVM_NVHE_ALIAS(kvm_vgic_global_state);

/* Kernel symbols used to call panic() from nVHE hyp code (via ERET). */
KVM_NVHE_ALIAS(__hyp_panic_string);
KVM_NVHE_ALIAS(panic);

/* Vectors installed by hyp-init on reset HVC. */
KVM_NVHE_ALIAS(__hyp_stub_vectors);

/* Kernel symbol used by icache_is_vpipt(). */
KVM_NVHE_ALIAS(__icache_flags);

/* Kernel symbols needed for cpus_have_final/const_caps checks. */
KVM_NVHE_ALIAS(arm64_const_caps_ready);
KVM_NVHE_ALIAS(cpu_hwcap_keys);

/* Static keys which are set if a vGIC trap should be handled in hyp. */
KVM_NVHE_ALIAS(vgic_v2_cpuif_trap);
KVM_NVHE_ALIAS(vgic_v3_cpuif_trap);

/* Static key checked in pmr_sync(). */
#ifdef CONFIG_ARM64_PSEUDO_NMI
KVM_NVHE_ALIAS(gic_pmr_sync);
#endif
/* Static key checked in GIC_PRIO_IRQOFF. */
KVM_NVHE_ALIAS(gic_nonsecure_priorities);

/* EL2 exception handling */
KVM_NVHE_ALIAS(__start___kvm_ex_table);
KVM_NVHE_ALIAS(__stop___kvm_ex_table);

/* Array containing bases of nVHE per-CPU memory regions. */
KVM_NVHE_ALIAS(kvm_arm_hyp_percpu_base);

/* Hypevisor VA size */
KVM_NVHE_ALIAS(hyp_va_bits);

/* Kernel memory sections */
KVM_NVHE_ALIAS(__start_rodata);
KVM_NVHE_ALIAS(__end_rodata);
KVM_NVHE_ALIAS(__bss_start);
KVM_NVHE_ALIAS(__bss_stop);

/* Hyp memory sections */
KVM_NVHE_ALIAS(__hyp_idmap_text_start);
KVM_NVHE_ALIAS(__hyp_idmap_text_end);
KVM_NVHE_ALIAS(__hyp_text_start);
KVM_NVHE_ALIAS(__hyp_text_end);
KVM_NVHE_ALIAS(__hyp_data_ro_after_init_start);
KVM_NVHE_ALIAS(__hyp_data_ro_after_init_end);
KVM_NVHE_ALIAS(__hyp_bss_start);
KVM_NVHE_ALIAS(__hyp_bss_end);

/* pKVM static key */
KVM_NVHE_ALIAS(kvm_protected_mode_initialized);

#ifdef CONFIG_KVM_ARM_HYP_DEBUG_UART
KVM_NVHE_ALIAS(kvm_hyp_debug_uart_set_basep);
#endif

/* Only needed to link when built at -O0 */
KVM_NVHE_ALIAS(sve_load_state);
KVM_NVHE_ALIAS(sve_save_state);
KVM_NVHE_ALIAS(cpu_hwcaps);
