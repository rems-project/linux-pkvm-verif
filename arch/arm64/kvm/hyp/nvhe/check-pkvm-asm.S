#include <asm/asm-offsets.h>
#include <linux/linkage.h>	

// PS HACK: snapshot the main EL2 system registers into a struct kvm_nvhe_init_params struct as defined in kvm_asm.h.  Call with a pointer to that struct in x0
	
	SYM_CODE_START(___kvm_get_sysregs)

	mrs	x1, tpidr_el2
	str	x1, [x0, #NVHE_INIT_TPIDR_EL2]

	mov	x1, sp
	str	x1, [x0, #NVHE_INIT_STACK_HYP_VA]

	mrs	x1, mair_el2
	str	x1, [x0, #NVHE_INIT_MAIR_EL2]

	mrs	x1, hcr_el2
	str	x1, [x0, #NVHE_INIT_HCR_EL2]

	mrs	x1, vttbr_el2
	str	x1, [x0, #NVHE_INIT_VTTBR]

	mrs	x1, vtcr_el2
	str	x1, [x0, #NVHE_INIT_VTCR]

	mrs	x1, ttbr0_el2
	str	x1, [x0, #NVHE_INIT_PGD_PA]

	mrs	x1, tcr_el2
	str	x1, [x0, #NVHE_INIT_TCR_EL2]

	ret
	
	SYM_CODE_END(___kvm_get_sysregs)
 
