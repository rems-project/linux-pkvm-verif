#ifndef __KVM_HYP_MM_H
#define __KVM_HYP_MM_H

#include <asm/kvm_pgtable.h>
#include <linux/types.h>
#include <nvhe/spinlock.h>

extern struct hyp_pool hpool;
extern struct kvm_pgtable hyp_pgtable;
extern phys_addr_t __phys_hyp_pgd;
extern nvhe_spinlock_t __hyp_pgd_lock;
extern u64 __io_map_base;
extern void *kvm_hyp_stacks[];
extern u32 hyp_va_bits;

int hyp_create_idmap(void);
int hyp_back_vmemmap_early(phys_addr_t phys, unsigned long size);
int __hyp_create_mappings(unsigned long start, unsigned long size,
			  unsigned long phys, unsigned long prot);
unsigned long __hyp_create_private_mapping(phys_addr_t phys, size_t size,
					 unsigned long prot);
int hyp_create_mappings(void *from, void *to, enum kvm_pgtable_prot prot);
static inline unsigned long hyp_create_private_mapping(phys_addr_t phys,
						       size_t size,
						       enum kvm_pgtable_prot prot)
{
	return __hyp_create_private_mapping(phys, size, prot);
}
#endif /* __KVM_HYP_MM_H */
