
// PS HACK
// toying with a native EL2 address translation C executable "spec"

#include <asm/kvm_pgtable.h>
#include <asm/kvm_asm.h>
#include <nvhe/memory.h>
#include <nvhe/mm.h>

int _check_hyp_mapping(struct kvm_pgtable *pgt, void *virt, phys_addr_t phys, enum kvm_pgtable_prot prot)
{
  /** from kvm_pgtable.h, pgt has (among other members which aren't relevant here):
   * @ia_bits:		Maximum input address size, in bits.
   * @start_level:	Level at which the page-table walk starts.
   * @pgd:		Pointer to the first top-level entry of the page-table.
   */
  

  
  return 0;
}

int check_hyp_mapping(void *from, void *to, enum kvm_pgtable_prot prot)
{
  // just check the first address for now (aligned in the same way as hyp_create_mappings) - later, the first address of each page
  unsigned long virt_addr = (unsigned long)from & PAGE_MASK;
  void * virt = (void*)virt_addr;
  phys_addr_t phys = hyp_virt_to_phys(virt);
  struct kvm_pgtable *pgt = &hyp_pgtable; 
  int ret = _check_hyp_mapping(pgt, virt, phys, prot);
  return ret;
}
  
  
int check_hyp_mappings(void)
{
  int ret = 0;
  ret = check_hyp_mapping(hyp_symbol_addr(__hyp_text_start),
			  hyp_symbol_addr(__hyp_text_end),
			  PAGE_HYP_EXEC);
  return ret;
}
