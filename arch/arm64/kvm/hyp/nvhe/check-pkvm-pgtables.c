
// PS HACK

// toying with using a native EL2 address translation C executable
// "spec" to express a property of the state established by the pKVM
// initialisation, in a style that could easily be used by the pKVM devs.

// We might be able to check that something like this "semantics" of
// address translation is equivalent to the Armv8-A ASL definition
// (under a raft of system-state assumptions appropriate to pKVM)
// simply by using isla on the compiled binary and asking an SMT
// solver - after unfolding everything, there wouldn't be that many
// cases.

// And we might be able to prove in RefinedC / CN that the actual
// page-table setup, done by pKVM in setup.c recreate_hyp_mappings
// using hyp_create_mappings using kvm_pgtable_hyp_map, establishes
// this.

// How we design the refinement-type assertion language(s) to make it
// easy to express this kind of thing in a way that can easily be
// shown to correspond to this executable C version is an interesting
// question...

// Note that as written this checks a sample minimal fact about pKVM's
// own putative mapping at hyp_pgtable, not whatever is installed in
// TTBR0_EL2, so it's suitable for use _before_ the idmap tango, not
// necessarily after.
// 
// Note that it reads pagetable contents just using the current
// mapping, whatever that is. 

#include <asm/kvm_pgtable.h>
#include <asm/kvm_asm.h>
#include <nvhe/memory.h>
#include <nvhe/mm.h>
#include <linux/bits.h>




/* ************************************************************************** */
/* 
 * experiment in style: sketching a C-executable "semantics" of
 * Armv8-A page tables, (very) loosely following the Arm ARM ASL
 * definition but missing out most of the details, in a pure-ish
 * style.
 */

// I've made the types follow the ASL, modulo embedding bitvectors into uint64_t

enum Fault {
  Fault_None,
  Fault_AccessFlag,
  Fault_Alignment,
  Fault_Background,
  Fault_Domain,
  Fault_Permission,
  Fault_Translation,
  Fault_AddressSize,
  Fault_SyncExternal,
  Fault_SyncExternalOnWalk,
  Fault_SyncParity,
  Fault_SyncParityOnWalk,
  Fault_AsyncParity,
  Fault_AsyncExternal,
  Fault_Debug,
  Fault_TLBConflict,
  Fault_BranchTarget,
  Fault_HWUpdateAccessFlag,
  Fault_Lockdown,
  Fault_Exclusive,
  Fault_ICacheMaint
};

struct FaultRecord {
  enum Fault statuscode; // Fault Status
  //  AccType acctype; // Type of access that faulted
  //  FullAddress ipaddress; // Intermediate physical address
  //  boolean s2fs1walk; // Is on a Stage 1 page table walk
  //  boolean write; // TRUE for a write, FALSE for a read
  //  integer level; // For translation, access flag and permission faults
  //  bit extflag; // IMPLEMENTATION DEFINED syndrome for external aborts
  //  boolean secondstage; // Is a Stage 2 abort
  //  bits(4) domain; // Domain number, AArch32 only
  //  bits(2) errortype; // [Armv8.2 RAS] AArch32 AET or AArch64 SET
  //  bits(4) debugmoe; // Debug method of entry, from AArch32 only
};

struct FullAddress {
  uint64_t address; // bits(52) address;
  bool NS;          // bit NS; // '0' = Secure, '1' = Non-secure
};

struct AddressDescriptor {
  struct FaultRecord fault; // fault.statuscode indicates whether the address is valid
  //  MemoryAttributes memattrs;
  struct FullAddress paddress;
  uint64_t vaddress; // bits(64) vaddress;
};

//struct Permissions {
// bits(3) ap; // Access permission bits
// bit xn; // Execute-never bit
// bit xxn; // [Armv8.2] Extended execute-never bit for stage 2
// bit pxn // Privileged execute-never bit
//}

struct TLBRecord {
  //  Permissions        perms;	    
  //  bit 	             nG;	   // '0' = Global, '1' = not Global				
  //  bits(4)	     domain;	   // AArch32 only						
  //  bit		     GP;	   // Guarded Page						
  //  boolean	     contiguous;   // Contiguous bit from page table				
  //  integer	     level;	   // AArch32 Short-descriptor format: Indicates Section/Page	
  //  integer	     blocksize;    // Describes size of memory translated in KBytes		
  //  DescriptorUpdate   descupdate;   // [Armv8.1] Context for h/w update of table descriptor	
  //  bit		     CnP;	   // [Armv8.2] TLB entry can be shared between different PEs 
  struct AddressDescriptor  addrdesc;    
};


// aarch64/translation/walk/AArch64.TranslationTableWalk
// AArch64.TranslationTableWalk()
// ==============================
// Returns a result of a translation table walk
// Implementations might cache information from memory in any number of non-coherent TLB
// caching structures, and so avoid memory accesses that have been expressed in this
// pseudocode. The use of such TLBs is not expressed in this pseudocode.
// TLBRecord AArch64.TranslationTableWalk(bits(52) ipaddress, boolean s1_nonsecure, bits(64) vaddress, AccType acctype, boolean iswrite, boolean secondstage, boolean s2fs1walk, integer size)

// There's a lot of detailed code here, but most relates to options
// that I think are irrelevant for us. The actual walk is the repeat
// loop on p7729-7730.  For now, I'll try for something clean that
// handles only the basic VA->PA part, ignoring attributes etc., not
// to follow the ASL closely.

// I've done this recursively, but we might well want to unfold
// explicitly, eg to more easily check the correspondence between
// the ASL and the compiled implementation of this

struct TLBRecord mkFault(uint64_t vaddress) {
  struct TLBRecord r = { .addrdesc = { .fault = { .statuscode=Fault_Translation } , .paddress =  { .address=0, .NS=0 }, .vaddress = vaddress } };
  return r;
  // oversimplified
}


struct TLBRecord mkTranslation(uint64_t vaddress, uint64_t pa) {
  struct TLBRecord r = { .addrdesc = { .fault = { .statuscode=Fault_None } , .paddress =  { .address=pa, .NS=1 }, .vaddress = vaddress } };
  return r;
  // oversimplified
}


#define ENTRY_INVALID_0 0
#define ENTRY_INVALID_2 2
#define ENTRY_BLOCK 1
#define ENTRY_PAGE_DESCRIPTOR 3
#define ENTRY_TABLE 3

struct TLBRecord AArch64_TranslationTableWalk( uint64_t table_base, uint64_t level, uint64_t vaddress);

struct TLBRecord AArch64_TranslationTableWalk( uint64_t table_base, uint64_t level, uint64_t vaddress) {
  // these two should be combined with their initialisations below, but
  // the compiler complains that ISO C90 forbids mixed declations and
  // code
  uint64_t pte;            
  uint64_t table_base_next;
	      
  uint64_t offset = 0; // offset in bytes of entry from table_base
  switch (level) {
  case 0: offset = (vaddress & GENMASK(47,39)) >> (39-3); break;
  case 1: offset = (vaddress & GENMASK(38,30)) >> (30-3); break;
  case 2: offset = (vaddress & GENMASK(29,21)) >> (21-3); break;
  case 3: offset = (vaddress & GENMASK(20,12)) >> (12-3); break;
  default: return mkFault(vaddress); // this is just to tell the compiler that the cases are exhaustive
  }

  // the actual page table entry
  pte = *((uint64_t*)(table_base + offset));

  switch(level)
    {
    case 3: 
      switch (pte & GENMASK(1,0))
	{
	case ENTRY_INVALID_0:
	case ENTRY_INVALID_2:
	case ENTRY_BLOCK:
	  // invalid or fault entry
	  return mkFault(vaddress); 
	case ENTRY_PAGE_DESCRIPTOR: // page descriptor
	  return mkTranslation(vaddress, (pte & GENMASK(47,12)) | (vaddress & GENMASK(11,0)));
	}
    
    case 0:
    case 1:
    case 2:
      {
	switch (pte & GENMASK(1,0))
	  {
	  case ENTRY_INVALID_0: 
	  case ENTRY_INVALID_2:
	    return mkFault(vaddress); 
	  case ENTRY_BLOCK:
	    switch (level)
	      {
	      case 0:
		return mkFault(vaddress); 
	      case 1:
		return mkTranslation(vaddress, (pte & GENMASK(47,30)) | (vaddress & GENMASK(29,0)));
	      case 2:
		return mkTranslation(vaddress, (pte & GENMASK(47,21)) | (vaddress & GENMASK(20,0)));
	      }
	  case ENTRY_TABLE: // recurse
	    {
	      table_base_next = pte & GENMASK(47,12); 
	      return AArch64_TranslationTableWalk(table_base_next, level+1, vaddress);
	    }
	  }
      }
    default: return mkFault(vaddress); // this is just to tell the compiler that the cases are exhaustive
    }
}

      
// struct TLBRecord AArch64_TranslationTableWalk(uint64_t vaddress) {
//  uint64_t inputsize = 48;         // input address zie in bits
//  uint64_t grainsize = 12;         // log2(Size of Table) 4kb granules, TCR_EL2.TG0, bits[15:14] = 0b00
//  uint64_t firstblocklevel = 1;    // first level where a block entry is allowed
//  uint64_t stride = grainsize - 3; // bits of address consumed at each level
//  uint64_t level = 0;  // 4 - (1+((inputsize - grainsize - 1) DIV stride)); //  4-(1+((48-12-1) DIV 9))  The starting level is the number of strides needed to consume the input address
//  uint64_t outputsize = 48;        // PS guess

  
  
// aarch64/translation/translation/AArch64.FirstStageTranslate
// AArch64.FirstStageTranslate()
// =============================
// Perform a stage 1 translation walk. The function used by Address Translation operations is
// similar except it uses the translation regime specified for the instruction.
// AddressDescriptor AArch64.FirstStageTranslate(bits(64) vaddress, AccType acctype, boolean iswrite, boolean wasaligned, integer size)



  
struct AddressDescriptor AArch64_FirstStageTranslate(uint64_t table_base, uint64_t vaddress /*, AccType acctype, boolean iswrite, boolean wasaligned, integer size*/) {

  /* S1 = AArch64.TranslationTableWalk(ipaddress, TRUE, vaddress, acctype, iswrite, secondstage, s2fs1walk, size); */
  struct TLBRecord S1 = AArch64_TranslationTableWalk(table_base, 0, vaddress); 
    
  return S1.addrdesc;
}






/* ************************************************************************** */
/* using the above to sketch an assertion for the state established by pKVM initialisation */




_Bool _check_hyp_mapping(struct kvm_pgtable *pgt, void *virt, phys_addr_t phys, enum kvm_pgtable_prot prot)
{
  /** from kvm_pgtable.h, pgt has (among other members which aren't relevant here):
   * @ia_bits:		Maximum input address size, in bits.
   * @start_level:	Level at which the page-table walk starts.
   * @pgd:		Pointer to the first top-level entry of the page-table.
   */
  
  struct AddressDescriptor ad = AArch64_FirstStageTranslate((uint64_t)pgt->pgd, (uint64_t)virt);
  
  switch (ad.fault.statuscode)
    {
    case Fault_None:
      return (ad.paddress.address == phys);
    default:
      return false;
    }
}

_Bool check_hyp_mapping(void *from, void *to, enum kvm_pgtable_prot prot)
{
  // just check the first address for now (aligned in the same way as hyp_create_mappings) - later, the first address of each page
  unsigned long virt_addr = (unsigned long)from & PAGE_MASK;
  void * virt = (void*)virt_addr;
  phys_addr_t phys = hyp_virt_to_phys(virt);
  struct kvm_pgtable *pgt = &hyp_pgtable; 
  _Bool ret = _check_hyp_mapping(pgt, virt, phys, prot);
  return ret;
}
  
  
_Bool check_hyp_mappings(void)
{
  _Bool ret = check_hyp_mapping(hyp_symbol_addr(__hyp_text_start),
				hyp_symbol_addr(__hyp_text_end),
				PAGE_HYP_EXEC);
  return ret;
}
