
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
//#include <asm/kvm_asm.h>
//#include <nvhe/memory.h>
#include <nvhe/mm.h>
#include <linux/bits.h>

#include <asm/kvm_mmu.h>
#include <../debug-pl011.h>


// copied from setup.c
#define hyp_percpu_size ((unsigned long)__per_cpu_end - \
			 (unsigned long)__per_cpu_start)


// horrible hack for max CPUs - later find out how to do this properly 
#define MAX_CPUS 8






/* ************************************************************************** */
/* 
 * experiment in style: pretty-print of Armv8-A page tables that can run in the EL2 code
 */

// "plain" versions of some debug-pl011.h functions, without the trailing \n
void hyp_putsp(char *s)
{
  while (*s)
    hyp_putc(*s++);
}

void hyp_putbool(_Bool b)
{
  if (b) hyp_putsp("true"); else hyp_putsp("false");
}


static inline void __hyp_putx4np(unsigned long x, int n)
{
	int i = n >> 2;

	hyp_putc('0');
	hyp_putc('x');

	while (i--)
		__hyp_putx4(x >> (4 * i));

}




void hyp_putsxn(char *s, unsigned long x, int n)
{
  hyp_putsp(s);
  hyp_putc(':');
  __hyp_putx4np(x,n);
  hyp_putc(' ');
}



// the logical entry kinds
enum entry_kind {
  EK_INVALID,
  EK_BLOCK,
  EK_TABLE,
  EK_PAGE_DESCRIPTOR,
  EK_BLOCK_NOT_PERMITTED,
  EK_RESERVED,
  EK_DUMMY
};

// the entry kind bit representations
#define ENTRY_INVALID_0 0
#define ENTRY_INVALID_2 2
#define ENTRY_BLOCK 1
#define ENTRY_RESERVED 1
#define ENTRY_PAGE_DESCRIPTOR 3
#define ENTRY_TABLE 3

// 
enum entry_kind entry_kind(kvm_pte_t pte, u8 level)
{
  switch(level)
    {
    case 0:
    case 1:
    case 2:
      {
	switch (pte & GENMASK(1,0))
	  {
	  case ENTRY_INVALID_0: 
	  case ENTRY_INVALID_2:
	    return EK_INVALID;
	  case ENTRY_BLOCK:
	    switch (level)
	      {
	      case 0:
		return EK_BLOCK_NOT_PERMITTED;
	      case 1:
	      case 2:
		return EK_BLOCK;
	      }
	  case ENTRY_TABLE: 
	    return EK_TABLE;
	  default:
	    return EK_DUMMY; // this is just to tell the compiler that the cases are exhaustive
	  }
      }
    case 3: 
      switch (pte & GENMASK(1,0))
	{
	case ENTRY_INVALID_0:
	case ENTRY_INVALID_2:
	  return EK_INVALID;
	case ENTRY_RESERVED:
	  return EK_RESERVED;
	case ENTRY_PAGE_DESCRIPTOR:
	  return EK_PAGE_DESCRIPTOR;
	}
    
    default:
      return EK_DUMMY; // this is just to tell the compiler that the cases are exhaustive
    }
}


void hyp_put_ek(enum entry_kind ek)
{
  switch(ek)
    {
    case EK_INVALID:               hyp_putsp("EK_INVALID");             break;
    case EK_BLOCK:		   hyp_putsp("EK_BLOCK");	       break;	 
    case EK_TABLE:		   hyp_putsp("EK_TABLE");	       break;	 
    case EK_PAGE_DESCRIPTOR:	   hyp_putsp("EK_PAGE_DESCRIPTOR");     break;	 
    case EK_BLOCK_NOT_PERMITTED:   hyp_putsp("EK_BLOCK_NOT_PERMITTED"); break;
    case EK_RESERVED:		   hyp_putsp("EK_RESERVED");	       break;	 
    case EK_DUMMY:                 hyp_putsp("EK_DUMMY");               break;
    }
}

void hyp_put_entry(kvm_pte_t pte, u8 level)
{
  enum entry_kind ek;
  ek = entry_kind(pte, level);       
  hyp_put_ek(ek); hyp_putsp(" ");
  switch(ek)
    {
    case EK_INVALID:               break;
    case EK_BLOCK:		   break;	 
    case EK_TABLE:		   break;	 
    case EK_PAGE_DESCRIPTOR:
      { u64 oa;
	oa = pte & GENMASK(47,12);
	hyp_putsxn("oa", oa, 64);
      }
      break;	 
    case EK_BLOCK_NOT_PERMITTED:   break;
    case EK_RESERVED:		   break;	 
    case EK_DUMMY:                 break;
    }

}



// dump page starting at pgd, and any sub-pages
void _dump_hyp_mappings(u64 *pgd, u8 level)
{
    u32 idx;
    if (pgd) {
      // dump this page
      hyp_putsxn("level",level,8);
      hyp_putsxn("table at virt", (u64)pgd, 64); hyp_puts("");
      for (idx = 0; idx < 512; idx++) {
	kvm_pte_t pte = pgd[idx];
	hyp_putsxn("level",level,8);
	hyp_putsxn("entry at virt",(u64)(pgd+idx),64);
	hyp_putsxn("raw",(u64)pte,64);
	hyp_put_entry(pte, level);
	hyp_puts("");
      }
      // dump any sub-pages
      for (idx = 0; idx < 512; idx++) {
	kvm_pte_t pte = pgd[idx];
	if (entry_kind(pte, level) == EK_TABLE) {
	  u64 next_level_phys_address, next_level_virt_address;
	  next_level_phys_address = pte & GENMASK(47,12);
	  next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
	  hyp_putsxn("table phys", next_level_phys_address, 64);
	  hyp_putsxn("table virt", next_level_virt_address, 64);
	  _dump_hyp_mappings((kvm_pte_t *)next_level_virt_address, level+1);
	  hyp_puts("");
	}
      }
    }
    else {
      hyp_puts("table address null");
    }
}


void dump_hyp_mappings(struct kvm_pgtable pg)
{
  hyp_putsxn("ia_bits", pg.ia_bits, 32);
  hyp_putsxn("ia_start_level", pg.start_level, 32);
  hyp_puts("");
  _dump_hyp_mappings(pg.pgd, pg.start_level);
  
  return;
}



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




struct TLBRecord AArch64_TranslationTableWalk( uint64_t table_base, uint64_t level, uint64_t vaddress);

struct TLBRecord AArch64_TranslationTableWalk( uint64_t table_base, uint64_t level, uint64_t vaddress) {
  // in pure-ish C style, these should really be combined with their
  // initialisations below, but the compiler complains that ISO C90
  // forbids mixed declations and code
  uint64_t pte;            
  uint64_t table_base_next_virt, table_base_next_phys;
	      
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
	      table_base_next_phys = pte & GENMASK(47,12); 
	      table_base_next_virt = (u64)hyp_phys_to_virt((phys_addr_t)table_base_next_phys);
	  
	      return AArch64_TranslationTableWalk(table_base_next_virt, level+1, vaddress);
	    }
	  default: return mkFault(vaddress); // this is just to tell the compiler that the cases are exhaustive
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

enum mapping_kind {
  HYP_NULL,
  HYP_TEXT,
  HYP_RODATA,
  HYP_RODATA2,
  HYP_BSS,
  HYP_BSS2,
  HYP_IDMAP,
  HYP_WORKSPACE,
  HYP_PERCPU,
  HYP_MAPPING_KIND_NUMBER=HYP_PERCPU + MAX_CPUS
};

#define DUMMY_CPU 0

struct mapping {
  char *doc;                        // documentation string
  enum mapping_kind kind;           
  u64 cpu;                          // cpu ID for HYP_PERCPU mappings; 0 otherwise
  u64 virt;                         // start pKVM EL2 after-the-switch virtual address, page-aligned
  phys_addr_t phys;                 // start physical address, page-aligned
  u64 size;                         // size, as the number of 4k pages
  enum kvm_pgtable_prot prot;       // protection
};

struct mapping mappings[HYP_MAPPING_KIND_NUMBER];

void hyp_put_prot(enum kvm_pgtable_prot prot)
{
  if (prot & KVM_PGTABLE_PROT_DEVICE) hyp_putc('D'); else hyp_putc('-');
  if (prot & KVM_PGTABLE_PROT_R) hyp_putc('R'); else hyp_putc('-');
  if (prot & KVM_PGTABLE_PROT_W) hyp_putc('W'); else hyp_putc('-');
  if (prot & KVM_PGTABLE_PROT_X) hyp_putc('X'); else hyp_putc('-');
  hyp_putsp(" ");
}

    
void hyp_put_mapping_kind(enum mapping_kind kind)
{
  switch (kind) {
  case HYP_TEXT:          hyp_putsp("HYP_TEXT     "); break;
  case HYP_RODATA:	  hyp_putsp("HYP_RODATA   "); break;
  case HYP_RODATA2:	  hyp_putsp("HYP_RODATA2  "); break;
  case HYP_BSS:	          hyp_putsp("HYP_BSS      "); break;
  case HYP_BSS2:	  hyp_putsp("HYP_BSS2     "); break;
  case HYP_IDMAP:	  hyp_putsp("HYP_IDMAP    "); break;
  case HYP_WORKSPACE:	  hyp_putsp("HYP_WORKSPACE"); break;
  default:
    if (kind >= HYP_PERCPU && kind < HYP_PERCPU + MAX_CPUS)
      {
	hyp_putsp("HYP_PERCPU   "); break;
      }
    else
      {
	hyp_putsp("unknown mapping kind"); break;
      }
  }
  hyp_putsp(" ");
}

void hyp_put_mapping(struct mapping *map)
{
  if (map->kind == HYP_NULL)
    hyp_putsp("HYP_MAPPING_NULL");
  else {
    hyp_putsxn("virt",map->virt,64);
    hyp_putsxn("phys",map->phys,64);
    hyp_putsxn("size",map->size,64);
    hyp_put_prot(map->prot);
    hyp_put_mapping_kind(map->kind);
    if (map->kind >= HYP_PERCPU && map->kind < HYP_PERCPU + MAX_CPUS) hyp_putsxn("cpu",map->cpu,64);
    hyp_putsp(map->doc);
  }
}

void hyp_put_mappings(void)
{
  int i;
  for (i=0; i<HYP_MAPPING_KIND_NUMBER; i++) {
    hyp_put_mapping(&mappings[i]);
    hyp_putc('\n');
  }
}
  
    

// record a mapping for a range of hypervisor virtual addresses 
void record_hyp_mapping_virt(enum mapping_kind kind, u64 cpu, char *doc, void *virt_from, void *virt_to, enum kvm_pgtable_prot prot)
{
  u64 virt_from_aligned, virt_to_aligned;
  u64 size;
  phys_addr_t phys;
  virt_from_aligned = (u64)virt_from & PAGE_MASK;
  virt_to_aligned = PAGE_ALIGN((u64)virt_to);
  size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;  
  phys = hyp_virt_to_phys((void*)virt_from_aligned);

  mappings[kind].doc = doc;
  mappings[kind].kind = kind;
  mappings[kind].cpu = cpu;
  mappings[kind].virt = virt_from_aligned;
  mappings[kind].phys = phys;
  mappings[kind].size = size;
  mappings[kind].prot = prot;
}


// record the mapping for the idmap, adapting hyp_create_idmap from arch/arm64/kvm/hyp/nvhe/mm.c 
void record_hyp_mapping_image_idmap(enum mapping_kind kind, u64 cpu, char *doc, void *virt_from, void *virt_to, enum kvm_pgtable_prot prot)
{
  u64 virt_from_aligned, virt_to_aligned;
  u64 size;
  phys_addr_t phys;
  virt_from_aligned = (u64)virt_from & PAGE_MASK;
  virt_to_aligned = PAGE_ALIGN((u64)virt_to);
  size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;  
  phys = hyp_virt_to_phys((void*)virt_from_aligned);

  mappings[kind].doc = doc;
  mappings[kind].kind = kind;
  mappings[kind].cpu = cpu;
  mappings[kind].virt = phys; 
  mappings[kind].phys = phys;
  mappings[kind].size = size;
  mappings[kind].prot = prot;
}


  


/** from kvm_pgtable.h, pgt has (among other members which aren't relevant here):
 * @ia_bits:		Maximum input address size, in bits.
 * @start_level:	Level at which the page-table walk starts.
 * @pgd:		Pointer to the first top-level entry of the page-table.
 *
 * where pgd is a kvm_pte_t *, and kvm_pte_t is just u64
 */


// check a specific virt |-> (phys,prot) is included in the pagetables at pgd
_Bool _check_hyp_mapping(kvm_pte_t *pgd, u64 virt, phys_addr_t phys, enum kvm_pgtable_prot prot)
{

  struct AddressDescriptor ad = AArch64_FirstStageTranslate((uint64_t)pgd, virt);
  
  switch (ad.fault.statuscode)
    {
    case Fault_None:
      return (ad.paddress.address == phys);
    default:
      return false;
    }
}

// check the `mapping` range of pages are included in the pagetables at `pgd`
_Bool check_hyp_mapping(kvm_pte_t *pgd, struct mapping *mapping)
{
  u64 i;
  bool ret;
  
  hyp_putsp("check_hyp_mapping "); 
  ret = true;
  for (i=0; i<mapping->size; i++) 
    ret &= _check_hyp_mapping(pgd, mapping->virt + i*PAGE_SIZE, mapping->phys + i*PAGE_SIZE, mapping->prot);
  hyp_putbool(ret);
  hyp_putc(' ');
  hyp_put_mapping(mapping);
  hyp_putc('\n');
  return ret;
}


// check all the mappings recorded in `mappings` are included in the pagetables at `pgd`
_Bool __check_hyp_mappings(kvm_pte_t *pgd)
{
  bool ret;
  u64 i;
  ret = true;
  for (i=0; i<HYP_MAPPING_KIND_NUMBER; i++) {
    if (mappings[i].kind != HYP_NULL)
      ret &= check_hyp_mapping(pgd,&mappings[i]);
  }
  return ret;
}



// record and check all the pKVM mappings  
bool _check_hyp_mappings(kvm_pte_t *pgd, phys_addr_t phys, uint64_t size, uint64_t nr_cpus, unsigned long *per_cpu_base)
{

  bool ret;
  void *virt;   

  // horrible hack for number of CPUs
  if (nr_cpus > MAX_CPUS) {
    hyp_puts("_check_hyp_mappings nr_cpus > MAX_CPUS");
    return false;
  }
  
  
  // the vectors

  // TODO: recreate_hyp_mappings in setup.c calls hyp_map_vectors in mm.c, which uses __hyp_create_private_mapping there to do some spectre-hardened mapping of `__bp_harden_hyp_vecs` (in `arch/arm64/kvm/hyp/hyp-entry.S`(?)). Not sure what this notion of "private mapping" is - and don't want to think about that right now.
  
  // the rest of the image

  record_hyp_mapping_virt(HYP_TEXT, DUMMY_CPU, "hyp_symbol_addr(__hyp_text_start)",
				hyp_symbol_addr(__hyp_text_start),
				hyp_symbol_addr(__hyp_text_end),
				PAGE_HYP_EXEC);
  
  record_hyp_mapping_virt(HYP_RODATA, DUMMY_CPU, "hyp_symbol_addr(__start_rodata)",
				hyp_symbol_addr(__start_rodata),
				hyp_symbol_addr(__end_rodata), PAGE_HYP_RO);
  
  record_hyp_mapping_virt(HYP_RODATA2, DUMMY_CPU, "hyp_symbol_addr(__hyp_data_ro_after_init_start)",
				hyp_symbol_addr(__hyp_data_ro_after_init_start),
				hyp_symbol_addr(__hyp_data_ro_after_init_end),
				PAGE_HYP_RO);
  
  record_hyp_mapping_virt(HYP_BSS, DUMMY_CPU, "hyp_symbol_addr(__bss_start)",
				hyp_symbol_addr(__bss_start),
				hyp_symbol_addr(__hyp_bss_end), PAGE_HYP);
  
  record_hyp_mapping_virt(HYP_BSS2, DUMMY_CPU, "hyp_symbol_addr(__hyp_bss_end)",
				hyp_symbol_addr(__hyp_bss_end),
				hyp_symbol_addr(__bss_stop), PAGE_HYP_RO);

  // the idmap

  record_hyp_mapping_image_idmap(HYP_IDMAP, DUMMY_CPU, "hyp_symbol_addr(__hyp_idmap_text_start)",
				 hyp_symbol_addr(__hyp_idmap_text_start),
				 hyp_symbol_addr(__hyp_idmap_text_end), PAGE_HYP_EXEC);

  // ...and we need to check the contents of all of those is what we
  // expect from the image file (modulo relocations and alternatives)


  // - the non-per-cpu workspace handed from Linux

  virt = hyp_phys_to_virt(phys);
  record_hyp_mapping_virt(HYP_WORKSPACE, DUMMY_CPU, "non-per-cpu workspace",
			       virt,
			       virt + size - 1, PAGE_HYP);


  // AIUI this is all the working memory we've been handed.
  // divide_memory_pool chops it up into per-cpu stacks_base,
  // vmemmap_base, hyp_pgt_base, host_s2_mem_pgt_base,
  // host_s2_dev_pgt_base; then the remainder (after the switch) is
  // handed to the buddy allocator (we might want to check those
  // pieces separately, btw). 
    

  
  // why is the percpu stuff separate from the workspace?
  // 
  // TODO: fix this per-cpu stuff, which currently hits the build problem with #include files mentioned above
    {
      int i;
      void *start, *end;
      for (i = 0; i < nr_cpus; i++) {
        start = (void *)kern_hyp_va(per_cpu_base[i]);  // is per_cpu_base all the linux per-cpu variables, or what??
        end = start + PAGE_ALIGN(hyp_percpu_size);     // with the hyp per-cpu variables at the start??
        record_hyp_mapping_virt(HYP_PERCPU+i, i, "per-cpu variables", start, end, PAGE_HYP);
      }
  }

  hyp_put_mappings();

  ret = __check_hyp_mappings(pgd);



  
  //    && check_hyp_mapping_percpu

  // and we need disjointness of most of these.  Disjointness in a world with address translation is interesting... and there's also read-only-ness and execute permissions to be taken into account

  hyp_putbool(ret); hyp_putc('\n');

  
  return ret;
}


// check putative mappings as described in hyp_pgtable, before the
// switch.  After the switch, we can do the same but using the
// then-current TTBR0_EL2 value instead of the hyp_pgtable.pgd

bool check_hyp_mappings(phys_addr_t phys, uint64_t size, uint64_t nr_cpus, unsigned long *per_cpu_base)
{
  kvm_pte_t * pgd;
  pgd = hyp_pgtable.pgd;
  return _check_hyp_mappings(pgd, phys, size, nr_cpus, per_cpu_base);
}
  
