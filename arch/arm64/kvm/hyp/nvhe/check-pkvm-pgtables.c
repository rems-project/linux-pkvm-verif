
// PS HACK

// experiment with C executable version of the main EL2 page-table
// spec established by pKVM initialisation, using C versions of the
// EL2 address translation definition, in a style that could easily be
// used by the pKVM devs.

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
// mapping, whatever that is - one needs assumptions about that to
// make this assertion check meaningful.

/*
virt:0x00008000f1806000 phys:0x0000000131806000 size:0x0000000000000011 -R-X HYP_TEXT           hyp_symbol_addr(__hyp_text_start)
virt:0x00008000f1820000 phys:0x0000000131820000 size:0x0000000000000769 -R-- HYP_RODATA         hyp_symbol_addr(__start_rodata)
virt:0x00008000f280a000 phys:0x000000013280a000 size:0x0000000000000001 -R-- HYP_RODATA2        hyp_symbol_addr(__hyp_data_ro_after_init_start)
virt:0x00008000f280b000 phys:0x000000013280b000 size:0x0000000000000003 -RW- HYP_BSS            hyp_symbol_addr(__bss_start)
virt:0x00008000f280e000 phys:0x000000013280e000 size:0x0000000000000082 -R-- HYP_BSS2           hyp_symbol_addr(__hyp_bss_end)
virt:0x0000000131806000 phys:0x0000000131806000 size:0x0000000000000001 -R-X HYP_IDMAP          hyp_symbol_addr(__hyp_idmap_text_start)
virt:0x00008000fe000000 phys:0x000000013e000000 size:0x0000000000000002 -RW- HYP_STACKS         hyp stacks
virt:0x00008000fe002000 phys:0x000000013e002000 size:0x000000000000002d -RW- HYP_VMEMMAP        vmemmap
virt:0x00008000fe02f000 phys:0x000000013e02f000 size:0x0000000000000a81 -RW- HYP_S1_PGTABLE     s1 pgtable
virt:0x00008000feab0000 phys:0x000000013eab0000 size:0x000000000000088e -RW- HYP_S2_MEM_PGTABLE s2 mem pgtable
virt:0x00008000ff33e000 phys:0x000000013f33e000 size:0x0000000000000203 -RW- HYP_S2_DEV_PGTABLE s2 dev pgtable
virt:0x00008000fe000000 phys:0x000000013e000000 size:0x0000000000001643 -RW- HYP_ALL_WORKSPACE  all non-per-cpu workspace
virt:0x00006000027c0000 phys:0x000000013e002000 size:0x000000000000002d -RW- HYP_VMEMMAP_MAP    vmemmap
HYP_MAPPING_NULL
virt:0x00008000c03b8000 phys:0x00000001003b8000 size:0x0000000000000001 -RW- HYP_PERCPU    cpu:0x0000000000000000 per-cpu variables
virt:0x00008000c03b9000 phys:0x00000001003b9000 size:0x0000000000000001 -RW- HYP_PERCPU    cpu:0x0000000000000001 per-cpu variables
*/


  
#include <asm/kvm_pgtable.h>
//#include <asm/kvm_asm.h>
//#include <nvhe/memory.h>
#include <nvhe/mm.h>
#include <linux/bits.h>

#include <nvhe/early_alloc.h>

#include <asm/kvm_mmu.h>
#include <../debug-pl011.h>

// copy of linux sort library to make be linked in to nvhe.  likely there is a much better way to do this...
#include <nvhe/sort_hack.h>

// linking to definitions in setup.c
extern void *stacks_base;
extern void *vmemmap_base;
extern void *hyp_pgt_base;
extern void *host_s2_mem_pgt_base;
extern void *host_s2_dev_pgt_base;

extern void *early_remainder;

extern unsigned long stacks_size;
extern unsigned long vmemmap_size;              
extern unsigned long hyp_pgt_size;
extern unsigned long host_s2_mem_pgt_size;
extern unsigned long host_s2_dev_pgt_size;


// copied from setup.c
#define hyp_percpu_size ((unsigned long)__per_cpu_end - \
			 (unsigned long)__per_cpu_start)









/* ************************************************************************** 
 * additional debug printing functions, extending debug-pl011.h (some "plain",
 *  without the trailing \n) 
 */


void hyp_putsp(char *s)
{
  while (*s)
    hyp_putc(*s++);
}

void hyp_putbool(bool b)
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


void check_assert_fail(char *s)
{
  hyp_putsp("check_assert_fail: ");
  hyp_putsp(s);
  hyp_putc('\n');
}


/* ************************************************************************** 
 * Armv8-A page-table entries
 */

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

// compute the entry_kind of a page-table entry
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
	    return EK_DUMMY; // just to tell the compiler that the cases are exhaustive
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
      return EK_DUMMY; // just to tell the compiler that the cases are exhaustive
    }
}

// print entries

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



/* ************************************************************************** 
 * print Armv8-A page tables, starting at pgd, with any sub-tables
 * (ignoring many things)
 */

void _dump_pgtable(u64 *pgd, u8 level)
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
	  _dump_pgtable((kvm_pte_t *)next_level_virt_address, level+1);
	  hyp_puts("");
	}
      }
    }
    else {
      hyp_puts("table address null");
    }
}


void dump_pgtable(struct kvm_pgtable pg)
{
  hyp_putsxn("ia_bits", pg.ia_bits, 32);
  hyp_putsxn("ia_start_level", pg.start_level, 32);
  hyp_puts("");
  _dump_pgtable(pg.pgd, pg.start_level);
  
  return;
}



/* ************************************************************************** 
 * very crude C executable version of Armv8-A page-table walk definition, very 
 * loosely following the Arm ARM ASL definition - really just the types at 
 * present (modulo embedding bitvectors into uint64_t), 
 * but omitting almost all details
 */

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
  // massively oversimplified
}

struct TLBRecord mkTranslation(uint64_t vaddress, uint64_t pa) {
  struct TLBRecord r = { .addrdesc = { .fault = { .statuscode=Fault_None } , .paddress =  { .address=pa, .NS=1 }, .vaddress = vaddress } };
  return r;
  // massively oversimplified
}

struct TLBRecord AArch64_TranslationTableWalk( uint64_t table_base, uint64_t level, uint64_t vaddress);

struct TLBRecord AArch64_TranslationTableWalk( uint64_t table_base, uint64_t level, uint64_t vaddress) {
  // these declarations should really be combined with their
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
/* abstraction of pKVM intended mappings */

enum mapping_kind {
  HYP_NULL,
  HYP_TEXT,
  HYP_RODATA,
  HYP_RODATA2,
  HYP_BSS,
  HYP_BSS2,
  HYP_IDMAP,
  HYP_STACKS,
  HYP_VMEMMAP,
  HYP_S1_PGTABLE,
  HYP_S2_MEM_PGTABLE,
  HYP_S2_DEV_PGTABLE,
  HYP_WORKSPACE,
  HYP_VMEMMAP_MAP,
  HYP_UART,
  HYP_PERCPU,
  HYP_MAPPING_KIND_NUMBER=HYP_PERCPU
};

#define MAX_MAPPINGS HYP_MAPPING_KIND_NUMBER -1 + NR_CPUS

#define DUMMY_CPU 0

// abstracts to:
// - itself, i.e. to the canonical interpretation for data structures (especially simple as this contains no pointers)
struct mapping {
  enum mapping_kind kind;           // the kind of this mapping     
  u64 cpu;                          // cpu ID in 0..NR_CPUS-1 for HYP_PERCPU mappings; 0 otherwise
  u64 virt;                         // pKVM EL2 after-the-switch start virtual address, page-aligned
  phys_addr_t phys;                 // start physical address, page-aligned
  u64 size;                         // size, as the number of 4k pages
  enum kvm_pgtable_prot prot;       // protection
  char *doc;                        // documentation string, ignore in maths
};

// invariants:
// - after construction, sorted by virtual address
// - non-overlapping virtual address ranges
// - at most one per mapping_kind except HYP_PERCPU, for which at most one for each cpu up to NR_CPUS
// - count <= MAX_MAPPINGS
// abstracts to:
// - a finite set of [[struct mapping]] also satisfying the above
struct mappings {
  struct mapping m[MAX_MAPPINGS];  
  u64 count;
};

// most of our checker code treats datastructures pseudo-functionally,
// but we have to allocate them somehow, and we can't put them on the
// stack as pKVM has only one page of stack per-CPU.  We also want to
// hide this from the setup.c call sites, where mappings data has to
// flow from record_hyp_mappings to later check_hyp_mappings.  So we
// just make global variables, but we use them explicitly only in the
// top-level functions of this file; below that we pass pointers to
// them around.
static struct mappings mappings;


/* sort mappings by virtual address*/

/* we do this after construction with the linux heapsort, as it's
   handy, but it might be tidier to maintain sortedness during
   construction */

static int mapping_compare(const void *lhs, const void *rhs)
{
  if (((const struct mapping *)lhs)->virt < ((const struct mapping *)rhs)->virt) return -1;
  if (((const struct mapping *)lhs)->virt > ((const struct mapping *)rhs)->virt) return 1;
  return 0;
}

void sort_mappings(struct mappings *mappings)
{
  sort(mappings, HYP_MAPPING_KIND_NUMBER, sizeof(struct mapping), mapping_compare, NULL);
}

/* print mappings */

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
  case HYP_TEXT:          hyp_putsp("HYP_TEXT          "); break;
  case HYP_RODATA:	  hyp_putsp("HYP_RODATA        "); break;
  case HYP_RODATA2:	  hyp_putsp("HYP_RODATA2       "); break;
  case HYP_BSS:	          hyp_putsp("HYP_BSS           "); break;
  case HYP_BSS2:	  hyp_putsp("HYP_BSS2          "); break;
  case HYP_IDMAP:	  hyp_putsp("HYP_IDMAP         "); break;
  case HYP_STACKS:	  hyp_putsp("HYP_STACKS        "); break;
  case HYP_VMEMMAP:	  hyp_putsp("HYP_VMEMMAP       "); break;
  case HYP_S1_PGTABLE:	  hyp_putsp("HYP_S1_PGTABLE    "); break;
  case HYP_S2_MEM_PGTABLE:hyp_putsp("HYP_S2_MEM_PGTABLE"); break;
  case HYP_S2_DEV_PGTABLE:hyp_putsp("HYP_S2_DEV_PGTABLE"); break;
  case HYP_VMEMMAP_MAP:	  hyp_putsp("HYP_VMEMMAP_MAP   "); break;
  case HYP_UART:	  hyp_putsp("HYP_UART          "); break;
  case HYP_WORKSPACE:     hyp_putsp("HYP_WORKSPACE     "); break;
  case HYP_PERCPU:        hyp_putsp("HYP_PERCPU        "); break;
  default:                hyp_putsp("unknown mapping kind"); break;
  }
  hyp_putsp(" ");
}

void hyp_put_mapping(struct mapping *map)
{
  if (map->kind == HYP_NULL)
    hyp_putsp("HYP_MAPPING_NULL");
  else {
    hyp_putsxn("virt",map->virt,64);
    hyp_putsxn("virt'",(map->virt + PAGE_SIZE*map->size),64);
    hyp_putsxn("phys",map->phys,64);
    hyp_putsxn("size",(u32)map->size,32);
    hyp_put_prot(map->prot);
    hyp_put_mapping_kind(map->kind);
    if (map->kind == HYP_PERCPU) hyp_putsxn("cpu",map->cpu,64);
    hyp_putsp(map->doc);
  }
}

void hyp_put_mappings(struct mappings *mappings)
{
  u64 i;
  for (i=0; i<mappings->count; i++) {
    hyp_put_mapping(&mappings->m[i]);
    hyp_putc('\n');
  }
}
  
    

  


/* ************************************************************************** */
/* forwards check, that intended mappings are included in the actual page tables 
 * ignoring prot for now
 */


/* check that a specific virt |-> (phys,prot) is included in the pagetables at pgd, 
 * using the Armv8-A page-table walk function 
 */
bool _check_hyp_mapping_fwd(u64 virt, phys_addr_t phys, enum kvm_pgtable_prot prot, kvm_pte_t *pgd)
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


/* check the `mapping` range of pages are included in the pagetables at `pgd` */
bool check_hyp_mapping_fwd(struct mapping *mapping, kvm_pte_t *pgd, bool noisy)
{
  u64 i;
  bool ret;
  
  ret = true;
  for (i=0; i<mapping->size; i++) 
    ret = ret && _check_hyp_mapping_fwd(mapping->virt + i*PAGE_SIZE, mapping->phys + i*PAGE_SIZE, mapping->prot, pgd);

  if (noisy) {
    hyp_putsp("check_hyp_mapping_fwd "); 
    hyp_putbool(ret);
    hyp_putc(' ');
    hyp_put_mapping(mapping);
    hyp_putc('\n');
  }
  return ret;
}

/* check that all the mappings recorded in `mappings` are included in the pagetables at `pgd` */
bool check_hyp_mappings_fwd(struct mappings *mappings, kvm_pte_t *pgd, bool noisy)
{
  bool ret;
  u64 i;
  ret = true;
  for (i=0; i < mappings->count; i++) {
    ret = ret && check_hyp_mapping_fwd(&mappings->m[i], pgd, noisy);
  }
  return ret;
}


/* ************************************************************************** 
 * reverse check, that  all the mappings in the pagetables at `pgd` are included in those recorded in `mappings`
 */

// Mathematically one would do this with a single quantification over
// all virtual addresses, using the Arm ASL translate function for
// each, but that would take too long to execute.  So we have to
// duplicate some of the walk code.  We could reuse pgtable.c here -
// but we want an independent definition that eventually we can prove
// relates to the Arm ASL.  For now, I'll just hack something up,
// adapting the above hacked-up version of the walk code.

// At a higher level, instead of doing two inclusion checks, we could
// compute a more explicit representation of the denotation of a page
// table and of the collection of mappings and check equality. That
// would be mathematically cleaner but more algorithmically complex,
// and involve more allocation.  We do that below.

// check (virt,phys) is in at least one of the `mappings`
bool _check_hyp_mappings_rev(struct mappings *mappings, u64 virt, phys_addr_t phys, bool noisy)
{
  int i;
  u64 occs;
  occs=0;
  for (i=0; i < mappings->count; i++) {
    if (virt >= mappings->m[i].virt && virt < mappings->m[i].virt + PAGE_SIZE*mappings->m[i].size && phys == mappings->m[i].phys + (virt - mappings->m[i].virt)) {
      occs++;
      if (noisy) {
	hyp_put_mapping_kind(mappings->m[i].kind);
	hyp_putc(' ');
	if (occs > 1) hyp_putsp("duplicate ");
      }
    }
  }
  if (noisy)
    if (occs == 0) hyp_putsp("not found ");
  return (occs >= 1);
}

// very crude recurse over the Armv8-A page tables at `pgd`, checking that each leaf
// (virt,phys) is in at least one of the mappings
bool check_hyp_mappings_rev(struct mappings *mappings, kvm_pte_t *pgd, u8 level, u64 va_partial, bool noisy);
bool check_hyp_mappings_rev(struct mappings *mappings, kvm_pte_t *pgd, u8 level, u64 va_partial, bool noisy) 
{
  bool ret, entry;
  u64 idx;
  u64 va_partial_new;
  kvm_pte_t pte;
  enum entry_kind ek;
  u64 next_level_phys_address, next_level_virt_address;

  ret = true;
  for (idx = 0; idx < 512; idx++) {
    switch (level) {
    case 0: va_partial_new = va_partial | (idx << 39); break;
    case 1: va_partial_new = va_partial | (idx << 30); break;
    case 2: va_partial_new = va_partial | (idx << 21); break;
    case 3: va_partial_new = va_partial | (idx << 12); break;
    default: hyp_puts("unhandled level"); // this is just to tell the compiler that the cases are exhaustive
    }
      
    pte = pgd[idx];
    
    ek = entry_kind(pte, level);       
    switch(ek)
      {
      case EK_INVALID:             entry = true; break;
      case EK_BLOCK:		   hyp_putsp("unhandled EK_BLOCK"); entry = false; break;
      case EK_TABLE:
	next_level_phys_address = pte & GENMASK(47,12);
	next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
	// hyp_putsxn("table phys", next_level_phys_address, 64);
	//hyp_putsxn("table virt", next_level_virt_address, 64);
	entry =check_hyp_mappings_rev(mappings, (kvm_pte_t *)next_level_virt_address, level+1, va_partial_new, noisy); break;
      case EK_PAGE_DESCRIPTOR:
	{ u64 oa;
	  oa = pte & GENMASK(47,12);
	  //hyp_putsxn("oa", oa, 64);
	  // now check (va_partial, oa) is in one of the mappings  (ignore prot for now, but should check)
	  if (noisy) { hyp_putsp("check_hyp_mappings_rev "); hyp_putsxn("va", va_partial_new, 64); hyp_putsxn("oa", oa, 64); }
	  entry = _check_hyp_mappings_rev(mappings, va_partial_new, oa, noisy);
	  if (noisy) { hyp_putbool(entry); hyp_putc('\n'); }

	}
	break;	 
      case EK_BLOCK_NOT_PERMITTED:  hyp_putsp("unhandled EK_BLOCK_NOT_PERMITTED"); entry = false; break;
      case EK_RESERVED:		   hyp_putsp("unhandled EK_RESERVED"); entry = false; break;
      case EK_DUMMY:               hyp_putsp("unhandled EK_DUMMY"); entry = false; break;
      default:            hyp_putsp("unhandled default"); entry = false; break;
      }
    ret = ret && entry;
  }
  if (level == 0) { hyp_putsp("check_hyp_mappings_rev "); hyp_putbool(ret); hyp_putc('\n'); }
  return ret;
}



/* ************************************************************************** 
 * check forward and reverse inclusions of the mappings in the pagetables at `pgd` and those recorded in `mappings`
 */

// call with hyp_pgtable.pgd to check putative mappings as described
// in hyp_pgtable, before the switch.  After the switch, we can do the
// same but using the then-current TTBR0_EL2 value instead of the
// hyp_pgtable.pgd


bool check_hyp_mappings_both(struct mappings *mappings, kvm_pte_t *pgd, bool noisy) 
{
  bool ret, fwd, rev;
  fwd = check_hyp_mappings_fwd(mappings, pgd, noisy);
  rev = check_hyp_mappings_rev(mappings, pgd, 0, 0, noisy);

  // and we need to check disjointness of most of them. Disjointness
  // in a world with address translation is interesting... and there's
  // also read-only-ness and execute permissions to be taken into
  // account

  ret = fwd && rev;
  hyp_putsp("check_hyp_mappings_both: "); hyp_putbool(ret); hyp_putc('\n');
  return ret;
}



/* ************************************************************************** 
 * record the intended pKVM mappings
 */

// record a mapping for a range of hypervisor virtual addresses 
void extend_mappings_virt(struct mappings *mappings, enum mapping_kind kind, u64 cpu, char *doc, void *virt_from, void *virt_to, enum kvm_pgtable_prot prot)
{
  u64 virt_from_aligned, virt_to_aligned;
  u64 size;
  phys_addr_t phys;
  if (mappings->count >= MAX_MAPPINGS) check_assert_fail("extend_mappings_virt full");

  virt_from_aligned = (u64)virt_from & PAGE_MASK;
  virt_to_aligned = PAGE_ALIGN((u64)virt_to);
  size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;  
  phys = hyp_virt_to_phys((void*)virt_from_aligned);

  mappings->m[mappings->count].doc = doc;
  mappings->m[mappings->count].kind = kind;
  mappings->m[mappings->count].cpu = cpu;
  mappings->m[mappings->count].virt = virt_from_aligned;
  mappings->m[mappings->count].phys = phys;
  mappings->m[mappings->count].size = size;
  mappings->m[mappings->count].prot = prot;
  mappings->count++;
}

// record the mapping for the idmap, adapting hyp_create_idmap from arch/arm64/kvm/hyp/nvhe/mm.c 
void extend_mappings_image_idmap(struct mappings *mappings, enum mapping_kind kind, u64 cpu, char *doc, void *virt_from, void *virt_to, enum kvm_pgtable_prot prot)
{
  u64 virt_from_aligned, virt_to_aligned;
  u64 size;
  phys_addr_t phys;
  if (mappings->count >= MAX_MAPPINGS) check_assert_fail("extend_mappings_image_idmap full");

  virt_from_aligned = (u64)virt_from & PAGE_MASK;
  virt_to_aligned = PAGE_ALIGN((u64)virt_to);
  size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;  
  phys = hyp_virt_to_phys((void*)virt_from_aligned);

  mappings->m[mappings->count].doc = doc;
  mappings->m[mappings->count].kind = kind;
  mappings->m[mappings->count].cpu = cpu;
  mappings->m[mappings->count].virt = phys;  // NB
  mappings->m[mappings->count].phys = phys;
  mappings->m[mappings->count].size = size;
  mappings->m[mappings->count].prot = prot;
  mappings->count++;
}


// record a mapping for a range of hypervisor virtual addresses to a specific physical address, for the vmemmap
void extend_mappings_vmemmap(struct mappings *mappings, enum mapping_kind kind, u64 cpu, char *doc, void *virt_from, void *virt_to, phys_addr_t phys, enum kvm_pgtable_prot prot)
{
  u64 virt_from_aligned, virt_to_aligned;
  u64 size;
  if (mappings->count >= MAX_MAPPINGS) check_assert_fail("extend_mappings_vmemmap full");

  virt_from_aligned = (u64)virt_from & PAGE_MASK;
  virt_to_aligned = PAGE_ALIGN((u64)virt_to);
  size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;  

  mappings->m[mappings->count].doc = doc;
  mappings->m[mappings->count].kind = kind;
  mappings->m[mappings->count].cpu = cpu;
  mappings->m[mappings->count].virt = virt_from_aligned; 
  mappings->m[mappings->count].phys = phys;
  mappings->m[mappings->count].size = size;
  mappings->m[mappings->count].prot = prot;
  mappings->count++;
}


// * record a mapping for the uart  TODO
// */
//void extend_mappings_uart(void);
//{
//  phys_addr_t phys = CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR;
//  enum kvm_pgtable_prot prot = PAGE_HYP_DEVICE;
//  u64 size = 1;
//  void *virt = __io_map_base;
//  
//  u64 virt_from_aligned, virt_to_aligned;
//  u64 size;
//  virt_from_aligned = (u64)virt_from & PAGE_MASK;
//  virt_to_aligned = PAGE_ALIGN((u64)virt_to);
//  size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;  
//
//  mappings[kind].doc = doc;
//  mappings[kind].kind = kind;
//  mappings[kind].cpu = cpu;
//  mappings[kind].virt = virt_from_aligned; 
//  mappings[kind].phys = phys;
//  mappings[kind].size = size;
//  mappings[kind].prot = prot;
//}


/* 
 * record all the pKVM mappings  
 *
 * As written this duplicates some of the setup.c code that constructs
 * the actual mappings. That duplication is somewhat useful for us to
 * check we understand, but it would be cleaner to integrate the
 * recording into the construction code - though that would also be
 * more invasive w.r.t. the non-verification code, so this might be
 * preferable in practice for now in any case.
 */
void _record_hyp_mappings(struct mappings *mappings, phys_addr_t phys, uint64_t size, uint64_t nr_cpus, unsigned long *per_cpu_base)
{

  if (nr_cpus > NR_CPUS) {
    check_assert_fail("record_hyp_mappings nr_cpus > NR_CPUS");
    return;
  }
  
  // the vectors
  // TODO: recreate_hyp_mappings in setup.c calls hyp_map_vectors in
  // mm.c, which uses __hyp_create_private_mapping there to do some
  // spectre-hardened mapping of `__bp_harden_hyp_vecs` (in
  // `arch/arm64/kvm/hyp/hyp-entry.S`(?)). Not sure what this notion
  // of "private mapping" is - and don't want to think about that
  // right now.  It doesn't seem to actually be used in the QEMU
  // execution - perhaps Cortex-A72 doesn't have the required
  // cpus_have_const_cap(ARM64_SPECTRE_V3A) - so I punt on it for now.
  
  // the rest of the image

  extend_mappings_virt(mappings, HYP_TEXT, DUMMY_CPU, "hyp_symbol_addr(__hyp_text_start)",
				hyp_symbol_addr(__hyp_text_start),
				hyp_symbol_addr(__hyp_text_end),
				PAGE_HYP_EXEC);
  
  extend_mappings_virt(mappings, HYP_RODATA, DUMMY_CPU, "hyp_symbol_addr(__start_rodata)",
				hyp_symbol_addr(__start_rodata),
				hyp_symbol_addr(__end_rodata), PAGE_HYP_RO);
  
  extend_mappings_virt(mappings, HYP_RODATA2, DUMMY_CPU, "hyp_symbol_addr(__hyp_data_ro_after_init_start)",
				hyp_symbol_addr(__hyp_data_ro_after_init_start),
				hyp_symbol_addr(__hyp_data_ro_after_init_end),
				PAGE_HYP_RO);
  
  extend_mappings_virt(mappings, HYP_BSS, DUMMY_CPU, "hyp_symbol_addr(__bss_start)",
				hyp_symbol_addr(__bss_start),
				hyp_symbol_addr(__hyp_bss_end), PAGE_HYP);
  
  extend_mappings_virt(mappings, HYP_BSS2, DUMMY_CPU, "hyp_symbol_addr(__hyp_bss_end)",
				hyp_symbol_addr(__hyp_bss_end),
				hyp_symbol_addr(__bss_stop), PAGE_HYP_RO);

  // the idmap

  extend_mappings_image_idmap(mappings, HYP_IDMAP, DUMMY_CPU, "hyp_symbol_addr(__hyp_idmap_text_start)",
				 hyp_symbol_addr(__hyp_idmap_text_start),
				 hyp_symbol_addr(__hyp_idmap_text_end), PAGE_HYP_EXEC);

  // ...and we need to check the contents of all of those is what we
  // expect from the image file (modulo relocations and alternatives)


  // the non-per-cpu workspace handed from Linux
  // AIUI this is all the working memory we've been handed.
  // divide_memory_pool chops it up into per-cpu stacks_base,
  // vmemmap_base, hyp_pgt_base, host_s2_mem_pgt_base,
  // host_s2_dev_pgt_base; then the remainder (after the switch) is
  // handed to the buddy allocator. We want to check those
  // pieces separately, so split this up.
  
  extend_mappings_virt(mappings, HYP_STACKS, DUMMY_CPU, "hyp stacks", stacks_base, stacks_base + PAGE_SIZE*stacks_size, PAGE_HYP);
  extend_mappings_virt(mappings, HYP_VMEMMAP, DUMMY_CPU, "vmemmap", vmemmap_base, vmemmap_base + PAGE_SIZE*vmemmap_size, PAGE_HYP);
  extend_mappings_virt(mappings, HYP_S1_PGTABLE, DUMMY_CPU, "s1 pgtable", hyp_pgt_base, hyp_pgt_base + PAGE_SIZE*hyp_pgt_size, PAGE_HYP);
  extend_mappings_virt(mappings, HYP_S2_MEM_PGTABLE, DUMMY_CPU, "s2 mem pgtable", host_s2_mem_pgt_base, host_s2_mem_pgt_base + PAGE_SIZE*host_s2_mem_pgt_size, PAGE_HYP);
  extend_mappings_virt(mappings, HYP_S2_DEV_PGTABLE, DUMMY_CPU, "s2 dev pgtable", host_s2_dev_pgt_base, host_s2_dev_pgt_base + PAGE_SIZE*host_s2_dev_pgt_size, PAGE_HYP);

  // I don't understand how the __kvm_hyp_protect_finalise installation of the buddy allocator relates to the host_s2 parts of the divide_memory_pool
  // but this is the remaining early allocator space
  extend_mappings_virt(mappings, HYP_WORKSPACE, DUMMY_CPU, "workspace",  early_remainder, (void*)hyp_phys_to_virt(phys)+size,PAGE_HYP); 


  // the per-cpu variables.
  // why is the percpu stuff separate from the workspace?  Because these are shared with other kernel code, pre-switch?
    {
      int i;
      void *start, *end;
      for (i = 0; i < nr_cpus; i++) {
        start = (void *)kern_hyp_va(per_cpu_base[i]);  // is per_cpu_base all the linux per-cpu variables, or what??
        end = start + PAGE_ALIGN(hyp_percpu_size);     // with the hyp per-cpu variables at the start??
        extend_mappings_virt(mappings, HYP_PERCPU, i, "per-cpu variables", start, end, PAGE_HYP);
      }
    }
    
    // the vmemmap
    // as established by hyp_back_vmemmap in mm.c
    {
      unsigned long vmemmap_start, vmemmap_end;
      phys_addr_t vmemmap_back;
      
      vmemmap_back = hyp_virt_to_phys(vmemmap_base);
      hyp_vmemmap_range(phys, size, &vmemmap_start, &vmemmap_end);
      extend_mappings_vmemmap(mappings, HYP_VMEMMAP_MAP, DUMMY_CPU, "vmemmap", (void*)vmemmap_start, (void*)vmemmap_end, vmemmap_back, PAGE_HYP);
    }

    sort_mappings(mappings);
    
    hyp_put_mappings(mappings);

}

// apply the above to the global variable `mappings`
void record_hyp_mappings(phys_addr_t phys, uint64_t size, uint64_t nr_cpus, unsigned long *per_cpu_base)
{
  _record_hyp_mappings(&mappings, phys, size, nr_cpus, per_cpu_base);
}


/* *********************************************************** */
/* new abstraction */

struct maplet {
  u64 virt;                   // page-aligned      
  phys_addr_t phys;           // page-aligned
  enum kvm_pgtable_prot prot; // punting on this for now
};

#define MAX_MAPLETS 100000     // arbitrary hack - better to calculate how big this must be and get linux to give us enough memory for them up-front


// invariant:
// - functional and sorted by virt
// - count <= MAX_MAPLETS
// abstracts to:
// - a finite map from virtual addresses to (phys,prot) records
struct maplets {
  struct maplet maplets[MAX_MAPLETS];  // must be sorted by virtual address
  u64 count;
};

static struct maplets maplets_a, maplets_b;



// extend maplets with one new maplet
// precondition:
// - virt is strictly greater than the virt of any existing maplet
void extend_maplets(struct maplets *ms, u64 virt, phys_addr_t phys, enum kvm_pgtable_prot prot)
{
  if (ms->count >= MAX_MAPLETS) check_assert_fail("extend maplets full");
  if (ms->count > 0 && virt <= ms->maplets[ms->count - 1].virt) { check_assert_fail("extend maplets given non-increasing virt"); hyp_putsxn("ms->count",ms->count,64); hyp_putsxn("virt",virt,64); }
  ms->maplets[ms->count].virt = virt;
  ms->maplets[ms->count].phys = phys;
  ms->maplets[ms->count].prot = prot;
  ms->count++;
}

// equality check of maplets
bool interpret_equals(struct maplets *ms1, struct maplets *ms2)
{
  u64 i;
  if (ms1->count != ms2->count) return false;
  for (i=0; i<ms1->count; i++) {
    if ( !(ms1->maplets[i].virt == ms2->maplets[i].virt && ms1->maplets[i].phys == ms2->maplets[i].phys) ) {
      hyp_putsxn("interpret_equals mismatch virt1", ms1->maplets[i].virt, 64);
      hyp_putsxn("virt2", ms2->maplets[i].virt, 64);
      hyp_putc('\n');
      return false;
    }
  }
  return true;
}


/* *********************************************************** */
/* compute interpretation of pagetables at `pgd`, ms = [[pgd]]
 */

void _interpret_pgtable(struct maplets *ms, kvm_pte_t *pgd, u8 level, u64 va_partial, bool noisy) 
{
  u64 idx;
  u64 va_partial_new;
  kvm_pte_t pte;
  enum entry_kind ek;
  u64 next_level_phys_address, next_level_virt_address;

  for (idx = 0; idx < 512; idx++) {
    switch (level) {
    case 0: va_partial_new = va_partial | (idx << 39); break;
    case 1: va_partial_new = va_partial | (idx << 30); break;
    case 2: va_partial_new = va_partial | (idx << 21); break;
    case 3: va_partial_new = va_partial | (idx << 12); break;
    default: hyp_puts("unhandled level"); // cases are exhaustive
    }
      
    pte = pgd[idx];
    
    ek = entry_kind(pte, level);       
    switch(ek)
      {
      case EK_INVALID:             break;
      case EK_BLOCK:		   check_assert_fail("unhandled EK_BLOCK"); break;
      case EK_TABLE:
	next_level_phys_address = pte & GENMASK(47,12);
	next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
	// hyp_putsxn("table phys", next_level_phys_address, 64);
	// hyp_putsxn("table virt", next_level_virt_address, 64);
	_interpret_pgtable(ms, (kvm_pte_t *)next_level_virt_address, level+1, va_partial_new, noisy); break;
      case EK_PAGE_DESCRIPTOR:
	{ u64 oa;
	  oa = pte & GENMASK(47,12);
	  // hyp_putsxn("oa", oa, 64);
	  // now add (va_partial, oa) to the mappings  (ignore prot for now)
	  if (noisy) { hyp_putsp("interpret_pgtable "); hyp_putsxn("va", va_partial_new, 64); hyp_putsxn("oa", oa, 64); }
	  extend_maplets(ms,va_partial_new, oa, 0);

	}
	break;	 
      case EK_BLOCK_NOT_PERMITTED: check_assert_fail("unhandled EK_BLOCK_NOT_PERMITTED"); break;
      case EK_RESERVED:		   check_assert_fail("unhandled EK_RESERVED"); break;
      case EK_DUMMY:               check_assert_fail("unhandled EK_DUMMY"); break;
      default:                     check_assert_fail("unhandled default");  break;
      }
  }
}


void interpret_pgtable(struct maplets *ms, kvm_pte_t *pgd, bool noisy);
void interpret_pgtable(struct maplets *ms, kvm_pte_t *pgd, bool noisy)
{
  ms->count = 0;
  _interpret_pgtable(ms, pgd, 0, 0, false);
}



/* ************************************************************************** 
 * copute interpretation of the recorded intended mappings, ms = [[mapping]]
 */
void _interpret_mapping(struct maplets *ms, struct mapping *mapping, bool noisy)
{
  u64 i;
  
  if (noisy) hyp_putsp("_interpret_mapping "); 
  for (i=0; i<mapping->size; i++) 
    extend_maplets(ms, mapping->virt + i*PAGE_SIZE, mapping->phys + i*PAGE_SIZE, mapping->prot);
  if (noisy) {
    hyp_put_mapping(mapping);
    hyp_putc('\n');
  }
}

/* ************************************************************************** 
 * ms := the interpretation of all the mappings recorded in `mappings` 
 */
void interpret_mappings(struct maplets *ms, struct mappings *mappings, bool noisy)
{
  u64 i;
  ms->count = 0;
  for (i=0; i < mappings->count; i++) 
    _interpret_mapping(ms, &mappings->m[i], noisy);
}






/* **************************************** */
// top-level check that the recorded intended mappings and the actual mappings at pgd are identical
bool _check_hyp_mappings(struct mappings *mappings, struct maplets *maplets_a, struct maplets *maplets_b, kvm_pte_t *pgd, bool noisy) 
{
  bool new_equal;

  // the "old abstraction" check is much better for debugging the
  // checking code, as one can more easily identify the source of any
  // mismatches, while the "new abstraction" check will be easier to
  // work with in the verification.  Do both.
  
  // check directly, old abstraction
  check_hyp_mappings_both(mappings, pgd, false && noisy);

  // check using new abstraction
  hyp_puts("hyp_put_mappings");
  hyp_put_mappings(mappings);
  hyp_puts("interpret_mappings");
  interpret_mappings(maplets_a, mappings, noisy);
  hyp_puts("interpret_pgtable");
  interpret_pgtable(maplets_b, pgd, noisy);
  new_equal = interpret_equals(maplets_a, maplets_b);
  hyp_putsp("interpret_equals: "); hyp_putbool(new_equal); hyp_putc('\n');

  return new_equal;
}

 // apply the above to the global variables
 bool check_hyp_mappings(kvm_pte_t *pgd, bool noisy) 
 {
   return _check_hyp_mappings(&mappings, &maplets_a, &maplets_b, pgd, noisy);
 }
 
 
/* **************************************** */
 /* print key system register values */
void dump_kvm_nvhe_init_params(struct kvm_nvhe_init_params *params)
{
        hyp_putsxn("mair_el2    ", params->mair_el2     , 64); hyp_putc('\n');
        hyp_putsxn("tcr_el2     ", params->tcr_el2      , 64); hyp_putc('\n');
        hyp_putsxn("tpidr_el2   ", params->tpidr_el2    , 64); hyp_putc('\n');
        hyp_putsxn("stack_hyp_va", params->stack_hyp_va , 64); hyp_putc('\n');
        hyp_putsxn("pgd_pa      ", (unsigned long)params->pgd_pa       , 64); hyp_putc('\n');
        hyp_putsxn("hcr_el2     ", params->hcr_el2      , 64); hyp_putc('\n');
        hyp_putsxn("vttbr       ", params->vttbr        , 64); hyp_putc('\n');
        hyp_putsxn("vtcr        ", params->vtcr         , 64); hyp_putc('\n');
}


