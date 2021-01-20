#include <asm/kvm_asm.h>
void record_hyp_mappings(phys_addr_t phys, uint64_t size, uint64_t nr_cpus, unsigned long *per_cpu_base);
#define CHECK_QUIET false
#define CHECK_NOISY true
bool check_hyp_mappings(kvm_pte_t *pgd, bool noisy);
void dump_pgtable(struct kvm_pgtable pg);
void dump_kvm_nvhe_init_params(struct kvm_nvhe_init_params *params);

