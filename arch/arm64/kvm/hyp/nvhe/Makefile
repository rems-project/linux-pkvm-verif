# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module, HYP/nVHE part
#

asflags-y := -D__KVM_NVHE_HYPERVISOR__
ccflags-y := -D__KVM_NVHE_HYPERVISOR__

lib-objs := clear_page.o copy_page.o memcpy.o memset.o
lib-objs := $(addprefix ../../../lib/, $(lib-objs))

obj-y := timer-sr.o sysreg-sr.o debug-sr.o switch.o tlb.o hyp-init.o \
	 hyp-start.o hyp-main.o early_alloc.o page_alloc.o setup.o mm.o \
	 cache.o
obj-y += ../vgic-v3-sr.o ../aarch32.o ../vgic-v2-cpuif-proxy.o ../entry.o \
	 ../fpsimd.o ../hyp-entry.o ../pgtable.o
obj-y += $(lib-objs)

obj-y := $(patsubst %.o,%.hyp.o,$(obj-y))
extra-y := $(patsubst %.hyp.o,%.hyp.tmp.o,$(obj-y))

$(obj)/%.hyp.tmp.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/%.hyp.tmp.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)
$(obj)/%.hyp.o: $(obj)/%.hyp.tmp.o FORCE
	$(call if_changed,hypcopy)

# Disable reordering functions by GCC (enabled at -O2).
# This pass puts functions into '.text.*' sections to aid the linker
# in optimizing ELF layout. See HYPCOPY comment below for more info.
ccflags-y += $(call cc-option,-fno-reorder-functions)

# The HYPCOPY command uses `objcopy` to prefix all ELF symbol names
# and relevant ELF section names to avoid clashes with VHE code/data.
#
# Hyp code is assumed to be in the '.text' section of the input object
# files (with the exception of specialized sections such as
# '.hyp.idmap.text'). This assumption may be broken by a compiler that
# divides code into sections like '.text.unlikely' so as to optimize
# ELF layout. HYPCOPY checks that no such sections exist in the input
# using `objdump`, otherwise they would be linked together with other
# kernel code and not memory-mapped correctly at runtime.
quiet_cmd_hypcopy = HYPCOPY $@
      cmd_hypcopy =							\
	if $(OBJDUMP) -h $< | grep -F '.text.'; then			\
		echo "$@: function reordering not supported in nVHE hyp code" >&2; \
		/bin/false;						\
	fi;								\
      $(OBJCOPY)	--prefix-symbols=__kvm_nvhe_			\
			--remove-section=!.text				\
			--rename-section=.text=.hyp.text		\
			--remove-section=!.bss				\
			--rename-section=.bss=.hyp.bss			\
			--remove-section=!.data..percpu		\
			--rename-section=.data..percpu=.hyp.data..percpu \
			--remove-section=!.data..percpu..read_mostly	\
			--rename-section=.data..percpu..read_mostly=.hyp.data..percpu..read_mostly \
			--remove-section=!.hyp.*			\
			--remove-section=!.altinst*			\
			--remove-section=!.rodata*			\
			--remove-section=!.rela*			\
			--remove-section=!.shstrtab			\
			--remove-section=!.strtab			\
			--remove-section=!.symtab			\
			--remove-section=.*				\
			$< $@

# Remove ftrace and Shadow Call Stack CFLAGS.
# This is equivalent to the 'notrace' and '__noscs' annotations.
KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_FTRACE) $(CC_FLAGS_SCS), $(KBUILD_CFLAGS))

# KVM nVHE code is run at a different exception code with a different map, so
# compiler instrumentation that inserts callbacks or checks into the code may
# cause crashes. Just disable it.
GCOV_PROFILE	:= n
KASAN_SANITIZE	:= n
UBSAN_SANITIZE	:= n
KCOV_INSTRUMENT	:= n

# Skip objtool checking for this directory because nVHE code is compiled with
# non-standard build rules.
OBJECT_FILES_NON_STANDARD := y
