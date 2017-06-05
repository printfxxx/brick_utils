#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		gcc.mk
# Brief		GCC toolchain support.
#

ifeq ($(EXTMF_SEG),V)

# Link all module files into target file
define do_ldout
$(strip $(CC) $(1) -o $(2) $(3) -Wl,-Map=$(2)$(SFX_MAP))
endef

define ldout_cmd_wrapper
$(call $(1),$(2),$(optdir)$(3),$(_ldflags) $(ldflags_$(3)))
endef

SFX_H	 = .h
SFX_MAP  = .map
SFX_BIN  = .bin
SFX_HEX  = .hex
SFX_SREC = .srec

_out  = $(out) $(out-y)
ldout = $(foreach f,$(_out),$(if $($(f)),$(f),))
OUT   = $(_out:%=$(optdir)%)
LDOUT = $(ldout:%=$(optdir)%)
DIS   = $(LDOUT:%=%$(SFX_ASM))
BIN   = $(LDOUT:%=%$(SFX_BIN))
HEX   = $(LDOUT:%=%$(SFX_HEX))
SREC  = $(LDOUT:%=%$(SFX_SREC))

host   ?= $(CROSS_COMPILE)
CC	= $(host)gcc
AR	= $(host)ar
LD	= $(host)ld
NM	= $(host)nm
OBJDUMP = $(host)objdump
OBJCOPY = $(host)objcopy
STRIP	= $(host)strip

_LDFLAGS = $(LDFLAGS) $(LDFLAGS-y)
ldflags  = $(_LDFLAGS)
_ldflags = $(ldflags) $(ldflags-y)

ifneq ($(shell $(LD) -V | sed -ne '/Supported/,+1{/pep\{,1\}$$/p}'),)
SFX_EXE = .exe
endif

export CC AR LD

endif	# ifeq ($(EXTMF_SEG),V)

ifeq ($(EXTMF_SEG),R)

all: out

out: $(OUT) $(OLST)
dis: $(DIS)
bin: $(BIN)
hex: $(HEX)
srec: $(SREC)

ifeq ($(filter $(NOINIT_TARGET),$(MAKECMDGOALS)),)
$(foreach f,$(ldout),$(eval objs_$(f) = $(filter-out %/,$($(f)))))
$(foreach f,$(ldout),$(eval olst_$(f) = $(addsuffix $(OLST),$(filter %/,$($(f))))))
$(foreach f,$(ldout),$(eval $(optdir)$(f): $(objs_$(f))))
$(foreach f,$(ldout),$(eval $(optdir)$(f): $(olst_$(f))))
endif

%$(OLST): $(OLST);

$(ldout:%=$(bdir)%$(SFX_CMD)): $(bdir)%$(SFX_CMD): FORCE
	$(call cmd_change_chk,$(call ldout_cmd_wrapper,do_ldout,$(objs_$*) `cat $(olst_$*) /dev/null`,$*),$@)

$(LDOUT): $(optdir)%: $(bdir)%$(SFX_CMD)
	$(call msg,LD,$*)
	$(call ldout_cmd_wrapper,do_ldout,$(objs_$*) `cat $(olst_$*) /dev/null`,$*)

$(DIS):
	$(call msg,DIS,$(@:$(optdir)%=%))
	$(OBJDUMP) -S $(@:%$(SFX_ASM)=%) > $@ || ($(RM) $@; false)

$(BIN):
	$(call msg,GEN,$(@:$(optdir)%=%))
	$(OBJCOPY) -O binary $(@:%$(SFX_BIN)=%) $@

$(HEX):
	$(call msg,GEN,$(@:$(optdir)%=%))
	$(OBJCOPY) -O ihex $(@:%$(SFX_HEX)=%) $@

$(SREC):
	$(call msg,GEN,$(@:$(optdir)%=%))
	$(OBJCOPY) -O srec $(@:%$(SFX_SREC)=%) $@

help::
	echo ''
	echo 'DISASSEMBLY'
	echo -e '$(GREEN)dis$(NORMAL)'
	echo -e '\tGenerate disassemble file from target'
	echo ''
	echo 'OBJCOPY'
	echo -e '$(GREEN)bin$(NORMAL)'
	echo -e '\tGenerate binary format target'
	echo -e '$(GREEN)hex$(NORMAL)'
	echo -e '\tGenerate ihex format target'
	echo -e '$(GREEN)srec$(NORMAL)'
	echo -e '\tGenerate srec format target'

.PHONY: out dis bin hex srec

endif	# ifeq ($(EXTMF_SEG),R)

ifeq ($(EXTR_SEG),V)

# Build obj
define do_cc
$(strip $(CC) -c $(1) -o $(2) $(3))
endef
# Relink obj
define do_robj
$(strip $(LD) -r $(1) -o $(2))
endef
# Build static library
define do_slib
$(strip $(AR) rc $(2) $(1))
endef
# Build share library
define do_dlib
$(strip $(CC) -fPIC -shared $(1) -o $(2))
endef
# Generate obj list
define do_olst
$(strip for f in $(1); do echo $$f; done > $(2) || ($(RM) $(2); false))
endef
# Rule for generate depend
define rule_cc_dep
sinclude $(2)$(SFX_D)
_$(2)_deps = $$(wildcard $$($(2)_deps))

$(2)$(SFX_D): $(1) $$(if $$(filter-out $$(_$(2)_deps),$$($(2)_deps)),FORCE,$$(_$(2)_deps))
	$(CC) $$< -M -MT $(2)_deps $(3) | sed -e '1s|:| =|' > $$@; \
	[ "$$$${PIPESTATUS[*]}" == "0 0" ] || ($(RM) $$@; $(call err,GEN,$$(@:$(bdir)%=%)); false)
endef

SFX_C	= .c
SFX_ASM = .S
SFX_CXX = .cpp
SFX_O	= .o
SFX_A	= .a
SFX_D	= .d
SFX_SO	= .so
SFX_LDS = .ld
SFX_CMD = .cmd

_obj = $(obj) $(obj-y)
DIR  = $(filter %/,$(_obj))
MOD  = $(filter %$(SFX_O) %$(SFX_A) %$(SFX_SO),$(_obj))
LEAF = $(call extract_all_leaf,$(MOD))
NODE = $(call extract_all_node,$(MOD))

OBJ   = $(filter %$(SFX_O),$(LEAF))
ROBJ  = $(filter %$(SFX_O),$(NODE))
SLIB  = $(filter %$(SFX_A),$(NODE))
DLIB  = $(filter %$(SFX_SO),$(NODE))
OLST  = $(bdir)objs
SOLST = $(DIR:%=%$(OLST))

_CFLAGS = $(CFLAGS) $(CFLAGS-y)
cflags  = $(_CFLAGS)
_cflags = $(cflags) $(cflags-y)

export CFLAGS CFLAGS-y

endif	# ifeq ($(EXTR_SEG),V)

ifeq ($(EXTR_SEG),R)

ifeq ($(filter $(NOINIT_TARGET),$(MAKECMDGOALS)),)
$(shell mkdir -p $(addprefix $(bdir),$(sort $(dir $(NODE) $(LEAF)) ./)))
$(foreach m,$(MOD),$(foreach f,$(call extract_all_leaf,$(m)), \
	$(eval cflags_$(f) += -DMOD_NAME=\"$(m)\" -DOBJ_NAME=\"$(f)\")))
$(foreach f,$(call extract_all_leaf,$(DLIB)),$(eval cflags_$(f) += -fPIC))
$(foreach f,$(ROBJ) $(SLIB) $(DLIB),$(eval $(bdir)$(f): $($(f):%=$(bdir)%)))
endif

$(ROBJ:%=$(bdir)%$(SFX_CMD)): $(bdir)%$(SFX_CMD): FORCE
	$(call cmd_change_chk,$(call do_robj,$($*:%=$(bdir)%),$(bdir)$*),$@)

$(SLIB:%=$(bdir)%$(SFX_CMD)): $(bdir)%$(SFX_CMD): FORCE
	$(call cmd_change_chk,$(call do_slib,$($*:%=$(bdir)%),$(bdir)$*),$@)

$(DLIB:%=$(bdir)%$(SFX_CMD)): $(bdir)%$(SFX_CMD): FORCE
	$(call cmd_change_chk,$(call do_dlib,$($*:%=$(bdir)%),$(bdir)$*),$@)

$(ROBJ:%=$(bdir)%): $(bdir)%: $(bdir)%$(SFX_CMD)
	$(call msg,LD,$*)
	$(call do_robj,$($*:%=$(bdir)%),$@)

$(SLIB:%=$(bdir)%): $(bdir)%: $(bdir)%$(SFX_CMD)
	$(call msg,AR,$*)
	$(call do_slib,$($*:%=$(bdir)%),$@)

$(DLIB:%=$(bdir)%): $(bdir)%: $(bdir)%$(SFX_CMD)
	$(call msg,LD,$*)
	$(call do_dlib,$($*:%=$(bdir)%),$@)

$(OLST)$(SFX_CMD): FORCE
	$(call cmd_change_chk,$(call do_olst,$(MOD:%=$(reldir)$(bdir)%) `cat $(SOLST) /dev/null`,$(OLST)),$@)

$(OLST): $(MOD:%=$(bdir)%) $(SOLST) $(OLST)$(SFX_CMD)
	$(call do_olst,$(MOD:%=$(reldir)$(bdir)%) `cat $(SOLST) /dev/null`,$@)

$(SOLST): %/$(OLST): build-%;

$(SOLST:%/$(OLST)=build-%): build-%: FORCE
	$(call msg2,CD,$*/)
	$(MAKE) -f $(topdir)rule.mk -C $* $(OLST)

endif	# ifeq ($(EXTR_SEG),R)
