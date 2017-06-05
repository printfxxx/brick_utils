#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		gcc.asm.mk
# Brief		Rules for compile ASM files with gcc.
#

ifeq ($(EXTMF_SEG),V)

export ASFLAGS ASFLAGS-y

endif	# ifeq ($(EXTMF_SEG),V)

ifeq ($(EXTR_SEG),V)

define as_cmd_wrapper
$(call $(1),$(2),$(bdir)$(3),$(_cflags) $(_asflags) $(cflags_$(3)))
endef

ASRC = $(wildcard $(OBJ:%$(SFX_O)=%$(SFX_ASM)))
AOBJ = $(ASRC:%$(SFX_ASM)=%$(SFX_O))

_ASFLAGS = $(ASFLAGS) $(ASFLAGS-y)
asflags  = $(_ASFLAGS)
_asflags = $(asflags) $(asflags-y)

endif	# ifeq ($(EXTR_SEG),V)

ifeq ($(EXTR_SEG),R)

ifeq ($(filter $(NOINIT_TARGET),$(MAKECMDGOALS)),)
$(foreach f,$(ASRC),$(eval $(call as_cmd_wrapper,rule_cc_dep,$(f),$(f:%$(SFX_ASM)=%$(SFX_O)))))
endif

$(AOBJ:%=$(bdir)%$(SFX_D)): %$(SFX_D): %$(SFX_CMD)

$(AOBJ:%=$(bdir)%$(SFX_CMD)): $(bdir)%$(SFX_CMD): FORCE
	$(call cmd_change_chk,$(call as_cmd_wrapper,do_cc,$(*:%$(SFX_O)=%$(SFX_ASM)),$*),$@)

$(AOBJ:%=$(bdir)%): $(bdir)%: $(bdir)%$(SFX_D)
	$(call msg,CC,$(*:%$(SFX_O)=%$(SFX_ASM)))
	$(call cc_cmd_wrapper,do_cc,$(*:%$(SFX_O)=%$(SFX_ASM)),$*)

endif	# ifeq ($(EXTR_SEG),V)
