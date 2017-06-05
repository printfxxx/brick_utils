#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		gcc.c.mk
# Brief		Rules for compile C files with gcc.
#

ifeq ($(EXTMF_SEG),V)

export CCFLAGS CCFLAGS-y

endif	# ifeq ($(EXTMF_SEG),V)

ifeq ($(EXTR_SEG),V)

define cc_cmd_wrapper
$(call $(1),$(2),$(bdir)$(3),$(_cflags) $(_ccflags) $(cflags_$(3)))
endef

CSRC = $(wildcard $(OBJ:%$(SFX_O)=%$(SFX_C)))
COBJ = $(CSRC:%$(SFX_C)=%$(SFX_O))

_CCFLAGS = $(CCFLAGS) $(CCFLAGS-y)
ccflags  = $(_CCFLAGS)
_ccflags = $(ccflags) $(ccflags-y)

endif	# ifeq ($(EXTR_SEG),V)

ifeq ($(EXTR_SEG),R)

ifeq ($(filter $(NOINIT_TARGET),$(MAKECMDGOALS)),)
$(foreach f,$(CSRC),$(eval $(call cc_cmd_wrapper,rule_cc_dep,$(f),$(f:%$(SFX_C)=%$(SFX_O)))))
endif

$(COBJ:%=$(bdir)%$(SFX_D)): %$(SFX_D): %$(SFX_CMD)

$(COBJ:%=$(bdir)%$(SFX_CMD)): $(bdir)%$(SFX_CMD): FORCE
	$(call cmd_change_chk,$(call cc_cmd_wrapper,do_cc,$(*:%$(SFX_O)=%$(SFX_C)),$*),$@)

$(COBJ:%=$(bdir)%): $(bdir)%: $(bdir)%$(SFX_D)
	$(call msg,CC,$(*:%$(SFX_O)=%$(SFX_C)))
	$(call cc_cmd_wrapper,do_cc,$(*:%$(SFX_O)=%$(SFX_C)),$*)

endif	# ifeq ($(EXTR_SEG),V)
