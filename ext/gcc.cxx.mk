#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		gcc.cxx.mk
# Brief		Rules for compile C++ files with gcc.
#

ifeq ($(EXTMF_SEG),V)

export CXXFLAGS CXXFLAGS-y

endif	# ifeq ($(EXTMF_SEG),V)

ifeq ($(EXTR_SEG),V)

define cxx_cmd_wrapper
$(call $(1),$(2),$(bdir)$(3),$(_cflags) $(_cxxflags) $(cflags_$(3)))
endef

CXXSRC = $(wildcard $(OBJ:%$(SFX_O)=%$(SFX_CXX)))
CXXOBJ = $(CXXSRC:%$(SFX_CXX)=%$(SFX_O))

_CXXFLAGS = $(CXXFLAGS) $(CXXFLAGS-y)
cxxflags  = $(_CXXFLAGS)
_cxxflags = $(cxxflags) $(cxxflags-y)

endif	# ifeq ($(EXTR_SEG),V)

ifeq ($(EXTR_SEG),R)

ifeq ($(filter $(NOINIT_TARGET),$(MAKECMDGOALS)),)
$(foreach f,$(CXXSRC),$(eval $(call cxx_cmd_wrapper,rule_cc_dep,$(f),$(f:%$(SFX_CXX)=%$(SFX_O)))))
endif

$(CXXOBJ:%=$(bdir)%$(SFX_D)): %$(SFX_D): %$(SFX_CMD)

$(CXXOBJ:%=$(bdir)%$(SFX_CMD)): $(bdir)%$(SFX_CMD): FORCE
	$(call cmd_change_chk,$(call cxx_cmd_wrapper,do_cc,$(*:%$(SFX_O)=%$(SFX_CXX)),$*),$@)

$(CXXOBJ:%=$(bdir)%): $(bdir)%: $(bdir)%$(SFX_D)
	$(call msg,CC,$(*:%$(SFX_O)=%$(SFX_CXX)))
	$(call cxx_cmd_wrapper,do_cc,$(*:%$(SFX_O)=%$(SFX_CXX)),$*)

endif	# ifeq ($(EXTR_SEG),V)
