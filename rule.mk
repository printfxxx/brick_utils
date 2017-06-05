#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		rule.mk
# Brief		Rules in each directories.
#

SHELL = $(BASH)
include $(topdir)func.mk

# Extract all leafs recursively
define extract_all_leaf
$(foreach f,$(1),$(if $($(f)),$(call extract_all_leaf,$($(f))),$(f)))
endef
# Extract all nodes recursively
define extract_all_node
$(foreach f,$(1),$(if $($(f)),$(f) $(call extract_all_node,$($(f)))))
endef

curdir = $(CURDIR)/
reldir = $(curdir:$(topdir)%=%)
bdir   = .build/

ifeq ($(filter $(NOINIT_TARGET),$(MAKECMDGOALS)),)
$(shell mkdir -p $(bdir))
endif

EXTR_SEG := V
include $(EXTR_LIST)
EXTR_SEG :=

ifeq ($(reldir),)
include cfg.mk
else
include Makefile
endif

FORCE:

EXTR_SEG := R
include $(EXTR_LIST)
EXTR_SEG :=

.PHONY: FORCE
