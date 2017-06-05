#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		Makefile
# Brief		Main makefile for Bmake.
#

BASH := $(shell which bash)
ifneq ($(BASH),)
SHELL = $(BASH)
else
$(error BASH not found!)
endif

.DEFAULT_GOAL = all

topdir	= $(CURDIR)/
optdir	= $(topdir)opt/
gendir	= $(topdir)gen/
tooldir = $(topdir)tools/

$(shell mkdir -p $(optdir) $(gendir))

MAKEFLAGS = -R -r
NOINIT_TARGET = clean distclean help

include ext.mk

ifneq ($(V),1)
MAKEFLAGS += -s
endif

EXTMF_SEG := V
include $(EXTMF_LIST)
EXTMF_SEG :=

include rule.mk

all:

help::
	echo ''
	echo 'GET HELP'
	echo -e '$(GREEN)help$(NORMAL)'
	echo -e '\tPrint this help'
	echo ''
	echo 'BUILD TARGETS'
	echo -e '$(GREEN)all$(NORMAL)'
	echo -e '\tDefault target'
	echo ''
	echo 'DO CLEAN'
	echo -e '$(GREEN)clean$(NORMAL)'
	echo -e '\tRemove all files created by build'
	echo -e '$(GREEN)distclean$(NORMAL)'
	echo -e '\tRemove all non-source files'
	echo ''
	echo 'SPECIAL VARIABLE'
	echo -e '$(GREEN)V$(NORMAL)'
	echo -e '\tSet variable "V=1" to print verbose information when make'
	echo -e '$(GREEN)C$(NORMAL)'
	echo -e '\tSet variable "C=0" to disable print message with color'

clean::
	$(call msg,RM,$(gendir:$(topdir)%=%))
	shopt -s dotglob && $(RM) $(gendir)*
	$(call msg,RM,$(optdir:$(topdir)%=%))
	shopt -s dotglob && $(RM) $(optdir)*
	$(call msg,RM,$(bdir))
	$(RM) `find . -name "$(bdir:%/=%)" -type d`

distclean:: clean
	$(call msg,RM,tags \& cscope.out)
	$(RM) tags cscope*.out

EXTMF_SEG := R
include $(EXTMF_LIST)
EXTMF_SEG :=

export topdir optdir BASH MAKE

.PHONY: all help clean distclean
