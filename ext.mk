#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		ext.mk
# Brief		Extra makefile and rule list.
#

# Makefile Configuration
# Extra makefile list
EXTMF_LIST  = $(topdir)ext/mconf.mk
EXTMF_LIST += $(topdir)ext/gcc.mk
EXTMF_LIST += $(topdir)ext/gcc.h.mk
EXTMF_LIST += $(topdir)ext/gcc.c.mk
EXTMF_LIST += $(topdir)ext/gcc.asm.mk
EXTMF_LIST += $(topdir)ext/gcc.cxx.mk
EXTMF_LIST += $(topdir)ext/archive.mk
# Extra rule list
EXTR_LIST += $(topdir)ext/gcc.mk
EXTR_LIST += $(topdir)ext/gcc.c.mk
EXTR_LIST += $(topdir)ext/gcc.asm.mk
EXTR_LIST += $(topdir)ext/gcc.cxx.mk
EXTR_LIST += $(topdir)ext/kmod.mk

export EXTR_LIST
