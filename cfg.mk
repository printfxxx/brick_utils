#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		cfg.mk
# Brief		Configuration for brick_utils.
#

# === Project Configuration ===
# Project name
project = brick_utils

# === Objs, subdirs, targets ===
obj-$(CONFIG_MTOOL)      += mtool/
obj-$(CONFIG_SIMPLEBITS) += simplebits/

out-$(CONFIG_MTOOL)  += mtool
out-$(CONFIG_SB_CLI) += sb_cli

mtool	 = mtool/
sb_cli = simplebits/cli/

# === Flags For Compiler & Linker ===
# Flags to give to C compiler
CFLAGS = -O0 -g3 -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs \
	 -Werror-implicit-function-declaration -Wno-format-security -Wno-sign-compare \
	 -Wno-unused-but-set-variable -Wdeclaration-after-statement -Wno-pointer-sign \
	 --sysroot=$(SDK_SYSROOT) -I$(topdir)mtrace
# Flags to give to assembler
ASFLAGS =
# Flags to give to C++ compiler
CXXFLAGS =
# Flags to give to linker
LDFLAGS = --sysroot=$(SDK_SYSROOT)
ldflags_sb_cli += -lpcap

# === Mconf Options ===
# Mconf config file
mcfg = Kconfig
MCONF = opt/mconf

ifeq ($(CONFIG_MTRACE),y)
obj-y += mtrace/

CFLAGS  += -DMTRACE
LDFLAGS += -L$(topdir)mtrace/$(bdir) -lpthread -lmtrace

$(ldout:%=build-%): build-mtrace
endif

ifneq ($(filter kconfig,$(MAKECMDGOALS)),)
NOMCFG_TARGET = kconfig
CROSS_COMPILE =
obj-y = kconfig/
out-y = mconf
mconf = kconfig/
NCURSES_INC = $(firstword $(dir $(wildcard /usr/include/ncursesw/ncurses.h /usr/include/ncurses/ncurses.h /usr/include/ncurses.h)))

CFLAGS = -O2 -g3 -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs \
	 -Werror-implicit-function-declaration -Wno-format-security -Wno-sign-compare \
	 -Wno-unused-but-set-variable -Wdeclaration-after-statement -Wno-pointer-sign \
	 -DCURSES_LOC="<ncurses.h>" -I$(NCURSES_INC)
CFLAGS += $(if $(findstring ncursesw,$(NCURSES_INC)),-DNCURSES_WIDECHAR=1)
LDFLAGS = $(if $(findstring ncursesw,$(NCURSES_INC)),-lncursesw,-lncurses)
endif

kconfig: all

help::
	echo ''
	echo 'KCONFIG'
	echo -e '$(GREEN)kconfig$(NORMAL)'
	echo -e '\tBuild kconfig tool'

.PHONY: kconfig
