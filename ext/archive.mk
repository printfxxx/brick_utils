#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		archive.mk
# Brief		Archiving tools support.
#

ifeq ($(EXTMF_SEG),V)

ARV_DIR  = $(notdir $(topdir:%/=%))
ARV_GZ	 = $(optdir)$(project).tar.gz
ARV_BZ2  = $(optdir)$(project).tar.bz2
ARV_XZ	 = $(optdir)$(project).tar.xz
ARV_ZIP  = $(optdir)$(project).zip
ARV_DGZ  = $(optdir)$(project).$(YEAR)$(MONTH)$(DAY).tar.gz
ARV_DBZ2 = $(optdir)$(project).$(YEAR)$(MONTH)$(DAY).tar.bz2
ARV_DXZ  = $(optdir)$(project).$(YEAR)$(MONTH)$(DAY).tar.xz
ARV_DZIP = $(optdir)$(project).$(YEAR)$(MONTH)$(DAY).zip

NOINIT_TARGET += gz bz2 xz zip d-gz d-bz2 d-xz d-zip

endif	# ifeq ($(EXTMF_SEGXTMF_SEG),V)

ifeq ($(EXTMF_SEG),R)

gz:
	$(call msg,TAR,$(ARV_GZ:$(optdir)%=%))
	cd $(topdir).. && \
	tar czf $(ARV_GZ) $(ARV_DIR) --exclude $(ARV_DIR)/$(ARV_GZ:$(topdir)%=%)

bz2:
	$(call msg,TAR,$(ARV_BZ2:$(optdir)%=%))
	cd $(topdir).. && \
	tar cjf $(ARV_BZ2) $(ARV_DIR) --exclude $(ARV_DIR)/$(ARV_BZ2:$(topdir)%=%)

xz:
	$(call msg,TAR,$(ARV_XZ:$(optdir)%=%))
	cd $(topdir).. && \
	tar cJf $(ARV_XZ) $(ARV_DIR) --exclude $(ARV_DIR)/$(ARV_XZ:$(topdir)%=%)

zip:
	$(call msg,ZIP,$(ARV_ZIP:$(optdir)%=%))
	cd $(topdir).. && \
	zip -qr - $(ARV_DIR) -x $(ARV_DIR)/$(ARV_ZIP:$(topdir)%=%) > $(ARV_ZIP) || ($(RM) $(ARV_ZIP); false)

d-gz:
	$(call msg,TAR,$(ARV_DGZ:$(optdir)%=%))
	cd $(topdir).. && \
	tar czf $(ARV_DGZ) $(ARV_DIR) --exclude $(ARV_DIR)/$(ARV_DGZ:$(topdir)%=%)

d-bz2:
	$(call msg,TAR,$(ARV_DBZ2:$(optdir)%=%))
	cd $(topdir).. && \
	tar cjf $(ARV_DBZ2) $(ARV_DIR) --exclude $(ARV_DIR)/$(ARV_DBZ2:$(topdir)%=%)

d-xz:
	$(call msg,TAR,$(ARV_DXZ:$(optdir)%=%))
	cd $(topdir).. && \
	tar cJf $(ARV_DXZ) $(ARV_DIR) --exclude $(ARV_DIR)/$(ARV_DXZ:$(topdir)%=%)

d-zip:
	$(call msg,ZIP,$(ARV_DZIP:$(optdir)%=%))
	cd $(topdir).. && \
	zip -qr - $(ARV_DIR) -x $(ARV_DIR)/$(ARV_DZIP:$(topdir)%=%) > $(ARV_DZIP) || ($(RM) $(ARV_DZIP); false)

help::
	echo ''
	echo 'ARCHIVE'
	echo -e '$(GREEN)gz$(NORMAL)'
	echo -e '\tArchiving project into a ".tar.gz" file'
	echo -e '$(GREEN)bz2$(NORMAL)'
	echo -e '\tArchiving project into a ".tar.bz2" file'
	echo -e '$(GREEN)xz$(NORMAL)'
	echo -e '\tArchiving project into a ".tar.xz" file'
	echo -e '$(GREEN)zip$(NORMAL)'
	echo -e '\tArchiving project into a ".zip" file'
	echo -e '$(GREEN)d-gz$(NORMAL)'
	echo -e '\tArchiving project into a ".<date>.tar.gz" file'
	echo -e '$(GREEN)d-bz2$(NORMAL)'
	echo -e '\tArchiving project into a ".<date>.tar.bz2" file'
	echo -e '$(GREEN)d-xz$(NORMAL)'
	echo -e '\tArchiving project into a ".<date>.tar.xz" file'
	echo -e '$(GREEN)d-zip$(NORMAL)'
	echo -e '\tArchiving project into a ".<date>.zip" file'

.PHONY: gz bz2 xz zip d-gz d-bz2 d-xz d-zip

endif	# ifeq ($(EXTMF_SEGXTMF_SEG),R)
