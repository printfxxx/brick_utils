#
# Copyright (C) 2011
#
# Brick Yang <printfxxx@163.com>
#
# This program is free software. You can redistribute it and/or
# modify it as you like.
#

##
# File		func.mk
# Brief		Functions and macros for Bmake
#

# Output message with format
# In green
define msg
echo -e '[ $(GREEN)$(1)$(NORMAL) ] '$(2)
endef
# In yellow
define msg2
echo -e '[ $(YELLOW)$(1)$(NORMAL) ] '$(2)
endef
# Output error with format
define err
echo -e '[ $(RED)$(1)$(NORMAL) ] '$(2) >&2
endef
# Escape
define escape
$(subst $(QUOTE),\$(QUOTE),$(subst \,\\,$(1)))
endef
# Unescape
define unescape
$(subst \\,\,$(subst \$(QUOTE),$(QUOTE),$(1)))
endef
# Force make target if command change
define cmd_change_chk
[ -r $(2) ] && cmp -s $(2) <<< '$(1)' || echo '$(1)' > $(2)
endef

# Remove command
RM = rm -rf

# OS type
OSTYPE := $(shell uname -o)
# Year
YEAR := $(shell date +%Y)
# Month
MONTH := $(shell date +%m)
# Day
DAY := $(shell date +%d)

# Comma
COMMA =,
# Space
SPACE := $(shell echo ' ')
# Quote
QUOTE := $(shell echo '"')

# Colors definition
ifneq ($(C),0)
NORMAL = \033[0m
LIGHT  = \033[1m
RED    = \033[0;31m
GREEN  = \033[0;32m
YELLOW = \033[0;33m
endif
