obj-$(CONFIG_SB_CORE)   += km-core
obj-$(CONFIG_SB_CLI) += cli/
obj-$(CONFIG_SB_DRIVER) += driver/

km-core = simplebits.ko

KCFLAGS = -I$(topdir)/simplebits/core -I$(topdir)mtrace

ifeq ($(CONFIG_DEBUG),y)
KCFLAGS += -DDEBUG
endif
ifeq ($(CONFIG_MTRACE),y)
KCFLAGS += -DMTRACE
endif
ifeq ($(CONFIG_QORIQ),y)
KCFLAGS += -DQORIQ
endif
ifeq ($(CONFIG_LAYERSCAPE),y)
KCFLAGS += -DLAYERSCAPE
endif
ifeq ($(CONFIG_SB_PLATFORM_TIME),y)
KCFLAGS += -DPLATFORM_TIME
endif

export KCFLAGS CONFIG_TX_DRAIN_BP

build-driver: build-core
