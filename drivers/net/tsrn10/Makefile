include $(RTE_SDK)/mk/rte.vars.mk

LIB = librte_pmd_tsrn10.a

ifdef DO_BUILD
include $(SWD)/.define.mk
CFLAGS += -I./ -I$(SWD)/src/
RTE_TARGET = $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))
RTE_SDK ?=/usr/local/share/dpdk/
endif

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g -DDEBUG
else
CFLAGS += -O3 -g
endif

CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I./ -Wno-unused-parameter -Wno-unused-function

CFLAGS += -I$(RTE_SDK)/drivers/net/tsrn10/

EXPORT_MAP := rte_pmd_tsrn10_version.map

VPATH += $(SRCDIR)/base

SRCS-y += tsrn10_ethdev.c\
	  tsrn10_rxtx.c \
	  tsrn10_flow.c \
	  tsrn10_mbx.c \
	  tsrn10_mbx_fw.c\
	  tsrn10_api.c \
	  tsrn10_pcs.c \
	  tsrn10_phy.c

SRCS-y += tsrn10_vf.c

ifeq ($(CONFIG_RTE_ARCH_ARM64),y)
SRCS-y += tsrn10_rxtx_vec_neon.c
else ifeq ($(CONFIG_RTE_ARCH_PPC_64),y)
else ifeq ($(CONFIG_RTE_ARCH_LOONGSON),y)
else ifeq ($(CONFIG_RTE_ARCH_X86_64),y)
SRCS-y += tsrn10_rxtx_vec_sse.c
#SRCS-$(CONFIG_RTE_LIBRTE_TSRN10_PMD) += tsrn10_rxtx_vec_avx2.c
else
endif

SRCS-$(CONFIG_RTE_LIBRTE_IEEE1588)  += tsrn10_ptp.c

# vector PMD driver needs SSE4.1 support
ifeq ($(findstring RTE_MACHINE_CPUFLAG_SSE4_1,$(CFLAGS)),)
CFLAGS_tsrn10_rxtx_vec_sse.o += -msse4.1
endif

USE_LDLIBS=n
ifneq ($(origin LIBABIVER),undefined)
ifneq ($(shell test $(LIBABIVER) -eq 1 && echo 1), 1)
USE_LDLIBS=y
endif
else
USE_LDLIBS=y
endif
ifeq ($(USE_LDLIBS),y)
LDFLAGS += --no-undefined
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_kvargs
LDLIBS += -lrte_ethdev -lrte_net
LDLIBS += -lrte_bus_pci
else
DEPDIRS-$(CONFIG_RTE_LIBRTE_TSRN10_PMD) += lib/librte_eal lib/librte_ether
DEPDIRS-$(CONFIG_RTE_LIBRTE_TSRN10_PMD) += lib/librte_mempool lib/librte_mbuf
DEPDIRS-$(CONFIG_RTE_LIBRTE_TSRN10_PMD) += lib/librte_net
DEPDIRS-$(CONFIG_RTE_LIBRTE_TSRN10_PMD) += lib/librte_kvargs
endif

ifdef DO_BUILD
ifeq ($(CONFIG_RTE_BUILD_SHARED_LIB),y)
include $(RTE_SDK)mk/rte.extshared.mk
else
include $(RTE_SDK)/mk/rte.lib.mk
endif
else
include $(RTE_SDK)/mk/rte.lib.mk
endif

ifdef DO_BUILD
install:
	@echo $(RTE_OUTPUT)
	install -m 755 $(RTE_OUTPUT)/lib/$(SHARED)$(LIB) $(RTE_SDK)/$(RTE_TARGET)/lib/

clean:
	$(RM) _postclean

remove:
	$(RM) $(RTE_SDK)/$(RTE_TARGET)/lib/$(SHARED)$(LIB)
endif
