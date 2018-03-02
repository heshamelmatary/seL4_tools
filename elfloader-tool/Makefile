#
# Copyright 2017, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the GNU General Public License version 2. Note that NO WARRANTY is provided.
# See "LICENSE_GPLv2.txt" for details.
#
# @TAG(DATA61_GPL)
#
#
# Targets
TARGETS := elfloader.o

# Source files required to build the target
CFILES   := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/*.c))
CFILES   += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/arch-$(ARCH)/*.c))

CFILES   += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/arch-$(ARCH)/elf/*.c))
CFILES   += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/arch-$(ARCH)/plat-$(PLAT)/*.c))
CFILES   += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/arch-$(ARCH)/*.c))

ASMFILES := $(patsubst $(SOURCE_DIR)/%,%,$(SOURCE_DIR)/src/arch-$(ARCH)/crt0.S)

NK_CFLAGS += -D_XOPEN_SOURCE=700

ifeq (${ARCH}, riscv)
CFLAGS   += -nodefaultlibs -mcmodel=medany -nostdinc
ifeq (${KERNEL_32}, y)
CFLAGS   += -march=rv32ima -mabi=ilp32 -fno-pic
else
CFLAGS   += -march=rv64imac -mabi=lp64
endif
else
CFLAGS   += -nodefaultlibs
endif

#ASFLAGS   += -nodefaultlibs
LDFLAGS = -nodefaultlibs
#LDFLAGS = -nodefaultlibs -nostdlib

ifeq ($(ARMV),armv5)
ASMFILES += $(patsubst $(SOURCE_DIR)/%,%,$(SOURCE_DIR)/src/arch-$(ARCH)/mmu-v5.S)
endif
ifeq ($(ARMV),armv6)
ASMFILES += $(patsubst $(SOURCE_DIR)/%,%,$(SOURCE_DIR)/src/arch-$(ARCH)/mmu-v6.S)
endif
ifeq ($(ARMV),armv7-a)
ASMFILES += $(patsubst $(SOURCE_DIR)/%,%,$(SOURCE_DIR)/src/arch-$(ARCH)/smc.S)
ASMFILES += $(patsubst $(SOURCE_DIR)/%,%,$(SOURCE_DIR)/src/arch-$(ARCH)/mmu-v7a.S)
ASMFILES += $(patsubst $(SOURCE_DIR)/%,%,$(SOURCE_DIR)/src/arch-$(ARCH)/mmu-v7a-hyp.S)
endif

#INCLUDE_DIRS += $(SOURCE_DIR)/src/arch-arm/plat-$(PLAT)/
INCLUDE_DIRS += $(SOURCE_DIR)/include/
INCLUDE_DIRS += $(SOURCE_DIR)/src/arch-riscv/
INCLUDE_DIRS += $(SOURCE_DIR)/src/arch-riscv/plat-$(PLAT)/

LIBS = cpio

NK_CFLAGS += -ffreestanding -Wall -W
NK_CFLAGS +=

include $(SEL4_COMMON)/common.mk

#
# We produce a partially linked object file here which, to be used, will be
# eventually relinked with the compiled kernel and user images forming
# a bootable ELF file.
#
elfloader.o: $(OBJFILES)
	@echo " [LINK] $@"
	${Q}$(CC) -r $^ $(LDFLAGS) -o $@
