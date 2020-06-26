# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.

# Enclave lifetime management support for Nitro Enclaves (NE).

obj-m += nitro_enclaves.o

nitro_enclaves-y := ne_pci_dev.o ne_misc_dev.o

ccflags-y += -Wall -I$(src)/../../../include

KERNEL_RELEASE := $(shell uname -r)

KERNEL_BUILD_DIR := "/lib/modules/$(KERNEL_RELEASE)/build"

all:
	@if [ ! -d "$(KERNEL_BUILD_DIR)" ] ; then \
		echo "$(KERNEL_BUILD_DIR) not present, install kernel-devel package for $(KERNEL_RELEASE)"; \
	fi
		$(MAKE) -C $(KERNEL_BUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KERNEL_BUILD_DIR) M=$(shell pwd) clean
