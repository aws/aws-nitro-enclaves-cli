# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Enclave lifetime management support for Nitro Enclaves (NE).

obj-m += nitro_enclaves.o

nitro_enclaves-y := ne_pci_dev.o ne_main.o

ccflags-y += -Wall -I$(src)/../../../../include

KERNEL_RELEASE := $(shell uname -r)

KERNEL_BUILD_DIR := "/lib/modules/$(KERNEL_RELEASE)/build"

all:
	@if [ ! -d "$(KERNEL_BUILD_DIR)" ] ; then \
		echo "$(KERNEL_BUILD_DIR) not present, install kernel-devel package for $(KERNEL_RELEASE)"; \
	fi
		$(MAKE) -C $(KERNEL_BUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KERNEL_BUILD_DIR) M=$(shell pwd) clean