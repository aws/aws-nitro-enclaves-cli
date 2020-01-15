# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# Resource allocation driver for Nitro CLI.
#
# TODO: Compile based on entry in menu config for nitro cli resource allocator.

.PHONY: all clean

obj-m += nitro_cli_resource_allocator.o

ccflags-y := -I$(src)/include
ccflags-y += -Wall

KERNEL_RELEASE := $(shell uname -r)

KERNEL_BUILD_DIR := "/lib/modules/$(KERNEL_RELEASE)/build"

all:
	@if [ ! -d "$(KERNEL_BUILD_DIR)" ] ; then \
		echo "$(KERNEL_BUILD_DIR) not present, install kernel-devel package for $(KERNEL_RELEASE)"; \
	fi
	$(MAKE) -C $(KERNEL_BUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KERNEL_BUILD_DIR) M=$(shell pwd) clean
