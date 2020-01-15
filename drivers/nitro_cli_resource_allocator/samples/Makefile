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

# Usage example for the resource allocation driver for Nitro CLI.

CC=gcc
CFLAGS=-I../include/uapi -Wall

.PHONY: all
all: nitro_cli_resource_allocator_sample

.PHONY: nitro_cli_resource_allocator_sample
nitro_cli_resource_allocator_sample: nitro_cli_resource_allocator_sample.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f nitro_cli_resource_allocator_sample
