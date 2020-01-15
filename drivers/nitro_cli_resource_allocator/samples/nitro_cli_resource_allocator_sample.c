// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Usage example for the resource allocation driver for Nitro CLI.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/nitro_cli_resource_allocator.h>

#define DECIMAL_BASE 10

void print_usage(char *executable_name) {
	printf("Usage: %s <slot_uid> <mem_size> <mem_regions_count> "
	       "<alloc/free_loop_count>\n", executable_name);
	printf("slot_uid - Slot to allocate/free memory region(s) for.\n");
	printf("mem_size - Memory size of the memory region; the value "
	       "is in bytes.\n");
	printf("mem_regions_count - Number of memory regions to alloc for "
	       "the slot.\n");
	printf("alloc/free_loop_count - Number of alloc/free memory regions "
	       "flows to run in a loop.\n");

	return;
}

void init_slot_mem_region(struct nitro_cli_slot_mem_region *slot_mem_region,
			  __u64 slot_uid, __u64 mem_size) {

	memset(slot_mem_region, 0, sizeof(*slot_mem_region));
	slot_mem_region->slot_uid = slot_uid;
	slot_mem_region->mem_size = mem_size;
}

int main(int argc, char *argv[]) {
	unsigned int i = 0;
	unsigned int j = 0;
	unsigned int loop_count = 0;
	unsigned int mem_regions_count = 0;
	__u64 mem_size = 0;
	int nitro_cli_resource_allocator_fd = -1;
	struct nitro_cli_slot_mem_region slot_mem_region;
	int rc = -1;
	__u64 slot_uid = 0;

	if (argc != 5) {
		print_usage(argv[0]);

		goto err;
	}

	slot_uid = strtoull(argv[1], NULL, DECIMAL_BASE);
	mem_size = strtoull(argv[2], NULL, DECIMAL_BASE);
	mem_regions_count = strtoul(argv[3], NULL, DECIMAL_BASE);
	loop_count = strtoul(argv[4], NULL, DECIMAL_BASE);

	nitro_cli_resource_allocator_fd =
		open("/dev/nitro_cli_resource_allocator", O_RDWR | O_CLOEXEC);

	if (nitro_cli_resource_allocator_fd < 0) {
		printf("Failure in opening resource allocator device: %m\n");

		goto err;
	}

	init_slot_mem_region(&slot_mem_region, slot_uid, mem_size);

	for (i = 0; i < loop_count; i++) {
		for (j = 0; j < mem_regions_count; j++) {
			rc = ioctl(nitro_cli_resource_allocator_fd,
				   NITRO_CLI_SLOT_ALLOC_MEMORY,
				   &slot_mem_region);

			if (rc < 0) {
				printf("Failure in NITRO_CLI_SLOT_ALLOC_MEMORY ioctl: %m, "
				       "loop_count iterator = %du, "
				       "mem_regions_count iterator = %du\n",
				       i, j);

				goto ioctl_alloc_err;
			}

			if (slot_mem_region.mem_gpa == 0) {
				printf("mem_gpa value was not updated during ALLOC_MEMORY, "
				       "loop_count iterator = %du, "
				       "mem_regions_count iterator = %du\n",
				       i, j);

				goto ioctl_alloc_err;
			}

			if (slot_mem_region.slot_uid != slot_uid) {
				printf("slot_uid value was updated during ALLOC_MEMORY, "
				       "loop_count iterator = %du, "
				       "mem_regions_count iterator = %du\n",
				       i, j);

				goto ioctl_alloc_err;
			}
		}

		rc = ioctl(nitro_cli_resource_allocator_fd,
			   NITRO_CLI_SLOT_FREE_RESOURCES,
			   &slot_uid);

		if (rc < 0) {
			printf("Failure in NITRO_CLI_SLOT_FREE_RESOURCES ioctl: %m, "
			       "loop_count iterator = %du, "
			       "mem_regions_count iterator = %du\n",
			       i, j);

			goto ioctl_free_err;
		}
	}


	close(nitro_cli_resource_allocator_fd);

	return 0;

ioctl_alloc_err:
	ioctl(nitro_cli_resource_allocator_fd,
	      NITRO_CLI_SLOT_FREE_RESOURCES,
	      &slot_uid);
ioctl_free_err:
	close(nitro_cli_resource_allocator_fd);
err:
	return -1;
}
