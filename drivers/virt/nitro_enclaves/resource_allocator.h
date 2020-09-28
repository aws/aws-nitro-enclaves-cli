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

#ifndef _RESOURCE_ALLOCATOR_H_
#define _RESOURCE_ALLOCATOR_H_

#include <linux/types.h>

/* Resource Allocator Interface */
#define NITRO_CLI_SLOT_ALLOC_MEMORY _IOWR('B', 0x4, struct nitro_cli_slot_mem_region)
#define NITRO_CLI_SLOT_SET_CPU_MAPPING _IOWR('B', 0x5, struct nitro_cli_slot_cpu_mapping)
#define NITRO_CLI_SLOT_FREE_RESOURCES _IOR('B', 0x6, __u64)

long nitro_cli_resource_allocator_ioctl(struct file *file,
					       unsigned int cmd,
					       unsigned long arg);
void nitro_cli_resource_allocator_init(void);
void nitro_cli_resource_allocator_exit(void);

/* Memory region that is allocated for a given slot. */
struct nitro_cli_slot_mem_region {
	/* Slot UID to add memory regions to. */
	__u64 slot_uid;
	/* GPA of the allocated memory region. */
	__u64 mem_gpa;
	/* Memory size, in bytes, of the memory region to allocate. */
	__u64 mem_size;
};

/* Mapping between cpu and slot uid */
struct nitro_cli_slot_cpu_mapping {
	/* Slot UID to which this cpu should be added */
	__u64 slot_uid;
	/*
	 * Bit mask of cpus to be allocated to the slot, it returns the
	 * cpus already allocated to the slot.
	 */
	__u64 cpu_mask[4];
};

#endif