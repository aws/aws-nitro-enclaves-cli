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
 * Resource allocation driver for Nitro CLI.
 */

#include <linux/file.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/kvm_host.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "resource_allocator.h"

#define MEM_REGION_HLIST_BITS 8
#define MEM_REGION_HLIST_SIZE (1 << MEM_REGION_HLIST_BITS)

#define CPU_MAPPING_HLIST_BITS 8
#define CPU_MAPPING_HLIST_SIZE (1 << CPU_MAPPING_HLIST_BITS)

struct nitro_cli_mem_region {
	struct hlist_node hlist_node;
	struct nitro_cli_slot_mem_region slot_mem_region;
};

struct nitro_cli_cpu_mapping {
	struct hlist_node hlist_node;
	struct nitro_cli_slot_cpu_mapping slot_cpu_mapping;
};

/* Hashtable with nitro_cli_mem_region entries and slot uid as key. */
static struct hlist_head mem_region_htable[MEM_REGION_HLIST_SIZE];

/* Hashtable with nitro_cli_cpu_mapping entries and slot uid as key. */
static struct hlist_head cpu_mapping_htable[CPU_MAPPING_HLIST_SIZE];

static struct mutex nitro_cli_resource_allocator_lock;

static int nitro_cli_mem_alloc_x86_mem_size_policy(__u64 *mem_size)
{
#define ALLOCATION_SIZE (2 * 1024UL * 1024UL)
	if (!mem_size)
		return -EINVAL;

	/* For x86, have mem_size multiple of 2 MiB. */
	if (*mem_size % ALLOCATION_SIZE != 0)
		*mem_size = ALIGN(*mem_size, ALLOCATION_SIZE);

	return 0;
}

/*
 * nitro_cli_mem_region_alloc - Allocate memory pages for the
 * given slot uid and memory size.
 *
 * @slot_uid: slot uid to allocate memory pages for.
 * @mem_size: size (in bytes) of the memory region to allocate for the
 *	      given slot.
 * @mem_gpa: gpa of the memory region that was allocated for the slot.
 *
 * @returns: 0 on success, negative errno value on failure.
 */
static int nitro_cli_mem_region_alloc(__u64 slot_uid, __u64 mem_size,
				      __u64 *mem_gpa)
{
	void *mem_region;
	struct nitro_cli_mem_region *mem_region_htable_entry;

	if (!mem_gpa)
		return -EINVAL;

	mem_region_htable_entry = kzalloc(sizeof(*mem_region_htable_entry),
					   GFP_KERNEL);

	if (!mem_region_htable_entry)
		return -ENOMEM;

	mem_region = alloc_pages_exact(mem_size,
				       GFP_USER | __GFP_ZERO | __GFP_NOWARN);

	if (!mem_region) {
		kfree(mem_region_htable_entry);

		return -ENOMEM;
	}

	*mem_gpa = virt_to_phys(mem_region);

	mem_region_htable_entry->slot_mem_region.slot_uid = slot_uid;
	mem_region_htable_entry->slot_mem_region.mem_gpa = *mem_gpa;
	mem_region_htable_entry->slot_mem_region.mem_size = mem_size;

	hash_add(mem_region_htable, &mem_region_htable_entry->hlist_node,
		 slot_uid);

	return 0;
}

/*
 * nitro_cli_mem_region_free - Free allocated memory pages for the given
 * slot uid.
 *
 * @slot_uid: slot uid to free memory pages for.
 */
static void nitro_cli_mem_region_free(__u64 slot_uid)
{
	__u64 mem_gpa;
	struct nitro_cli_mem_region *mem_region_htable_entry;
	__u64 mem_size;
	struct nitro_cli_slot_mem_region *slot_mem_region;
	__u64 slot_uid_entry;
	struct hlist_node *tmp;

	hash_for_each_possible_safe(mem_region_htable,
				    mem_region_htable_entry,
				    tmp, hlist_node, slot_uid) {
		slot_mem_region = &mem_region_htable_entry->slot_mem_region;
		slot_uid_entry = slot_mem_region->slot_uid;

		if (slot_uid_entry == slot_uid) {
			mem_gpa = slot_mem_region->mem_gpa;
			mem_size = slot_mem_region->mem_size;

			hash_del(&mem_region_htable_entry->hlist_node);

			if (mem_size > 0)
				free_pages_exact(phys_to_virt(mem_gpa),
						 mem_size);

			kfree(mem_region_htable_entry);
		}
	}
}

/*
 * nitro_cli_cpu_mapping_set - Set the mapping between the slot uid and the
 * cpus allocated to that slot.
 *
 * @req_slot_cpu_mapping: slot uid - cpu mapping received from the user; the
 *			  mapping is updated to have info on all allocated
 *			  cpus for the given slot uid.
 *
 * @returns: 0 on success, negative errno value on failure.
 */
static int nitro_cli_cpu_mapping_set(
	struct nitro_cli_slot_cpu_mapping *req_slot_cpu_mapping)
{
	int cpu_mask_array_size;
	struct nitro_cli_cpu_mapping *cpu_mapping_htable_entry;
	unsigned int i;
	struct nitro_cli_slot_cpu_mapping *slot_cpu_mapping;
	__u64 req_slot_uid, slot_uid_entry;
	struct hlist_node *tmp;

	if (!req_slot_cpu_mapping)
		return -EINVAL;

	req_slot_uid = req_slot_cpu_mapping->slot_uid;

	/*
	 * Search if the cpu mapping for the given slot is already available in
	 * the hashtable for cpu mapping. If the mapping is already created,
	 * update the cpu mask value.
	 */
	hash_for_each_possible_safe(cpu_mapping_htable,
				    cpu_mapping_htable_entry,
				    tmp, hlist_node,
				    req_slot_uid) {
		slot_cpu_mapping =
			&cpu_mapping_htable_entry->slot_cpu_mapping;
		slot_uid_entry = slot_cpu_mapping->slot_uid;

		if (slot_uid_entry == req_slot_uid) {
			cpu_mask_array_size = ARRAY_SIZE(
				slot_cpu_mapping->cpu_mask);

			for (i = 0; i < cpu_mask_array_size; i++) {
				slot_cpu_mapping->cpu_mask[i] |=
					req_slot_cpu_mapping->cpu_mask[i];

				req_slot_cpu_mapping->cpu_mask[i] =
					slot_cpu_mapping->cpu_mask[i];
			}

			return 0;
		}
	}

	/*
	 * If not found in the cpu mapping hashtable, create a cpu mapping
	 * entry for the given slot.
	 */
	cpu_mapping_htable_entry =
		kzalloc(sizeof(*cpu_mapping_htable_entry), GFP_KERNEL);

	if (!cpu_mapping_htable_entry)
		return -ENOMEM;

	cpu_mapping_htable_entry->slot_cpu_mapping.slot_uid = req_slot_uid;

	cpu_mask_array_size = ARRAY_SIZE(
		cpu_mapping_htable_entry->slot_cpu_mapping.cpu_mask);

	for (i = 0; i < cpu_mask_array_size; i++)
		cpu_mapping_htable_entry->slot_cpu_mapping.cpu_mask[i] =
			req_slot_cpu_mapping->cpu_mask[i];

	hash_add(cpu_mapping_htable, &cpu_mapping_htable_entry->hlist_node,
		 req_slot_uid);

	return 0;
}

/*
 * nitro_cli_cpu_mapping_unset - Unset the mapping between the slot uid and the
 * cpus allocated to that slot.
 *
 * @slot_uid: slot uid to unset the cpu mapping for.
 */
static void nitro_cli_cpu_mapping_unset(__u64 slot_uid)
{
	struct nitro_cli_cpu_mapping *cpu_mapping_htable_entry;
	struct nitro_cli_slot_cpu_mapping *slot_cpu_mapping;
	__u64 slot_uid_entry;
	struct hlist_node *tmp;

	hash_for_each_possible_safe(cpu_mapping_htable,
				    cpu_mapping_htable_entry,
				    tmp, hlist_node,
				    slot_uid) {
		slot_cpu_mapping =
			&cpu_mapping_htable_entry->slot_cpu_mapping;
		slot_uid_entry = slot_cpu_mapping->slot_uid;

		if (slot_uid_entry == slot_uid) {
			hash_del(&cpu_mapping_htable_entry->hlist_node);

			kfree(cpu_mapping_htable_entry);
		}
	}
}

/*
 * nitro_cli_mem_region_free_all_hashtable_entries - Free allocated
 * memory pages for all the memory region entries in the memory region
 * hashtable.
 */
static void nitro_cli_mem_region_free_all_hashtable_entries(void)
{
	unsigned int i;
	__u64 mem_gpa;
	struct nitro_cli_mem_region *mem_region_htable_entry;
	__u64 mem_size;
	struct nitro_cli_slot_mem_region *slot_mem_region;
	struct hlist_node *tmp;

	hash_for_each_safe(mem_region_htable, i, tmp, mem_region_htable_entry,
			   hlist_node) {
		slot_mem_region = &mem_region_htable_entry->slot_mem_region;
		mem_gpa = slot_mem_region->mem_gpa;
		mem_size = slot_mem_region->mem_size;

		hash_del(&mem_region_htable_entry->hlist_node);

		if (mem_size > 0)
			free_pages_exact(phys_to_virt(mem_gpa),
					 mem_size);

		kfree(mem_region_htable_entry);
	}
}

/*
 * nitro_cli_cpu_mapping_free_all_hashtable_entries - Free all cpu mapping
 * entries in the cpu mapping hashtable.
 */
static void nitro_cli_cpu_mapping_free_all_hashtable_entries(void)
{
	struct nitro_cli_cpu_mapping *cpu_mapping_htable_entry;
	unsigned int i;
	struct hlist_node *tmp;

	hash_for_each_safe(cpu_mapping_htable, i, tmp,
			   cpu_mapping_htable_entry, hlist_node) {
		hash_del(&cpu_mapping_htable_entry->hlist_node);

		kfree(cpu_mapping_htable_entry);
	}
}

long nitro_cli_resource_allocator_ioctl(struct file *file,
					       unsigned int cmd,
					       unsigned long arg)
{
	switch (cmd) {

	case NITRO_CLI_SLOT_ALLOC_MEMORY: {
		/*
		 * Allocate a memory region for the slot and the memory size
		 * given in arg.
		 */

		__u64 mem_size;
		int rc;
		struct nitro_cli_slot_mem_region slot_mem_region;
		__u64 slot_uid;

		mutex_lock(&nitro_cli_resource_allocator_lock);

		if (copy_from_user(&slot_mem_region, (void *)arg,
				   sizeof(slot_mem_region))) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return -EFAULT;
		}

		slot_uid = slot_mem_region.slot_uid;
		mem_size = slot_mem_region.mem_size;

		if (mem_size == 0) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return -EINVAL;
		}

		rc = nitro_cli_mem_alloc_x86_mem_size_policy(&mem_size);

		if (rc < 0) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return rc;
		}

		slot_mem_region.mem_size = mem_size;

		rc = nitro_cli_mem_region_alloc(slot_uid, mem_size,
						&slot_mem_region.mem_gpa);

		if (rc < 0) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return rc;
		}

		if (copy_to_user((void *)arg, &slot_mem_region,
				 sizeof(slot_mem_region))) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return -EFAULT;
		}

		mutex_unlock(&nitro_cli_resource_allocator_lock);

		return 0;

	}

	case NITRO_CLI_SLOT_SET_CPU_MAPPING: {
		/*
		 * Update the slot - cpu mapping using the slot and the cpu mask
		 * given in arg.
		 */

		int rc;
		struct nitro_cli_slot_cpu_mapping slot_cpu_mapping;

		mutex_lock(&nitro_cli_resource_allocator_lock);

		if (copy_from_user(&slot_cpu_mapping, (void *)arg,
				   sizeof(slot_cpu_mapping))) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return -EFAULT;
		}

		rc = nitro_cli_cpu_mapping_set(&slot_cpu_mapping);

		if (rc < 0) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return rc;
		}

		if (copy_to_user((void *)arg, &slot_cpu_mapping,
				 sizeof(slot_cpu_mapping))) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return -EFAULT;
		}

		mutex_unlock(&nitro_cli_resource_allocator_lock);

		return rc;
	}

	case NITRO_CLI_SLOT_FREE_RESOURCES: {
		/*
		 * Free the allocated memory regions and unset the cpu mapping
		 * for the slot given in arg.
		 */

		__u64 slot_uid;

		mutex_lock(&nitro_cli_resource_allocator_lock);

		if (copy_from_user(&slot_uid, (void *)arg,
				   sizeof(slot_uid))) {
			mutex_unlock(&nitro_cli_resource_allocator_lock);

			return -EFAULT;
		}

		nitro_cli_mem_region_free(slot_uid);
		nitro_cli_cpu_mapping_unset(slot_uid);

		mutex_unlock(&nitro_cli_resource_allocator_lock);

		return 0;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

void nitro_cli_resource_allocator_init(void)
{
	hash_init(mem_region_htable);
	hash_init(cpu_mapping_htable);

	mutex_init(&nitro_cli_resource_allocator_lock);
}

void nitro_cli_resource_allocator_exit(void)
{
	mutex_lock(&nitro_cli_resource_allocator_lock);

	nitro_cli_mem_region_free_all_hashtable_entries();
	nitro_cli_cpu_mapping_free_all_hashtable_entries();

	mutex_unlock(&nitro_cli_resource_allocator_lock);
}
