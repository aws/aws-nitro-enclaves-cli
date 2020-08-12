/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#ifndef _NE_MISC_DEV_H_
#define _NE_MISC_DEV_H_

#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/version.h>
#include <linux/wait.h>

/**
 * The type '__poll_t' is not available in kernels older than 4.16.0
 * so for these we define it here.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#define __poll_t unsigned int
#endif

/**
 * struct ne_mem_region - Entry in the enclave user space memory regions list.
 * @mem_region_list_entry:	Entry in the list of enclave memory regions.
 * @memory_size:		Size of the user space memory region.
 * @nr_pages:			Number of pages that make up the memory region.
 * @pages:			Pages that make up the user space memory region.
 * @userspace_addr:		User space address of the memory region.
 */
struct ne_mem_region {
	struct list_head	mem_region_list_entry;
	u64			memory_size;
	unsigned long		nr_pages;
	struct page		**pages;
	u64			userspace_addr;
};

/**
 * struct ne_enclave - Per-enclave data used for enclave lifetime management.
 * @avail_cpu_cores:		Available CPU cores for the enclave.
 * @avail_cpu_cores_size:	The size of the available cores array.
 * @enclave_info_mutex :	Mutex for accessing this internal state.
 * @enclave_list_entry :	Entry in the list of created enclaves.
 * @eventq:			Wait queue used for out-of-band event notifications
 *				triggered from the PCI device event handler to
 *				the enclave process via the poll function.
 * @has_event:			Variable used to determine if the out-of-band event
 *				was triggered.
 * @max_mem_regions:		The maximum number of memory regions that can be
 *				handled by the hypervisor.
 * @mem_regions_list:		Enclave user space memory regions list.
 * @mem_size:			Enclave memory size.
 * @mm :			Enclave process abstraction mm data struct.
 * @nr_mem_regions:		Number of memory regions associated with the enclave.
 * @nr_vcpus:			Number of vcpus associated with the enclave.
 * @numa_node:			NUMA node of the enclave memory and CPUs.
 * @pdev:			PCI device used for enclave lifetime management.
 * @slot_uid:			Slot unique id mapped to the enclave.
 * @state:			Enclave state, updated during enclave lifetime.
 * @vcpu_ids:			Enclave vCPUs.
 */
struct ne_enclave {
	cpumask_var_t		*avail_cpu_cores;
	unsigned int		avail_cpu_cores_size;
	struct mutex		enclave_info_mutex;
	struct list_head	enclave_list_entry;
	wait_queue_head_t	eventq;
	bool			has_event;
	u64			max_mem_regions;
	struct list_head	mem_regions_list;
	u64			mem_size;
	struct mm_struct	*mm;
	u64			nr_mem_regions;
	u64			nr_vcpus;
	int			numa_node;
	struct pci_dev		*pdev;
	u64			slot_uid;
	u16			state;
	cpumask_var_t		vcpu_ids;
};

/**
 * enum ne_state - States available for an enclave.
 * @NE_STATE_INIT:	The enclave has not been started yet.
 * @NE_STATE_RUNNING:	The enclave was started and is running as expected.
 * @NE_STATE_STOPPED:	The enclave exited without userspace interaction.
 */
enum ne_state {
	NE_STATE_INIT		= 0,
	NE_STATE_RUNNING	= 2,
	NE_STATE_STOPPED	= U16_MAX,
};

/* Nitro Enclaves (NE) misc device */
extern struct miscdevice ne_misc_dev;

#endif /* _NE_MISC_DEV_H_ */
