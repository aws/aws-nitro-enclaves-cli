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

/*
 * The type '__poll_t' is not available in kernels older than 4.16.0
 * so for these we define it here.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#define __poll_t unsigned int
#endif

/* Entry in memory regions list. */
struct ne_mem_region {
	struct list_head mem_region_list_entry;

	/* Number of pages that make up the memory region. */
	unsigned long nr_pages;

	/* Pages that make up the user space memory region. */
	struct page **pages;
};

/* Per-enclave data used for enclave lifetime management. */
struct ne_enclave {
	/* Available CPU cores for the enclave. */
	cpumask_var_t *avail_cpu_cores;

	/* The size of the available cores array. */
	unsigned int avail_cpu_cores_size;

	/* Mutex for accessing this internal state. */
	struct mutex enclave_info_mutex;

	struct list_head enclave_list_entry;

	/**
	 * Wait queue used for out-of-band event notifications
	 * triggered from the PCI device event handler to the enclave
	 * process via the poll function.
	 */
	wait_queue_head_t eventq;

	/* Variable used to determine if the out-of-band event was triggered. */
	bool has_event;

	/**
	 * The maximum number of memory regions that can be handled by the
	 * lower levels.
	 */
	u64 max_mem_regions;

	/* Enclave memory regions list. */
	struct list_head mem_regions_list;

	/* Enclave memory size. */
	u64 mem_size;

	/* Enclave process abstraction mm data struct. */
	struct mm_struct *mm;

	/* Number of memory regions associated with the enclave. */
	u64 nr_mem_regions;

	/* Number of vcpus associated with the enclave. */
	u64 nr_vcpus;

	/* NUMA node of the enclave memory and CPUs. */
	u32 numa_node;

	/* PCI device used for enclave lifetime management. */
	struct pci_dev *pdev;

	/* Slot unique id mapped to the enclave. */
	u64 slot_uid;

	/* Enclave state, updated during enclave lifetime. */
	u16 state;

	/* Enclave vCPUs. */
	cpumask_var_t vcpu_ids;
};

/* States available for an enclave. */
enum ne_state {
	/* NE_START_ENCLAVE ioctl was never issued for the enclave. */
	NE_STATE_INIT = 0,

	/**
	 * NE_START_ENCLAVE ioctl was issued and the enclave is running
	 * as expected.
	 */
	NE_STATE_RUNNING = 2,

	/* Enclave exited without userspace interaction. */
	NE_STATE_STOPPED = U16_MAX,
};

/* Nitro Enclaves (NE) misc device */
extern struct miscdevice ne_misc_dev;

#endif /* _NE_MISC_DEV_H_ */
