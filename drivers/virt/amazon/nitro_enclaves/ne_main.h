/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#ifndef _NE_MAIN_H_
#define _NE_MAIN_H_

#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/wait.h>

#include "ne_pci_dev.h"

/* Entry in vCPU IDs list. */
struct ne_vcpu_id {
	/* CPU id associated with a given slot, apic id on x86. */
	u32 vcpu_id;
	struct list_head vcpu_id_list_entry;
};

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
	struct list_head enclave_list_entry;
	/**
	 * Wait queue used for rescan event notifications
	 * triggered from @ref ne_pci_dev_rescan_handler
	 * the enclave process via @ref ne_dev_enclave_poll.
	 */
	wait_queue_head_t eventq;
	/* Variable used to determine if the rescan event was triggered. */
	bool has_event;
	/* Lock for accessing this internal state. */
	struct mutex lock;
	/**
	 * The maximum number of memory regions that can be handled by the
	 * lower levels.
	 */
	u64 max_mem_regions;
	/* Enclave memory regions list. */
	struct list_head mem_regions_list;
	/* Enclave process abstraction mm data struct. */
	struct mm_struct *mm;
	/* PCI device used for enclave lifetime management. */
	struct pci_dev *pdev;
	/* Slot unique id mapped to the enclave. */
	u64 slot_uid;
	/* Enclave state, updated during enclave lifetime. */
	u16 state;
	/* Enclave vCPUs list. */
	struct list_head vcpu_ids_list;
};

/**
 * States available for an enclave.
 *
 * TODO: Determine if the following states are exposing enough information
 * to the kernel driver.
 */
enum ne_state {
	/* NE_ENCLAVE_START ioctl was never issued for the enclave. */
	NE_STATE_INIT = 0,
	/**
	 * NE_ENCLAVE_START ioctl was issued and the enclave is running
	 * as expected.
	 */
	NE_STATE_RUNNING = 2,
	/* Enclave exited without userspace interaction. */
	NE_STATE_STOPPED = U16_MAX,
};

#endif /* _NE_MAIN_H_ */
