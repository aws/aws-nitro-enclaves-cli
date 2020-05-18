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

#define SETUP_TEST		0

#define TEST_INVALID_ENC_FD	1
#define TEST_VALID_ENC_FD	2
#define TEST_INVALID_MEM_REG	3
#define TEST_VALID_MEM_REG	4
#define TEST_INVALID_VCPU	5
#define TEST_VALID_VCPU		6

struct test_setup {
	int enc_fd_ret;
	int mem_reg_ret;
	int vcpu_ret;
};

/* Driver control struct, relevant only in a testing environment */
struct test_control {
	int test_no;
	struct test_setup *setup;
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
	/* Enclave process abstraction mm data struct. */
	struct mm_struct *mm;
	/* Slot unique id mapped to the enclave. */
	u64 slot_uid;
	/* Enclave state, updated during enclave lifetime. */
	u16 state;
};

/**
 * States available for an enclave.
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
