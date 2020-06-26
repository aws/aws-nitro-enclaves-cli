/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#ifndef _UAPI_LINUX_NITRO_ENCLAVES_H_
#define _UAPI_LINUX_NITRO_ENCLAVES_H_

#include <linux/types.h>

/* Nitro Enclaves (NE) Kernel Driver Interface */

#define NE_API_VERSION (1)

/**
 * The command is used to get the version of the NE API. This way the user space
 * processes can be aware of the feature sets provided by the NE kernel driver.
 *
 * The NE API version is returned as result of this ioctl call.
 *
 * The ioctl can be invoked on the /dev/nitro_enclaves fd, independent of
 * enclaves already created / started or not.
 *
 * No errors are returned.
 */
#define NE_GET_API_VERSION _IO(0xAE, 0x20)

/**
 * The command is used to create a slot that is associated with an enclave VM.
 * Memory and vCPUs are then set for the slot mapped to an enclave.
 *
 * The generated unique slot id is an output parameter. An enclave file
 * descriptor is returned as result of this ioctl call. The enclave fd can be
 * further used with ioctl calls to set vCPUs and memory regions, then start
 * the enclave.
 *
 * The ioctl can be invoked on the /dev/nitro_enclaves fd, before setting any
 * resources, such as memory and vCPUs, for an enclave.
 *
 * A NE CPU pool has be set before calling this function. The pool can be set
 * after the NE driver load, using /sys/module/nitro_enclaves/parameters/ne_cpus.
 * Its format is the following:
 * https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html#cpu-lists
 *
 * CPU 0 and its siblings have to remain available for the primary / parent VM,
 * so they cannot be set for enclaves. Full CPU core(s), from the same NUMA
 * node, need(s) be included in the CPU pool.
 *
 * The returned errors are:
 * * -EFAULT - copy_to_user() failure.
 * * -ENOMEM - memory allocation failure for internal bookkeeping variables.
 * * -EINVAL - no internal data structure available for the NE PCI device.
 *           - no NE CPU pool set.
 * * Error codes from get_unused_fd_flags() and anon_inode_getfile().
 * * Error codes from the NE PCI device request.
 */
#define NE_CREATE_VM _IOR(0xAE, 0x21, __u64)

/**
 * The command is used to set a vCPU for an enclave. The vCPU can be auto-chosen
 * from the NE CPU pool or it can be set by the caller, with the note that it
 * needs to be available in the NE CPU pool. Full CPU core(s), from the same
 * NUMA node, need(s) to be associated with an enclave.
 *
 * The vCPU id is an input / output parameter. If its value is 0, then a CPU is
 * chosen from the enclave CPU pool and returned via this parameter. A vCPU file
 * descriptor is returned as result of this ioctl call.
 *
 * The ioctl can be invoked on the enclave fd, before an enclave is started.
 *
 * The returned errors are:
 * * -EFAULT - copy_from_user() / copy_to_user() failure.
 * * -ENOMEM - memory allocation failure for internal bookkeeping variables.
 * * -EINVAL - no CPUs available in the NE CPU pool.
 *           - the vCPU that is set is not available in the NE CPU pool.
 *           - the enclave is not in init state (init = before being started).
 * * -EIO - current task mm is not the same as the one that created the enclave.
 * * Error codes from get_unused_fd_flags() and anon_inode_getfile().
 * * Error codes from the NE PCI device request.
 */
#define NE_CREATE_VCPU _IOWR(0xAE, 0x22, __u32)

/**
 * The command is used to get information needed for in-memory enclave image
 * loading e.g. offset in enclave memory to start placing the enclave image.
 *
 * The image load info is an input / output parameter. It includes info provided
 * by the caller - flags - and returns the offset in enclave memory where to
 * start placing the enclave image.
 *
 * The ioctl can be invoked on the enclave fd, before an enclave is started.
 *
 * The returned errors are:
 * * -EFAULT - copy_from_user() / copy_to_user() failure.
 * * -EINVAL - the enclave is not in init state (init = before being started).
 */
#define NE_GET_IMAGE_LOAD_INFO _IOWR(0xAE, 0x23, struct ne_image_load_info)

/**
 * The command is used to set a memory region for an enclave, given the
 * allocated memory from the userspace. Enclave memory needs to be from the
 * same NUMA node as the enclave CPUs.
 *
 * The user memory region is an input parameter. It includes info provided
 * by the caller - flags, memory size and userspace address.
 *
 * The ioctl can be invoked on the enclave fd, before an enclave is started.
 *
 * The returned errors are:
 * * -EFAULT - copy_from_user() failure.
 * * -ENOMEM - memory allocation failure for internal bookkeeping variables.
 * * -EINVAL - the enclave is not in init state (init = before being started).
 *           - the memory size of the region is not multiple of 2 MiB.
 *           - invalid user space address given.
 *           - the memory region is not from the same NUMA node as the CPUs.
 *           - the number of memory regions set for the enclave reached maximum.
 *           - the physical memory region are not minimum 2 MiB and aligned.
 * * -EIO - current task mm is not the same as the one that created the enclave.
 * * Error codes from get_user_pages().
 * * Error codes from the NE PCI device request.
 */
#define NE_SET_USER_MEMORY_REGION _IOW(0xAE, 0x24, struct ne_user_memory_region)

/**
 * The command is used to trigger enclave start after the enclave resources,
 * such as memory and CPU, have been set.
 *
 * The enclave start info is an input / output parameter. It includes info
 * provided by the caller - enclave cid and flags - and returns the cid (if
 * input cid is 0).
 *
 * The ioctl can be invoked on the enclave fd, after an enclave slot is created
 * and resources, such as memory and vCPUs are set for an enclave.
 *
 * The returned errors are:
 * * -EFAULT - copy_from_user() / copy_to_user() failure.
 * * -EINVAL - the enclave is not in init state (init = before being started).
 *           - no CPUs / memory regions are set for the enclave.
 *           - full core(s) not set for the enclave.
 *           - enclave memory is less than minimum memory size (64 MiB).
 * * Error codes from the NE PCI device request.
 */
#define NE_START_ENCLAVE _IOWR(0xAE, 0x25, struct ne_enclave_start_info)

/* Image load info flags */

/* Enclave Image Format (EIF) */
#define NE_EIF_IMAGE (0x01)

/* Info necessary for in-memory enclave image loading (in / out). */
struct ne_image_load_info {
	/**
	 * Flags to determine the enclave image type (e.g. Enclave Image Format
	 * - EIF) (in).
	 */
	__u64 flags;

	/**
	 * Offset in enclave memory where to start placing the enclave image
	 * (out).
	 */
	__u64 memory_offset;
};

/* User memory region flags */

/* Memory region for enclave general usage. */
#define NE_DEFAULT_MEMORY_REGION (0x00)

/* Memory region to be set for an enclave (in). */
struct ne_user_memory_region {
	/**
	 * Flags to determine the usage for the memory region (in).
	 */
	__u64 flags;

	/**
	 * The size, in bytes, of the memory region to be set for an enclave
	 * (in).
	 */
	__u64 memory_size;

	/**
	 * The start of the userspace allocated memory of the memory region to
	 * set for an enclave (in).
	 */
	__u64 userspace_addr;
};

/* Enclave start info flags */

/* Start enclave in debug mode. */
#define NE_ENCLAVE_DEBUG_MODE (0x01)

/* Setup info necessary for enclave start (in / out). */
struct ne_enclave_start_info {
	/* Flags for the enclave to start with (e.g. debug mode) (in). */
	__u64 flags;

	/**
	 * Context ID (CID) for the enclave vsock device. If 0 as input, the
	 * CID is autogenerated by the hypervisor and returned back as output
	 * by the driver (in / out).
	 */
	__u64 enclave_cid;
};

#endif /* _UAPI_LINUX_NITRO_ENCLAVES_H_ */
