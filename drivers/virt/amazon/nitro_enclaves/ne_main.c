// SPDX-License-Identifier: GPL-2.0
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

/**
 * Enclave lifetime management driver for Nitro Enclaves (NE).
 * Nitro is a hypervisor, based on KVM, that has been developed by Amazon.
 */

#include <linux/anon_inodes.h>
#include <linux/bug.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nitro_enclaves.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "ne_main.h"

#define NE_DEV_NAME "nitro_enclaves"

#define MIN_MEM_REGION_SIZE (2 * 1024UL * 1024UL)

/*
 * The type '__poll_t' is not available in kernels older than 4.16.0
 * so for these we define it here.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#define __poll_t unsigned int
#endif

static int user_access_ok(void __user *addr, unsigned long size) {
	/*
	 * For pre-5.0.0 kernels, the "access_ok" macro takes 3 arguments.
	 * The first argument is the verification type, with VERIFY_WRITE
	 * being the most comprehensive.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	return access_ok(VERIFY_WRITE, addr, size);
#else
	return access_ok(addr, size);
#endif
}

static int ne_dev_enclave_vcpu_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_dev_enclave_vcpu_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	struct ne_enclave *ne_enclave = file->private_data;

	if (!ne_enclave)
		return -EINVAL;

	switch (cmd) {

	/*
	 * Note: The ioctl interface will be updated as additional logic is
	 * added for the Nitro Enclaves PCI device and e.g. enclave image
	 * loading or CPU handling.
	 *
	 * TODO: Update the ioctl interface once the necessary logic has been
	 * added.
	 */

	case KVM_RUN: {
		mutex_lock(&ne_enclave->lock);

		/*
		 * TODO: Map kvm_run data struct via vcpu fd offset 0, size
		 * given by KVM_GET_VCPU_MMAP_SIZE.
		 */

		mutex_unlock(&ne_enclave->lock);

		return 0;
	}

	default:
		return -ENOTTY;
	}

	return 0;
}

static int ne_dev_enclave_vcpu_release(struct inode *inode, struct file *file)
{
	struct ne_enclave *ne_enclave = file->private_data;

	mutex_lock(&ne_enclave->lock);

	/* TODO: Free vCPU related private data. */

	mutex_unlock(&ne_enclave->lock);

	return 0;
}

static const struct file_operations ne_dev_enclave_vcpu_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= ne_dev_enclave_vcpu_ioctl,
	.open		= ne_dev_enclave_vcpu_open,
	.release	= ne_dev_enclave_vcpu_release,
};

/**
 * ne_create_vcpu_ioctl - Add vCPU to the slot associated with the current
 * enclave. Create vCPU file descriptor to be further used for CPU handling.
 *
 * This function gets called with the ne_enclave lock held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @vcpu_id: id of the CPU to be associated with the given slot, apic id on x86.
 *
 * @returns: vCPU fd on success, negative return value on failure.
 */
static int ne_create_vcpu_ioctl(struct ne_enclave *ne_enclave, u32 vcpu_id)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int fd = 0;
	struct file *file = NULL;
	struct ne_vcpu_id *ne_vcpu_id = NULL;
	int rc = -EINVAL;
	struct slot_add_vcpu_req slot_add_vcpu_req = {};

	if (!ne_enclave || !ne_enclave->pdev)
		return -EINVAL;

	if (ne_enclave->mm != current->mm)
		return -EIO;

	ne_vcpu_id = kzalloc(sizeof(*ne_vcpu_id), GFP_KERNEL);
	if (!ne_vcpu_id)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		rc = fd;

		pr_err("Failure in getting unused fd [rc=%d]\n", rc);

		goto err_get_unused_fd;
	}

	/* TODO: Include (vcpu) id in the ne-vm-vcpu naming. */
	file = anon_inode_getfile("ne-vm-vcpu", &ne_dev_enclave_vcpu_fops,
				  ne_enclave, O_RDWR);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);

		pr_err("Failure in anon inode get file [rc=%d]\n", rc);

		goto err_anon_inode_getfile;
	}

	slot_add_vcpu_req.slot_uid = ne_enclave->slot_uid;
	slot_add_vcpu_req.vcpu_id = vcpu_id;

	rc = do_request(ne_enclave->pdev, SLOT_ADD_VCPU, &slot_add_vcpu_req,
			sizeof(slot_add_vcpu_req), &cmd_reply,
			sizeof(cmd_reply));
	if (rc < 0) {
		pr_err("Failure in slot add vcpu [rc=%d]\n", rc);

		goto err_slot_add_vcpu;
	}

	ne_vcpu_id->vcpu_id = vcpu_id;

	list_add(&ne_vcpu_id->vcpu_id_list_entry, &ne_enclave->vcpu_ids_list);

	fd_install(fd, file);

	return fd;

err_slot_add_vcpu:
err_anon_inode_getfile:
	put_unused_fd(fd);
err_get_unused_fd:
	kfree(ne_vcpu_id);
	ne_vcpu_id = NULL;
	return rc;
}

/**
 * ne_set_user_memory_region_ioctl - Add user space memory region to the slot
 * associated with the current enclave.
 *
 * This function gets called with the ne_enclave lock held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @mem_region: user space memory region to be associated with the given slot.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_set_user_memory_region_ioctl(struct ne_enclave *ne_enclave,
	struct kvm_userspace_memory_region *mem_region)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	long gup_rc = 0;
	unsigned long i = 0;
	struct ne_mem_region *ne_mem_region = NULL;
	/*
	 * TODO: Update nr_pages to be non-const value to handles contiguous
	 * virtual address ranges mapped to non-contiguous physical regions.
	 * Hugetlbfs can give 2 MiB / 1 GiB contiguous physical regions.
	 */
	unsigned long nr_pages = 1;
	struct page **pages = NULL;
	int rc = -EINVAL;
	struct slot_add_mem_req slot_add_mem_req = {};

	if (!ne_enclave || !ne_enclave->pdev || !mem_region)
		return -EINVAL;

	if (ne_enclave->mm != current->mm)
		return -EIO;

	if (mem_region->slot > ne_enclave->max_mem_regions) {
		pr_err("Mem region slot higher than max mem regions\n");

		return -EINVAL;
	}

	if ((mem_region->memory_size % MIN_MEM_REGION_SIZE) != 0) {
		pr_err("Mem region size not multiple of 2 MiB\n");

		return -EINVAL;
	}

	if ((mem_region->userspace_addr & (PAGE_SIZE - 1)) ||
	    !user_access_ok((void __user *)(unsigned long)mem_region->userspace_addr,
		       mem_region->memory_size)) {
		pr_err("Invalid user space addr range\n");

		return -EINVAL;
	}

	if ((mem_region->guest_phys_addr + mem_region->memory_size) <
	    mem_region->guest_phys_addr) {
		pr_err("Invalid guest phys addr range\n");

		return -EINVAL;
	}

	ne_mem_region = kzalloc(sizeof(*ne_mem_region), GFP_KERNEL);
	if (!ne_mem_region)
		return -ENOMEM;

	pages = kcalloc(nr_pages, sizeof(*pages), GFP_KERNEL);
	if (!pages) {
		kfree(ne_mem_region);
		ne_mem_region = NULL;

		return -ENOMEM;
	}

	/*
	 * TODO: Handle non-contiguous memory regions received from user space.
	 * Hugetlbfs can give 2 MiB / 1 GiB contiguous physical regions. The
	 * virtual address space can be seen as contiguous, although it is
	 * mapped underneath to 2 MiB / 1 GiB physical regions e.g. 8 MiB
	 * virtual address space mapped to 4 physically contiguous regions of 2
	 * MiB. Check gup_rc if getting pages refs for less than nr_pages.
	 */
	gup_rc = get_user_pages(mem_region->userspace_addr, nr_pages,
				FOLL_GET, pages, NULL);

	if (gup_rc < 0) {
		rc = gup_rc;

		pr_err("Failure in get user pages [rc=%d]\n", rc);

		goto err_get_user_pages;
	}

	for (i = 0; i < nr_pages; i++) {
		mem_region->guest_phys_addr = page_to_phys(pages[i]);

		slot_add_mem_req.slot_uid = ne_enclave->slot_uid;
		slot_add_mem_req.paddr = mem_region->guest_phys_addr;
		/*
		 * TODO: Update memory size of physical contiguous memory
		 * region. It may be less than the entire userspace memory
		 * region size.
		 */
		slot_add_mem_req.size = mem_region->memory_size;

		rc = do_request(ne_enclave->pdev, SLOT_ADD_MEM,
				&slot_add_mem_req, sizeof(slot_add_mem_req),
				&cmd_reply, sizeof(cmd_reply));
		if (rc < 0) {
			pr_err("Failure in slot add mem [rc=%d]\n", rc);

			goto err_slot_add_mem;
		}

		memset(&slot_add_mem_req, 0, sizeof(slot_add_mem_req));
		memset(&cmd_reply, 0, sizeof(cmd_reply));
	}

	ne_mem_region->nr_pages = nr_pages;
	ne_mem_region->pages = pages;

	list_add(&ne_mem_region->mem_region_list_entry,
		 &ne_enclave->mem_regions_list);

	return 0;

err_slot_add_mem:
	/*
	 * TODO: put_user_pages() was introduced in commit
	 * fc1d8e7cca2daa18d2fe56b94874848adf89d7f5, part of
	 * kernel v.5.2. Then it was renamed to unpin_user_pages()
	 * in commit f1f6a7dd9b53aafd81b696b9017036e7b08e57ea,
	 * part of v5.6-rc1.
	 * Only the put_page() call exists before this commit.
	 */
	/*
	 * unpin_user_pages(pages, nr_pages);
	 */
	for (i = 0; i < nr_pages; i++)
		put_page(pages[i]);
err_get_user_pages:
	kfree(ne_mem_region);
	ne_mem_region = NULL;
	kfree(pages);
	pages = NULL;
	return rc;
}

/**
 * ne_enclave_start_ioctl - Trigger enclave start after the enclave resources,
 * such as memory and CPU, have been set.
 *
 * This function gets called with the ne_enclave lock held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @enclave_start_metadata: enclave metadata that includes enclave cid and
 *			    flags, slot uid and the vsock loader token.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_enclave_start_ioctl(struct ne_enclave *ne_enclave,
	struct enclave_start_metadata *enclave_start_metadata)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct enclave_start_req enclave_start_req = {};
	int rc = -EINVAL;

	if (!ne_enclave || !ne_enclave->pdev || !enclave_start_metadata)
		return -EINVAL;

	enclave_start_metadata->slot_uid = ne_enclave->slot_uid;

	enclave_start_req.enclave_cid = enclave_start_metadata->enclave_cid;
	enclave_start_req.flags = enclave_start_metadata->flags;
	enclave_start_req.slot_uid = enclave_start_metadata->slot_uid;

	rc = do_request(ne_enclave->pdev, ENCLAVE_START, &enclave_start_req,
			sizeof(enclave_start_req), &cmd_reply,
			sizeof(cmd_reply));
	if (rc < 0) {
		pr_err("Failure in enclave start [rc=%d]\n", rc);

		return rc;
	}

	ne_enclave->state = NE_STATE_RUNNING;

	enclave_start_metadata->enclave_cid = cmd_reply.enclave_cid;
	enclave_start_metadata->vsock_loader_token =
		cmd_reply.vsock_loader_token;

	return 0;
}

static int ne_dev_enclave_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_dev_enclave_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct ne_enclave *ne_enclave = file->private_data;

	if (!ne_enclave)
		return -EINVAL;

	switch (cmd) {

	/*
	 * Note: The ioctl interface will be updated as additional logic is
	 * added for the Nitro Enclaves PCI device and e.g. enclave image
	 * loading or CPU handling.
	 *
	 * TODO: Update the ioctl interface once the necessary logic has been
	 * added.
	 */

	case KVM_CREATE_VCPU: {
		int rc = -EINVAL;
		u32 vcpu_id = 0;

		if (copy_from_user(&vcpu_id, (void *)arg, sizeof(vcpu_id))) {
			pr_err("Failure in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->lock);

		rc = ne_create_vcpu_ioctl(ne_enclave, vcpu_id);

		mutex_unlock(&ne_enclave->lock);

		return rc;
	}

	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region mem_region = {};
		int rc = -EINVAL;

		if (copy_from_user(&mem_region, (void *)arg,
				   sizeof(mem_region))) {
			pr_err("Failure in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->lock);

		rc = ne_set_user_memory_region_ioctl(ne_enclave, &mem_region);

		mutex_unlock(&ne_enclave->lock);

		return rc;
	}

	case NE_ENCLAVE_START: {
		struct enclave_start_metadata enclave_start_metadata = {};
		int rc = -EINVAL;

		if (copy_from_user(&enclave_start_metadata, (void *)arg,
				   sizeof(enclave_start_metadata))) {
			pr_err("Failure in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->lock);

		rc = ne_enclave_start_ioctl(ne_enclave,
					    &enclave_start_metadata);

		mutex_unlock(&ne_enclave->lock);

		if (copy_to_user((void *)arg, &enclave_start_metadata,
				 sizeof(enclave_start_metadata))) {
			pr_err("Failure in copy to user\n");

			return -EFAULT;
		}

		return rc;
	}

	default:
		return -ENOTTY;
	}

	return 0;
}

/**
 * ne_enclave_remove_all_mem_region_entries - Remove all memory region
 * entries from the enclave data structure.
 *
 * This function gets called with the ne_enclave lock held.
 *
 * @ne_enclave: private data associated with the current enclave.
 */
static void ne_enclave_remove_all_mem_region_entries(
	struct ne_enclave *ne_enclave)
{
	unsigned long i = 0;
	struct ne_mem_region *ne_mem_region = NULL;
	struct ne_mem_region *ne_mem_region_tmp = NULL;

	if (!ne_enclave)
		return;

	list_for_each_entry_safe(ne_mem_region, ne_mem_region_tmp,
				 &ne_enclave->mem_regions_list,
				 mem_region_list_entry) {
		list_del(&ne_mem_region->mem_region_list_entry);

		/*
		 * TODO: put_user_pages() was introduced in commit
		 * fc1d8e7cca2daa18d2fe56b94874848adf89d7f5, part of
		 * kernel v.5.2. Then it was renamed to unpin_user_pages()
		 * in commit f1f6a7dd9b53aafd81b696b9017036e7b08e57ea,
		 * part of v5.6-rc1.
		 * Only the put_page() call exists before this commit.
		 */
		/*
		 * unpin_user_pages(ne_mem_region->pages,
		 *		 ne_mem_region->nr_pages);
		 */
		for (i = 0; i < ne_mem_region->nr_pages; i++)
			put_page(ne_mem_region->pages[i]);

		kfree(ne_mem_region->pages);
		ne_mem_region->pages = NULL;

		kfree(ne_mem_region);
		ne_mem_region = NULL;
	}
}

/**
 * ne_enclave_remove_all_vcpu_id_entries - Remove all vCPU id entries
 * from the enclave data structure.
 *
 * This function gets called with the ne_enclave lock held.
 *
 * @ne_enclave: private data associated with the current enclave.
 */
static void ne_enclave_remove_all_vcpu_id_entries(struct ne_enclave *ne_enclave)
{
	struct ne_vcpu_id *ne_vcpu_id = NULL;
	struct ne_vcpu_id *ne_vcpu_id_tmp = NULL;

	if (!ne_enclave)
		return;

	list_for_each_entry_safe(ne_vcpu_id, ne_vcpu_id_tmp,
				 &ne_enclave->vcpu_ids_list,
				 vcpu_id_list_entry) {
		list_del(&ne_vcpu_id->vcpu_id_list_entry);

		kfree(ne_vcpu_id);
		ne_vcpu_id = NULL;
	}
}

/**
 * ne_pci_dev_remove_enclave_entry - Remove enclave entry from the data
 * structure that is part of the PCI device private data.
 *
 * This function gets called with the ne_pci_dev enclave lock held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @ne_pci_dev: private data associated with the PCI device.
 */
static void ne_pci_dev_remove_enclave_entry(struct ne_enclave *ne_enclave,
					    struct ne_pci_dev *ne_pci_dev)
{
	struct ne_enclave *ne_enclave_entry = NULL;
	struct ne_enclave *ne_enclave_entry_tmp = NULL;

	if (!ne_enclave || !ne_pci_dev)
		return;

	list_for_each_entry_safe(ne_enclave_entry, ne_enclave_entry_tmp,
				 &ne_pci_dev->enclaves_list,
				 enclave_list_entry) {
		if (ne_enclave_entry->slot_uid == ne_enclave->slot_uid) {
			list_del(&ne_enclave_entry->enclave_list_entry);

			break;
		}
	}
}

static int ne_dev_enclave_release(struct inode *inode, struct file *file)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct enclave_stop_req enclave_stop_request = {};
	struct ne_enclave *ne_enclave = file->private_data;
	struct ne_pci_dev *ne_pci_dev = NULL;
	int rc = -EINVAL;
	struct slot_free_req slot_free_req = {};

	if (!ne_enclave || !ne_enclave->pdev)
		return -EINVAL;

	ne_pci_dev = pci_get_drvdata(ne_enclave->pdev);
	if (!ne_pci_dev)
		return -EINVAL;

	/*
	 * Acquire the enclave list mutex before the enclave mutex
	 * in order to avoid deadlocks with @ref ne_rescan_work_handler.
	 */
	mutex_lock(&ne_pci_dev->enclaves_list_lock);
	mutex_lock(&ne_enclave->lock);

	enclave_stop_request.slot_uid = ne_enclave->slot_uid;

	rc = do_request(ne_enclave->pdev, ENCLAVE_STOP, &enclave_stop_request,
			sizeof(enclave_stop_request), &cmd_reply,
			sizeof(cmd_reply));
	if (rc < 0) {
		pr_err("Failure in enclave stop [rc=%d]\n", rc);

		mutex_unlock(&ne_enclave->lock);
		mutex_unlock(&ne_pci_dev->enclaves_list_lock);

		WARN_ON(rc < 0);

		return rc;
	}

	memset(&cmd_reply, 0, sizeof(cmd_reply));

	slot_free_req.slot_uid = ne_enclave->slot_uid;

	rc = do_request(ne_enclave->pdev, SLOT_FREE, &slot_free_req,
			sizeof(slot_free_req), &cmd_reply, sizeof(cmd_reply));
	if (rc < 0) {
		pr_err("Failure in slot free [rc=%d]\n", rc);

		mutex_unlock(&ne_enclave->lock);
		mutex_unlock(&ne_pci_dev->enclaves_list_lock);

		WARN_ON(rc < 0);

		return rc;
	}

	ne_pci_dev_remove_enclave_entry(ne_enclave, ne_pci_dev);
	ne_enclave_remove_all_mem_region_entries(ne_enclave);
	ne_enclave_remove_all_vcpu_id_entries(ne_enclave);

	mutex_unlock(&ne_enclave->lock);
	mutex_unlock(&ne_pci_dev->enclaves_list_lock);

	kfree(ne_enclave);
	ne_enclave = NULL;

	return 0;
}

static __poll_t ne_dev_enclave_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;
	struct ne_enclave *ne_enclave = file->private_data;

	poll_wait(file, &ne_enclave->eventq, wait);

	if (!ne_enclave->has_event)
		return mask;

	mask = POLLHUP;

	return mask;
}

static const struct file_operations ne_dev_enclave_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.poll		= ne_dev_enclave_poll,
	.unlocked_ioctl	= ne_dev_enclave_ioctl,
	.open		= ne_dev_enclave_open,
	.release	= ne_dev_enclave_release,
};

/**
 * ne_create_vm_ioctl - Alloc slot to be associated with an enclave. Create
 * enclave file descriptor to be further used for enclave resources handling
 * e.g. memory regions and CPUs.
 *
 * This function gets called with the ne_pci_dev enclave lock held.
 *
 * @pdev: PCI device used for enclave lifetime management.
 * @ne_pci_dev: private data associated with the PCI device.
 * @type: type of the virtual machine to be created.
 *
 * @returns: enclave fd on success, negative return value on failure.
 */
static int ne_create_vm_ioctl(struct pci_dev *pdev,
			      struct ne_pci_dev *ne_pci_dev, unsigned long type)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int fd = 0;
	struct file *file = NULL;
	struct ne_enclave *ne_enclave = NULL;
	int rc = -EINVAL;
	struct slot_alloc_req slot_alloc_req = {};

	if (!pdev || !ne_pci_dev)
		return -EINVAL;

	ne_enclave = kzalloc(sizeof(*ne_enclave), GFP_KERNEL);
	if (!ne_enclave)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		rc = fd;

		pr_err("Failure in getting unused fd [rc=%d]\n", rc);

		goto err_get_unused_fd;
	}

	file = anon_inode_getfile("ne-vm", &ne_dev_enclave_fops, ne_enclave,
				  O_RDWR);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);

		pr_err("Failure in anon inode get file [rc=%d]\n", rc);

		goto err_anon_inode_getfile;
	}

	ne_enclave->pdev = pdev;

	rc = do_request(ne_enclave->pdev, SLOT_ALLOC, &slot_alloc_req,
			sizeof(slot_alloc_req), &cmd_reply, sizeof(cmd_reply));
	if (rc < 0) {
		pr_err("Failure in slot alloc [rc=%d]\n", rc);

		goto err_slot_alloc;
	}

	init_waitqueue_head(&ne_enclave->eventq);
	ne_enclave->has_event = false;
	mutex_init(&ne_enclave->lock);
	ne_enclave->max_mem_regions = cmd_reply.mem_regions;
	INIT_LIST_HEAD(&ne_enclave->mem_regions_list);
	ne_enclave->mm = current->mm;
	ne_enclave->slot_uid = cmd_reply.slot_uid;
	ne_enclave->state = NE_STATE_INIT;
	INIT_LIST_HEAD(&ne_enclave->vcpu_ids_list);

	list_add(&ne_enclave->enclave_list_entry, &ne_pci_dev->enclaves_list);

	fd_install(fd, file);

	return fd;

err_slot_alloc:
err_anon_inode_getfile:
	put_unused_fd(fd);
err_get_unused_fd:
	kfree(ne_enclave);
	ne_enclave = NULL;
	return rc;
}

static int ne_dev_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	struct pci_dev *pdev = ne_get_pci_dev();

	if (!pdev)
		return -EINVAL;

	ne_pci_dev = pci_get_drvdata(pdev);
	if (!ne_pci_dev)
		return -EINVAL;

	switch (cmd) {

	/*
	 * Note: The ioctl interface will be updated as additional logic is
	 * added for the Nitro Enclaves PCI device and e.g. enclave image
	 * loading or CPU handling.
	 *
	 * TODO: Update the ioctl interface once the necessary logic has been
	 * added.
	 */

	case KVM_CREATE_VM: {
		int rc = -EINVAL;
		unsigned long type = 0;

		if (copy_from_user(&type, (void *)arg, sizeof(type))) {
			pr_err("Failure in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_pci_dev->enclaves_list_lock);

		rc = ne_create_vm_ioctl(pdev, ne_pci_dev, type);

		mutex_unlock(&ne_pci_dev->enclaves_list_lock);

		return rc;
	}

	default:
		return -ENOTTY;
	}

	return 0;
}

static int ne_dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations ne_dev_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= ne_dev_ioctl,
	.open		= ne_dev_open,
	.release	= ne_dev_release,
};

static struct miscdevice ne_miscdevice = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= NE_DEV_NAME,
	.fops	= &ne_dev_fops,
	.mode	= 0664,
};

static int __init ne_init(void)
{
	int rc = -EINVAL;

	rc = ne_pci_dev_init();
	if (rc < 0) {
		pr_err("Failure in pci dev init [rc=%d]\n", rc);

		return rc;
	}

	/*
	 * TODO: Check if the misc dev register can be done as part of the PCI
	 * dev init flow (e.g. register misc dev only if the PCI dev exists,
	 * - e.g. pci_dev_present() or ne_get_pci_dev() - either when the driver
	 * is part of the kernel from the beginning or loaded later on, as a
	 * kernel module).
	 */
	rc = misc_register(&ne_miscdevice);
	if (rc < 0) {
		pr_err("Failure in misc dev register [rc=%d]\n", rc);

		ne_pci_dev_uninit();

		return rc;
	}

	return 0;
}

static void __exit ne_exit(void)
{
	ne_pci_dev_uninit();

	return misc_deregister(&ne_miscdevice);
}

/* TODO: Handle actions such as reboot, kexec. */

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
