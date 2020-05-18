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

static struct test_control tctl;

static int ne_dev_enclave_test_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_dev_enclave_test_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	switch (cmd) {
	case KVM_SET_USER_MEMORY_REGION:
		return tctl.setup->mem_reg_ret;
	case KVM_CREATE_VCPU:
		return tctl.setup->vcpu_ret;
	default:
		return -EINVAL;
	}
}

static int ne_dev_enclave_test_release(struct inode *inode, struct file *file)
{
	return 0;
}

static __poll_t ne_dev_enclave_test_poll(struct file *file, poll_table *wait)
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
	.poll		= ne_dev_enclave_test_poll,
	.unlocked_ioctl	= ne_dev_enclave_test_ioctl,
	.open		= ne_dev_enclave_test_open,
	.release	= ne_dev_enclave_test_release,
};

static int ne_dev_test_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_create_vm_test_ioctl(void)
{
	int rc = -EINVAL;
	int fd = 0;
	struct file *file = NULL;
	struct ne_enclave *ne_enclave = NULL;

	if (tctl.test_no == TEST_INVALID_ENC_FD)
		return tctl.setup->enc_fd_ret;

	ne_enclave = kzalloc(sizeof(*ne_enclave), GFP_KERNEL);
	if (ne_enclave == NULL)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		rc = fd;
		pr_err("Failure in getting unused fd [rc=%d]\n", rc);
		goto err_get_unused_fd;
	}

	file = anon_inode_getfile("ne_vm", &ne_dev_enclave_fops, ne_enclave, O_RDWR);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);
		pr_err("Failure in anon inode get file [rc=%d]\n", rc);
		goto err_anon_inode_getfile;
	}

	fd_install(fd, file);

	return fd;

err_anon_inode_getfile:
	put_unused_fd(fd);
err_get_unused_fd:
	kfree(ne_enclave);
	ne_enclave = NULL;
	return rc;
}

static int alloc_test_control_structure(void) {
	if (tctl.setup == NULL) {
		tctl.setup = kmalloc(sizeof(struct test_setup), GFP_KERNEL);
		if (tctl.setup == NULL)
			return -ENOMEM;
	}

	return 0;
}

static long ne_dev_setup_test_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rc = -EINVAL;

	switch (arg) {
	case TEST_INVALID_ENC_FD:
		rc = alloc_test_control_structure();
		if (rc != 0)
			goto err_alloc_out;
 
		tctl.test_no = arg;
		tctl.setup->enc_fd_ret = -1;
		break;
	case TEST_VALID_ENC_FD:
		rc = alloc_test_control_structure();
		if (rc != 0)
			goto err_alloc_out;

		tctl.test_no = arg;
		tctl.setup->enc_fd_ret = 10;
		break;
	case TEST_INVALID_MEM_REG:
		rc = alloc_test_control_structure();
		if (rc != 0)
			goto err_alloc_out;

		tctl.test_no = arg;
		tctl.setup->mem_reg_ret = -EFAULT;
		break;
	case TEST_VALID_MEM_REG:
		rc = alloc_test_control_structure();
		if (rc != 0)
			goto err_alloc_out;

		tctl.test_no = arg;
		tctl.setup->mem_reg_ret = 0;
		break;
	case TEST_INVALID_VCPU:
		rc = alloc_test_control_structure();
		if (rc != 0)
			goto err_alloc_out;

		tctl.test_no = arg;
		tctl.setup->vcpu_ret = -EINVAL;
		break;
	case TEST_VALID_VCPU:
		rc = alloc_test_control_structure();
		if (rc != 0)
			goto err_alloc_out;

		tctl.test_no = arg;
		tctl.setup->vcpu_ret = 0;
	default:
		goto err_unknown_arg;
	}

	return tctl.setup->enc_fd_ret;

err_alloc_out:
err_unknown_arg:
	return rc;
}

static long ne_dev_test_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SETUP_TEST:
		return ne_dev_setup_test_ioctl(file, cmd, arg);
	case KVM_CREATE_VM:
		return ne_create_vm_test_ioctl();
	default:
		return -ENOTTY;
	}

	return 0;
}

static int ne_dev_test_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations ne_dev_test_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= ne_dev_test_ioctl,
	.open		= ne_dev_test_open,
	.release	= ne_dev_test_release,
};

static struct miscdevice ne_test_miscdevice = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= NE_DEV_NAME,
	.fops	= &ne_dev_test_fops,
	.mode	= 0644,
};

static int __init ne_test_init(void)
{
	int rc;

	rc = misc_register(&ne_test_miscdevice);
	tctl.setup = NULL;

	return rc;
}

static void __exit ne_test_exit(void)
{
	if (tctl.setup)
		kfree(tctl.setup);

    return misc_deregister(&ne_test_miscdevice);
}


module_init(ne_test_init);
module_exit(ne_test_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
