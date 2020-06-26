// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

/**
 * Enclave lifetime management driver for Nitro Enclaves (NE).
 * Nitro is a hypervisor that has been developed by Amazon.
 */

#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/hugetlb.h>
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

#include "ne_misc_dev.h"
#include "ne_pci_dev.h"

#define NE_EIF_LOAD_OFFSET (8 * 1024UL * 1024UL)

#define NE_MIN_ENCLAVE_MEM_SIZE (64 * 1024UL * 1024UL)

#define NE_MIN_MEM_REGION_SIZE (2 * 1024UL * 1024UL)

/*
 * TODO: Update logic to create new sysfs entries instead of using
 * a kernel parameter e.g. if multiple sysfs files needed.
 */
static int ne_set_kernel_param(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops ne_cpu_pool_ops = {
	.get = param_get_string,
	.set = ne_set_kernel_param,
};

static char ne_cpus[PAGE_SIZE];
static struct kparam_string ne_cpus_arg = {
	.maxlen = sizeof(ne_cpus),
	.string = ne_cpus,
};

module_param_cb(ne_cpus, &ne_cpu_pool_ops, &ne_cpus_arg, 0644);
MODULE_PARM_DESC(ne_cpus, "<cpu-list> - CPU pool used for Nitro Enclaves");

/* CPU pool used for Nitro Enclaves. */
struct ne_cpu_pool {
	/* Available CPU cores in the pool. */
	cpumask_var_t *avail_cores;

	/* The size of the available cores array. */
	unsigned int avail_cores_size;

	struct mutex mutex;

	/* NUMA node of the CPUs in the pool. */
	int numa_node;
};

static struct ne_cpu_pool ne_cpu_pool;

static const struct file_operations ne_enclave_vcpu_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};

/*
 * For pre-5.0.0 kernels, the "access_ok" macro takes 3 arguments.
 * The first argument is the verification type, with VERIFY_WRITE
 * being the most comprehensive.
 */
static int user_access_ok(void __user *addr, unsigned long size) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
       return access_ok(VERIFY_WRITE, addr, size);
#else
       return access_ok(addr, size);
#endif
}

#ifndef remove_cpu
static int remove_cpu(u32 cpu_id)
{
	struct device *cpu_dev = NULL;
	int rc = -EINVAL;


	cpu_dev = get_cpu_device(cpu_id);
	if (!cpu_dev) {
		rc = -EINVAL;

		pr_err("%s: Failure in getting cpu dev [rc=%d]\n",
			ne_misc_dev.name, rc);

		return rc;
	}

	rc = cpu_subsys.offline(cpu_dev);
	if (rc < 0) {
		pr_err("%s: Failure in cpu subsys offline [rc=%d]\n",
			ne_misc_dev.name, rc);

		return rc;
	}

	return 0;
}
#endif

#ifndef add_cpu
static int add_cpu(u32 cpu_id)
{
	struct device *cpu_dev = NULL;
	int rc = -EINVAL;

	cpu_dev = get_cpu_device(cpu_id);
	if (!cpu_dev) {
		rc = -EINVAL;

		pr_err("%s: Failure in getting cpu dev [rc=%d]\n",
			ne_misc_dev.name, rc);

		return rc;
	}

	rc = cpu_subsys.online(cpu_dev);
	if (rc < 0) {
		pr_err("%s: Failure in cpu subsys online [rc=%d]\n",
			ne_misc_dev.name, rc);

		return rc;
	}

	return 0;
}
#endif

#ifndef unpin_user_pages
void unpin_user_pages(struct page **pages, unsigned long npages)
{
       unsigned long i = 0;

       for (i = 0; i < npages; i++)
               put_page(pages[i]);
}
#endif

/**
 * ne_check_enclaves_created - Verify if at least one enclave has been created.
 *
 * @returns: true if at least one enclave is created, false otherwise.
 */
static bool ne_check_enclaves_created(void)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON,
					      PCI_DEVICE_ID_NE, NULL);

	if (!pdev)
		return false;

	ne_pci_dev = pci_get_drvdata(pdev);
	if (!ne_pci_dev) {
		pci_dev_put(pdev);

		return false;
	}

	mutex_lock(&ne_pci_dev->enclaves_list_mutex);

	if (list_empty(&ne_pci_dev->enclaves_list)) {
		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

		pci_dev_put(pdev);

		return false;
	}

	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

	pci_dev_put(pdev);

	return true;
}

/**
 * ne_setup_cpu_pool - Set the NE CPU pool after handling sanity checks such as
 * not sharing CPU cores with the primary / parent VM or not using CPU 0, which
 * should remain available for the primary / parent VM. Offline the CPUs from
 * the pool after the checks passed.
 *
 * @ne_cpu_list: the CPU list used for setting NE CPU pool.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_setup_cpu_pool(const char *ne_cpu_list)
{
	int core_id = -1;
	unsigned int cpu = 0;
	cpumask_var_t cpu_pool = NULL;
	unsigned int cpu_sibling = 0;
	unsigned int i = 0;
	int numa_node = -1;
	int rc = -EINVAL;

	if (!capable(CAP_SYS_ADMIN)) {
		pr_err("%s: No admin capability for CPU pool setup\n",
		       ne_misc_dev.name);

		return -EPERM;
	}

	if (!ne_cpu_list)
		return 0;

	if (!zalloc_cpumask_var(&cpu_pool, GFP_KERNEL))
		return -ENOMEM;

	mutex_lock(&ne_cpu_pool.mutex);

	rc = cpulist_parse(ne_cpu_list, cpu_pool);
	if (rc < 0) {
		pr_err("%s: Error in cpulist parse [rc=%d]\n",
		       ne_misc_dev.name, rc);

		goto free_cpumask;
	}

	cpu = cpumask_any(cpu_pool);
	if (cpu >= nr_cpu_ids) {
		pr_err("%s: No CPUs available in CPU pool\n", ne_misc_dev.name);

		rc = -EINVAL;

		goto free_cpumask;
	}

	/*
	 * Check if CPU 0 and its siblings are included in the provided CPU pool
	 * They should remain available for the primary / parent VM.
	 */
	if (cpumask_test_cpu(0, cpu_pool)) {
		pr_err("%s: CPU 0 has to remain available\n", ne_misc_dev.name);

		rc = -EINVAL;

		goto free_cpumask;
	}

	for_each_cpu(cpu_sibling, topology_sibling_cpumask(0)) {
		if (cpumask_test_cpu(cpu_sibling, cpu_pool)) {
			pr_err("%s: CPU sibling %d for CPU 0 is in CPU pool\n",
			       ne_misc_dev.name, cpu_sibling);

			rc = -EINVAL;

			goto free_cpumask;
		}
	}

	/*
	 * Check if CPU siblings are included in the provided CPU pool. The
	 * expectation is that CPU cores are made available in the CPU pool for
	 * enclaves.
	 */
	for_each_cpu(cpu, cpu_pool) {
		for_each_cpu(cpu_sibling, topology_sibling_cpumask(cpu)) {
			if (!cpumask_test_cpu(cpu_sibling, cpu_pool)) {
				pr_err("%s: CPU %d isn't in CPU pool\n",
				       ne_misc_dev.name, cpu_sibling);

				rc = -EINVAL;

				goto free_cpumask;
			}
		}
	}

	/*
	 * Check if the CPUs from the NE CPU pool are from the same NUMA node.
	 */
	for_each_cpu(cpu, cpu_pool) {
		if (numa_node < 0) {
			numa_node = cpu_to_node(cpu);
			if (numa_node < 0) {
				pr_err("%s: Invalid NUMA node %d\n",
				       ne_misc_dev.name, numa_node);

				rc = -EINVAL;

				goto free_cpumask;
			}
		} else {
			if (numa_node != cpu_to_node(cpu)) {
				pr_err("%s: CPUs with different NUMA nodes\n",
				       ne_misc_dev.name);

				rc = -EINVAL;

				goto free_cpumask;
			}
		}
	}

	ne_cpu_pool.numa_node = numa_node;

	/* Split the NE CPU pool in CPU cores. */
	for_each_cpu(cpu, cpu_pool) {
		core_id = topology_core_id(cpu);
		if (core_id < 0 || core_id >= ne_cpu_pool.avail_cores_size) {
			pr_err("%s: Invalid core id  %d\n", ne_misc_dev.name,
			       core_id);

			rc = -EINVAL;

			goto clear_cpumask;
		}

		cpumask_set_cpu(cpu, ne_cpu_pool.avail_cores[core_id]);
	}

	for_each_cpu(cpu, cpu_pool) {
		rc = remove_cpu(cpu);
		if (rc != 0) {
			pr_err("%s: CPU %d is not offlined [rc=%d]\n",
			       ne_misc_dev.name, cpu, rc);

			goto online_cpus;
		}
	}

	mutex_unlock(&ne_cpu_pool.mutex);

	free_cpumask_var(cpu_pool);

	return 0;

online_cpus:
	for_each_cpu(cpu, cpu_pool)
		add_cpu(cpu);
clear_cpumask:
	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		cpumask_clear(ne_cpu_pool.avail_cores[i]);
free_cpumask:
	free_cpumask_var(cpu_pool);
	mutex_unlock(&ne_cpu_pool.mutex);

	return rc;
}

/**
 * ne_teardown_cpu_pool - Online the CPUs from the NE CPU pool and cleanup the
 * CPU pool.
 */
static void ne_teardown_cpu_pool(void)
{
	unsigned int cpu = 0;
	unsigned int i = 0;
	int rc = -EINVAL;

	if (!capable(CAP_SYS_ADMIN)) {
		pr_err("%s: No admin capability for CPU pool setup\n",
		       ne_misc_dev.name);

		return;
	}

	mutex_lock(&ne_cpu_pool.mutex);

	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++) {
		for_each_cpu(cpu, ne_cpu_pool.avail_cores[i]) {
			rc = add_cpu(cpu);
			if (rc != 0)
				pr_err("%s: CPU %d is not onlined [rc=%d]\n",
				       ne_misc_dev.name, cpu, rc);
		}

		cpumask_clear(ne_cpu_pool.avail_cores[i]);
	}

	mutex_unlock(&ne_cpu_pool.mutex);
}

static int ne_set_kernel_param(const char *val, const struct kernel_param *kp)
{
	char error_val[] = "";
	int rc = -EINVAL;

	if (ne_check_enclaves_created()) {
		pr_err("%s: The CPU pool is used by enclave(s)\n",
		       ne_misc_dev.name);

		return -EPERM;
	}

	ne_teardown_cpu_pool();

	rc = ne_setup_cpu_pool(val);
	if (rc < 0) {
		pr_err("%s: Error in setup CPU pool [rc=%d]\n",
		       ne_misc_dev.name, rc);

		param_set_copystring(error_val, kp);

		return rc;
	}

	return param_set_copystring(val, kp);
}

/**
 * ne_get_cpu_from_cpu_pool - Get a CPU from the CPU pool. If the vCPU id is 0,
 * the CPU is autogenerated and chosen from the NE CPU pool.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @vcpu_id: id of the CPU to be associated with the given slot, apic id on x86.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_get_cpu_from_cpu_pool(struct ne_enclave *ne_enclave, u32 *vcpu_id)
{
	int core_id = -1;
	unsigned int cpu = 0;
	unsigned int i = 0;

	if (*vcpu_id != 0) {
		if (cpumask_test_cpu(*vcpu_id, ne_enclave->vcpu_ids)) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "CPU %d already used\n",
					    *vcpu_id);

			return -EINVAL;
		}

		for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
			if (cpumask_test_cpu(*vcpu_id,
					     ne_enclave->avail_cpu_cores[i]))
				return 0;

		mutex_lock(&ne_cpu_pool.mutex);

		for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
			if (cpumask_test_cpu(*vcpu_id,
					     ne_cpu_pool.avail_cores[i])) {
				core_id = i;

				break;
			}

		if (core_id < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "CPU %d is not in NE CPU pool\n",
					    *vcpu_id);

			mutex_unlock(&ne_cpu_pool.mutex);

			return -EINVAL;
		}

		if (core_id >= ne_enclave->avail_cpu_cores_size) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Invalid core id %d - ne_enclave\n",
					    core_id);

			mutex_unlock(&ne_cpu_pool.mutex);

			return -EINVAL;
		}

		for_each_cpu(cpu, ne_cpu_pool.avail_cores[core_id])
			cpumask_set_cpu(cpu,
					ne_enclave->avail_cpu_cores[core_id]);

		cpumask_clear(ne_cpu_pool.avail_cores[core_id]);

		mutex_unlock(&ne_cpu_pool.mutex);

		return 0;
	}

	/* There are CPU siblings available to choose from. */
	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
		for_each_cpu(cpu, ne_enclave->avail_cpu_cores[i])
			if (!cpumask_test_cpu(cpu, ne_enclave->vcpu_ids)) {
				*vcpu_id = cpu;

				return 0;
			}


	mutex_lock(&ne_cpu_pool.mutex);

	/* Choose a CPU from the available NE CPU pool. */
	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		if (!cpumask_empty(ne_cpu_pool.avail_cores[i])) {
			core_id = i;

			break;
		}

	if (core_id < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "No CPUs available in NE CPU pool\n");

		mutex_unlock(&ne_cpu_pool.mutex);

		return -EINVAL;
	}

	if (core_id >= ne_enclave->avail_cpu_cores_size) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid core id %d - ne_enclave\n",
				    core_id);

		mutex_unlock(&ne_cpu_pool.mutex);

		return -EINVAL;
	}

	*vcpu_id = cpumask_any(ne_cpu_pool.avail_cores[core_id]);

	for_each_cpu(cpu, ne_cpu_pool.avail_cores[core_id])
		cpumask_set_cpu(cpu, ne_enclave->avail_cpu_cores[core_id]);

	cpumask_clear(ne_cpu_pool.avail_cores[core_id]);

	mutex_unlock(&ne_cpu_pool.mutex);

	return 0;
}

/**
 * ne_create_vcpu_ioctl - Add vCPU to the slot associated with the current
 * enclave. Create vCPU file descriptor to be further used for CPU handling.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @vcpu_id: id of the CPU to be associated with the given slot, apic id on x86.
 *
 * @returns: vCPU fd on success, negative return value on failure.
 */
static int ne_create_vcpu_ioctl(struct ne_enclave *ne_enclave, u32 vcpu_id)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int rc = -EINVAL;
	struct slot_add_vcpu_req slot_add_vcpu_req = {};
	int vcpu_fd = -1;
	struct file *vcpu_file = NULL;
	/*
	 * ne-vm-vcpu-<u32 vcpu-id>
	 *
	 * ne-vm-vcpu (10 chars) + - (1 char) + u32 (12 chars) + \0 (1 char)
	 */
	char vcpu_file_name[10 + 1 + 12 + 1];

	if (ne_enclave->mm != current->mm)
		return -EIO;

	vcpu_fd = get_unused_fd_flags(O_CLOEXEC);
	if (vcpu_fd < 0) {
		rc = vcpu_fd;

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in getting unused fd [rc=%d]\n", rc);

		return rc;
	}

	rc = snprintf(vcpu_file_name, sizeof(vcpu_file_name), "ne-vm-vcpu-%d",
		      vcpu_id);
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in setting vCPU file name [rc=%d]\n",
				    rc);

		goto put_fd;
	}

	vcpu_file = anon_inode_getfile(vcpu_file_name, &ne_enclave_vcpu_fops,
				       ne_enclave, O_RDWR);
	if (IS_ERR(vcpu_file)) {
		rc = PTR_ERR(vcpu_file);

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in anon inode get file [rc=%d]\n",
				    rc);

		goto put_fd;
	}

	slot_add_vcpu_req.slot_uid = ne_enclave->slot_uid;
	slot_add_vcpu_req.vcpu_id = vcpu_id;

	rc = ne_do_request(ne_enclave->pdev, SLOT_ADD_VCPU, &slot_add_vcpu_req,
			   sizeof(slot_add_vcpu_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in slot add vCPU [rc=%d]\n", rc);

		goto put_file;
	}

	cpumask_set_cpu(vcpu_id, ne_enclave->vcpu_ids);

	ne_enclave->nr_vcpus++;

	fd_install(vcpu_fd, vcpu_file);

	return vcpu_fd;

put_file:
	fput(vcpu_file);
put_fd:
	put_unused_fd(vcpu_fd);

	return rc;
}

/**
 * ne_sanity_check_user_mem_region - Sanity check the userspace memory
 * region received during the set user memory region ioctl call.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @mem_region: user space memory region to be sanity checked.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_sanity_check_user_mem_region(struct ne_enclave *ne_enclave,
	struct ne_user_memory_region *mem_region)
{
	if (ne_enclave->mm != current->mm)
		return -EIO;

	if ((mem_region->memory_size % NE_MIN_MEM_REGION_SIZE) != 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Mem size not multiple of 2 MiB\n");

		return -EINVAL;
	}

	if ((mem_region->userspace_addr & (NE_MIN_MEM_REGION_SIZE - 1)) ||
	    !user_access_ok((void __user *)(unsigned long)mem_region->userspace_addr,
		       mem_region->memory_size)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid user space addr range\n");

		return -EINVAL;
	}

	return 0;
}

/**
 * ne_set_user_memory_region_ioctl - Add user space memory region to the slot
 * associated with the current enclave.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @mem_region: user space memory region to be associated with the given slot.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_set_user_memory_region_ioctl(struct ne_enclave *ne_enclave,
	struct ne_user_memory_region *mem_region)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	long gup_rc = 0;
	unsigned long i = 0;
	struct ne_mem_region *ne_mem_region = NULL;
	unsigned long nr_phys_contig_mem_regions = 0;
	unsigned long nr_pinned_pages = 0;
	struct page **phys_contig_mem_regions = NULL;
	int rc = -EINVAL;
	struct slot_add_mem_req slot_add_mem_req = {};

	rc = ne_sanity_check_user_mem_region(ne_enclave, mem_region);
	if (rc < 0)
		return rc;

	ne_mem_region = kzalloc(sizeof(*ne_mem_region), GFP_KERNEL);
	if (!ne_mem_region)
		return -ENOMEM;

	/*
	 * TODO: Update nr_pages value to handle contiguous virtual address
	 * ranges mapped to non-contiguous physical regions. Hugetlbfs can give
	 * 2 MiB / 1 GiB contiguous physical regions.
	 */
	ne_mem_region->nr_pages = mem_region->memory_size /
		NE_MIN_MEM_REGION_SIZE;

	ne_mem_region->pages = kcalloc(ne_mem_region->nr_pages,
				       sizeof(*ne_mem_region->pages),
				       GFP_KERNEL);
	if (!ne_mem_region->pages) {
		kfree(ne_mem_region);

		return -ENOMEM;
	}

	phys_contig_mem_regions = kcalloc(ne_mem_region->nr_pages,
					  sizeof(*phys_contig_mem_regions),
					  GFP_KERNEL);
	if (!phys_contig_mem_regions) {
		kfree(ne_mem_region->pages);
		kfree(ne_mem_region);

		return -ENOMEM;
	}

	/*
	 * TODO: Handle non-contiguous memory regions received from user space.
	 * Hugetlbfs can give 2 MiB / 1 GiB contiguous physical regions. The
	 * virtual address space can be seen as contiguous, although it is
	 * mapped underneath to 2 MiB / 1 GiB physical regions e.g. 8 MiB
	 * virtual address space mapped to 4 physically contiguous regions of 2
	 * MiB.
	 */
	do {
		unsigned long tmp_nr_pages = ne_mem_region->nr_pages -
			nr_pinned_pages;
		struct page **tmp_pages = ne_mem_region->pages +
			nr_pinned_pages;
		u64 tmp_userspace_addr = mem_region->userspace_addr +
			nr_pinned_pages * NE_MIN_MEM_REGION_SIZE;

		gup_rc = get_user_pages(tmp_userspace_addr, tmp_nr_pages,
					FOLL_GET, tmp_pages, NULL);
		if (gup_rc < 0) {
			rc = gup_rc;

			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in gup [rc=%d]\n", rc);

			unpin_user_pages(ne_mem_region->pages, nr_pinned_pages);

			goto free_mem_region;
		}

		nr_pinned_pages += gup_rc;

	} while (nr_pinned_pages < ne_mem_region->nr_pages);

	/*
	 * TODO: Update checks once physically contiguous regions are collected
	 * based on the user space address and get_user_pages() results.
	 */
	for (i = 0; i < ne_mem_region->nr_pages; i++) {
		if (!PageHuge(ne_mem_region->pages[i])) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Not a hugetlbfs page\n");

			rc = -EINVAL;

			goto unpin_pages;
		}

#ifdef page_hstate
		if (huge_page_size(page_hstate(ne_mem_region->pages[i])) !=
		    NE_MIN_MEM_REGION_SIZE) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Page size isn't 2 MiB\n");

			rc = -EINVAL;

			goto unpin_pages;
		}
#endif

		if (ne_enclave->numa_node !=
		    page_to_nid(ne_mem_region->pages[i])) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Page isn't from NUMA node %d\n",
					    ne_enclave->numa_node);

			rc = -EINVAL;

			goto unpin_pages;
		}

		/*
		 * TODO: Update once handled non-contiguous memory regions
		 * received from user space.
		 */
		phys_contig_mem_regions[i] = ne_mem_region->pages[i];
	}

	/*
	 * TODO: Update once handled non-contiguous memory regions received
	 * from user space.
	 */
	nr_phys_contig_mem_regions = ne_mem_region->nr_pages;

	if ((ne_enclave->nr_mem_regions + nr_phys_contig_mem_regions) >
	    ne_enclave->max_mem_regions) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Reached max memory regions %lld\n",
				    ne_enclave->max_mem_regions);

		rc = -EINVAL;

		goto unpin_pages;
	}

	for (i = 0; i < nr_phys_contig_mem_regions; i++) {
		u64 phys_addr = page_to_phys(phys_contig_mem_regions[i]);

		slot_add_mem_req.slot_uid = ne_enclave->slot_uid;
		slot_add_mem_req.paddr = phys_addr;
		/*
		 * TODO: Update memory size of physical contiguous memory
		 * region, in case of non-contiguous memory regions received
		 * from user space.
		 */
		slot_add_mem_req.size = NE_MIN_MEM_REGION_SIZE;

		rc = ne_do_request(ne_enclave->pdev, SLOT_ADD_MEM,
				   &slot_add_mem_req, sizeof(slot_add_mem_req),
				   &cmd_reply, sizeof(cmd_reply));
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in slot add mem [rc=%d]\n",
					    rc);

			/* TODO: Only unpin memory regions not added. */
			goto unpin_pages;
		}

		ne_enclave->mem_size += slot_add_mem_req.size;
		ne_enclave->nr_mem_regions++;

		memset(&slot_add_mem_req, 0, sizeof(slot_add_mem_req));
		memset(&cmd_reply, 0, sizeof(cmd_reply));
	}

	list_add(&ne_mem_region->mem_region_list_entry,
		 &ne_enclave->mem_regions_list);

	kfree(phys_contig_mem_regions);

	return 0;

unpin_pages:
	unpin_user_pages(ne_mem_region->pages, ne_mem_region->nr_pages);
free_mem_region:
	kfree(phys_contig_mem_regions);
	kfree(ne_mem_region->pages);
	kfree(ne_mem_region);

	return rc;
}

/**
 * ne_start_enclave_ioctl - Trigger enclave start after the enclave resources,
 * such as memory and CPU, have been set.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @enclave_start_info: enclave info that includes enclave cid and flags.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_start_enclave_ioctl(struct ne_enclave *ne_enclave,
	struct ne_enclave_start_info *enclave_start_info)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	unsigned int cpu = 0;
	struct enclave_start_req enclave_start_req = {};
	unsigned int i = 0;
	int rc = -EINVAL;

	if (!ne_enclave->nr_mem_regions) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Enclave has no mem regions\n");

		return -ENOMEM;
	}

	if (ne_enclave->mem_size < NE_MIN_ENCLAVE_MEM_SIZE) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Enclave memory is less than %ld\n",
				    NE_MIN_ENCLAVE_MEM_SIZE);

		return -ENOMEM;
	}

	if (!ne_enclave->nr_vcpus) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Enclave has no vCPUs\n");

		return -EINVAL;
	}

	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
		for_each_cpu(cpu, ne_enclave->avail_cpu_cores[i])
			if (!cpumask_test_cpu(cpu, ne_enclave->vcpu_ids)) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "CPU siblings not used\n");

				return -EINVAL;
			}

	enclave_start_req.enclave_cid = enclave_start_info->enclave_cid;
	enclave_start_req.flags = enclave_start_info->flags;
	enclave_start_req.slot_uid = ne_enclave->slot_uid;

	rc = ne_do_request(ne_enclave->pdev, ENCLAVE_START, &enclave_start_req,
			   sizeof(enclave_start_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in enclave start [rc=%d]\n", rc);

		return rc;
	}

	ne_enclave->state = NE_STATE_RUNNING;

	enclave_start_info->enclave_cid = cmd_reply.enclave_cid;

	return 0;
}

static long ne_enclave_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct ne_enclave *ne_enclave = file->private_data;

	switch (cmd) {
	case NE_CREATE_VCPU: {
		int rc = -EINVAL;
		int vcpu_fd = -1;
		struct file *vcpu_file = NULL;
		u32 vcpu_id = 0;

		if (copy_from_user(&vcpu_id, (void *)arg, sizeof(vcpu_id))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave isn't in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		/* Check if the CPU ID is not greater than the maximum. */
		if (vcpu_id >= (ne_enclave->avail_cpu_cores_size *
			smp_num_siblings)) {
			dev_err_ratelimited(ne_misc_dev.this_device,
				"vCPU id higher than max CPU id\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		/* Use the CPU pool for choosing a CPU for the enclave. */
		rc = ne_get_cpu_from_cpu_pool(ne_enclave, &vcpu_id);
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in get CPU from pool\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		vcpu_fd = ne_create_vcpu_ioctl(ne_enclave, vcpu_id);
		if (vcpu_fd < 0) {
			cpumask_clear_cpu(vcpu_id, ne_enclave->vcpu_ids);

			rc = vcpu_fd;

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (copy_to_user((void *)arg, &vcpu_id, sizeof(vcpu_id))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy to user\n");

			vcpu_file = fget(vcpu_fd);
			fput(vcpu_file);
			fput(vcpu_file);
			put_unused_fd(vcpu_fd);

			return -EFAULT;
		}

		return vcpu_fd;
	}

	case NE_GET_IMAGE_LOAD_INFO: {
		struct ne_image_load_info image_load_info = {};

		if (copy_from_user(&image_load_info, (void *)arg,
				   sizeof(image_load_info))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave isn't in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (image_load_info.flags == NE_EIF_IMAGE)
			image_load_info.memory_offset = NE_EIF_LOAD_OFFSET;

		if (copy_to_user((void *)arg, &image_load_info,
				 sizeof(image_load_info))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy to user\n");

			return -EFAULT;
		}

		return 0;
	}

	case NE_SET_USER_MEMORY_REGION: {
		struct ne_user_memory_region mem_region = {};
		int rc = -EINVAL;

		if (copy_from_user(&mem_region, (void *)arg,
				   sizeof(mem_region))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave isn't in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		rc = ne_set_user_memory_region_ioctl(ne_enclave, &mem_region);
		if (rc < 0) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		return 0;
	}

	case NE_START_ENCLAVE: {
		struct ne_enclave_start_info enclave_start_info = {};
		int rc = -EINVAL;

		if (copy_from_user(&enclave_start_info, (void *)arg,
				   sizeof(enclave_start_info))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave isn't in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		rc = ne_start_enclave_ioctl(ne_enclave, &enclave_start_info);
		if (rc < 0) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (copy_to_user((void *)arg, &enclave_start_info,
				 sizeof(enclave_start_info))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy to user\n");

			return -EFAULT;
		}

		return 0;
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
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 */
static void ne_enclave_remove_all_mem_region_entries(
	struct ne_enclave *ne_enclave)
{
	struct ne_mem_region *ne_mem_region = NULL;
	struct ne_mem_region *ne_mem_region_tmp = NULL;

	list_for_each_entry_safe(ne_mem_region, ne_mem_region_tmp,
				 &ne_enclave->mem_regions_list,
				 mem_region_list_entry) {
		list_del(&ne_mem_region->mem_region_list_entry);

		unpin_user_pages(ne_mem_region->pages,
				 ne_mem_region->nr_pages);

		kfree(ne_mem_region->pages);

		kfree(ne_mem_region);
	}
}

/**
 * ne_enclave_remove_all_vcpu_id_entries - Remove all vCPU id entries
 * from the enclave data structure.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 */
static void ne_enclave_remove_all_vcpu_id_entries(struct ne_enclave *ne_enclave)
{
	unsigned int cpu = 0;
	unsigned int i = 0;

	mutex_lock(&ne_cpu_pool.mutex);

	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++) {
		for_each_cpu(cpu, ne_enclave->avail_cpu_cores[i])
			/* Update the available NE CPU pool. */
			cpumask_set_cpu(cpu, ne_cpu_pool.avail_cores[i]);

		free_cpumask_var(ne_enclave->avail_cpu_cores[i]);
	}

	mutex_unlock(&ne_cpu_pool.mutex);

	kfree(ne_enclave->avail_cpu_cores);

	free_cpumask_var(ne_enclave->vcpu_ids);
}

/**
 * ne_pci_dev_remove_enclave_entry - Remove enclave entry from the data
 * structure that is part of the PCI device private data.
 *
 * This function gets called with the ne_pci_dev enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @ne_pci_dev: private data associated with the PCI device.
 */
static void ne_pci_dev_remove_enclave_entry(struct ne_enclave *ne_enclave,
					    struct ne_pci_dev *ne_pci_dev)
{
	struct ne_enclave *ne_enclave_entry = NULL;
	struct ne_enclave *ne_enclave_entry_tmp = NULL;

	list_for_each_entry_safe(ne_enclave_entry, ne_enclave_entry_tmp,
				 &ne_pci_dev->enclaves_list,
				 enclave_list_entry) {
		if (ne_enclave_entry->slot_uid == ne_enclave->slot_uid) {
			list_del(&ne_enclave_entry->enclave_list_entry);

			break;
		}
	}
}

static int ne_enclave_release(struct inode *inode, struct file *file)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct enclave_stop_req enclave_stop_request = {};
	struct ne_enclave *ne_enclave = file->private_data;
	struct ne_pci_dev *ne_pci_dev = NULL;
	int rc = -EINVAL;
	struct slot_free_req slot_free_req = {};

	if (!ne_enclave)
		return 0;

	/*
	 * Early exit in case there is an error in the enclave creation logic
	 * and fput() is called on the cleanup path.
	 */
	if (!ne_enclave->slot_uid)
		return 0;

	ne_pci_dev = pci_get_drvdata(ne_enclave->pdev);

	/*
	 * Acquire the enclave list mutex before the enclave mutex
	 * in order to avoid deadlocks with @ref ne_event_work_handler.
	 */
	mutex_lock(&ne_pci_dev->enclaves_list_mutex);
	mutex_lock(&ne_enclave->enclave_info_mutex);

	if (ne_enclave->state != NE_STATE_INIT &&
	    ne_enclave->state != NE_STATE_STOPPED) {
		enclave_stop_request.slot_uid = ne_enclave->slot_uid;

		rc = ne_do_request(ne_enclave->pdev, ENCLAVE_STOP,
				   &enclave_stop_request,
				   sizeof(enclave_stop_request), &cmd_reply,
				   sizeof(cmd_reply));
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in enclave stop [rc=%d]\n",
					    rc);

			goto unlock_mutex;
		}

		memset(&cmd_reply, 0, sizeof(cmd_reply));
	}

	slot_free_req.slot_uid = ne_enclave->slot_uid;

	rc = ne_do_request(ne_enclave->pdev, SLOT_FREE, &slot_free_req,
			   sizeof(slot_free_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in slot free [rc=%d]\n", rc);

		goto unlock_mutex;
	}

	ne_pci_dev_remove_enclave_entry(ne_enclave, ne_pci_dev);
	ne_enclave_remove_all_mem_region_entries(ne_enclave);
	ne_enclave_remove_all_vcpu_id_entries(ne_enclave);

	pci_dev_put(ne_enclave->pdev);

	mutex_unlock(&ne_enclave->enclave_info_mutex);
	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

	kfree(ne_enclave);

	return 0;

unlock_mutex:
	mutex_unlock(&ne_enclave->enclave_info_mutex);
	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

	return rc;
}

static __poll_t ne_enclave_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;
	struct ne_enclave *ne_enclave = file->private_data;

	poll_wait(file, &ne_enclave->eventq, wait);

	if (!ne_enclave->has_event)
		return mask;

	mask = POLLHUP;

	return mask;
}

static const struct file_operations ne_enclave_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.poll		= ne_enclave_poll,
	.unlocked_ioctl	= ne_enclave_ioctl,
	.release	= ne_enclave_release,
};

/**
 * ne_create_vm_ioctl - Alloc slot to be associated with an enclave. Create
 * enclave file descriptor to be further used for enclave resources handling
 * e.g. memory regions and CPUs.
 *
 * This function gets called with the ne_pci_dev enclave mutex held.
 *
 * @pdev: PCI device used for enclave lifetime management.
 * @ne_pci_dev: private data associated with the PCI device.
 * @slot_uid: generated unique slot id associated with an enclave.
 *
 * @returns: enclave fd on success, negative return value on failure.
 */
static int ne_create_vm_ioctl(struct pci_dev *pdev,
			      struct ne_pci_dev *ne_pci_dev, u64 *slot_uid)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int enclave_fd = -1;
	struct file *enclave_file = NULL;
	unsigned int i = 0;
	struct ne_enclave *ne_enclave = NULL;
	int rc = -EINVAL;
	struct slot_alloc_req slot_alloc_req = {};

	mutex_lock(&ne_cpu_pool.mutex);

	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		if (!cpumask_empty(ne_cpu_pool.avail_cores[i]))
			break;

	if (i == ne_cpu_pool.avail_cores_size) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "No CPUs available in CPU pool\n");

		mutex_unlock(&ne_cpu_pool.mutex);

		return -EINVAL;
	}

	mutex_unlock(&ne_cpu_pool.mutex);

	ne_enclave = kzalloc(sizeof(*ne_enclave), GFP_KERNEL);
	if (!ne_enclave)
		return -ENOMEM;

	mutex_lock(&ne_cpu_pool.mutex);

	ne_enclave->avail_cpu_cores_size = ne_cpu_pool.avail_cores_size;
	ne_enclave->numa_node = ne_cpu_pool.numa_node;

	mutex_unlock(&ne_cpu_pool.mutex);

	ne_enclave->avail_cpu_cores = kcalloc(ne_enclave->avail_cpu_cores_size,
		sizeof(*ne_enclave->avail_cpu_cores), GFP_KERNEL);
	if (!ne_enclave->avail_cpu_cores) {
		rc = -ENOMEM;

		goto free_ne_enclave;
	}

	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
		if (!zalloc_cpumask_var(&ne_enclave->avail_cpu_cores[i],
					GFP_KERNEL)) {
			rc = -ENOMEM;

			goto free_cpumask;
		}

	if (!zalloc_cpumask_var(&ne_enclave->vcpu_ids, GFP_KERNEL)) {
		rc = -ENOMEM;

		goto free_cpumask;
	}

	ne_enclave->pdev = pdev;

	enclave_fd = get_unused_fd_flags(O_CLOEXEC);
	if (enclave_fd < 0) {
		rc = enclave_fd;

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in getting unused fd [rc=%d]\n",
				    rc);

		goto free_cpumask;
	}

	enclave_file = anon_inode_getfile("ne-vm", &ne_enclave_fops, ne_enclave,
					  O_RDWR);
	if (IS_ERR(enclave_file)) {
		rc = PTR_ERR(enclave_file);

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in anon inode get file [rc=%d]\n",
				    rc);

		goto put_fd;
	}

	rc = ne_do_request(ne_enclave->pdev, SLOT_ALLOC, &slot_alloc_req,
			   sizeof(slot_alloc_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in slot alloc [rc=%d]\n", rc);

		goto put_file;
	}

	init_waitqueue_head(&ne_enclave->eventq);
	ne_enclave->has_event = false;
	mutex_init(&ne_enclave->enclave_info_mutex);
	ne_enclave->max_mem_regions = cmd_reply.mem_regions;
	INIT_LIST_HEAD(&ne_enclave->mem_regions_list);
	ne_enclave->mm = current->mm;
	ne_enclave->slot_uid = cmd_reply.slot_uid;
	ne_enclave->state = NE_STATE_INIT;

	list_add(&ne_enclave->enclave_list_entry, &ne_pci_dev->enclaves_list);

	*slot_uid = ne_enclave->slot_uid;

	fd_install(enclave_fd, enclave_file);

	return enclave_fd;

put_file:
	fput(enclave_file);
put_fd:
	put_unused_fd(enclave_fd);
free_cpumask:
	free_cpumask_var(ne_enclave->vcpu_ids);
	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
		free_cpumask_var(ne_enclave->avail_cpu_cores[i]);
	kfree(ne_enclave->avail_cpu_cores);
free_ne_enclave:
	kfree(ne_enclave);

	return rc;
}

static long ne_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NE_GET_API_VERSION:
		return NE_API_VERSION;

	case NE_CREATE_VM: {
		int enclave_fd = -1;
		struct file *enclave_file = NULL;
		struct ne_pci_dev *ne_pci_dev = NULL;
		struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON,
						      PCI_DEVICE_ID_NE, NULL);
		int rc = -EINVAL;
		u64 slot_uid = 0;

		ne_pci_dev = pci_get_drvdata(pdev);

		mutex_lock(&ne_pci_dev->enclaves_list_mutex);

		enclave_fd = ne_create_vm_ioctl(pdev, ne_pci_dev, &slot_uid);
		if (enclave_fd < 0) {
			rc = enclave_fd;

			mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

			pci_dev_put(pdev);

			return rc;
		}

		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

		if (copy_to_user((void *)arg, &slot_uid, sizeof(slot_uid))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy to user\n");

			enclave_file = fget(enclave_fd);
			fput(enclave_file);
			fput(enclave_file);
			put_unused_fd(enclave_fd);

			return -EFAULT;
		}

		return enclave_fd;
	}

	default:
		return -ENOTTY;
	}

	return 0;
}

static const struct file_operations ne_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= ne_ioctl,
};

struct miscdevice ne_misc_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "nitro_enclaves",
	.fops	= &ne_fops,
	.mode	= 0660,
};

static int __init ne_init(void)
{
	unsigned int i = 0;
	int rc = -EINVAL;

	ne_cpu_pool.avail_cores_size = nr_cpu_ids / smp_num_siblings;

	ne_cpu_pool.avail_cores = kcalloc(ne_cpu_pool.avail_cores_size,
					  sizeof(*ne_cpu_pool.avail_cores),
					  GFP_KERNEL);
	if (!ne_cpu_pool.avail_cores)
		return -ENOMEM;

	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		if (!zalloc_cpumask_var(&ne_cpu_pool.avail_cores[i],
					GFP_KERNEL)) {
			rc = -ENOMEM;

			goto free_cpumask;
		}

	mutex_init(&ne_cpu_pool.mutex);

	rc = pci_register_driver(&ne_pci_driver);
	if (rc < 0) {
		pr_err("%s: Error in pci register driver [rc=%d]\n",
		       ne_misc_dev.name, rc);

		goto free_cpumask;
	}

	return 0;

free_cpumask:
	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		free_cpumask_var(ne_cpu_pool.avail_cores[i]);
	kfree(ne_cpu_pool.avail_cores);

	return rc;
}

static void __exit ne_exit(void)
{
	unsigned int i = 0;

	pci_unregister_driver(&ne_pci_driver);

	ne_teardown_cpu_pool();

	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		free_cpumask_var(ne_cpu_pool.avail_cores[i]);

	kfree(ne_cpu_pool.avail_cores);
}

/* TODO: Handle actions such as reboot, kexec. */

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
