//! Sysfs-based enclave resource allocation
pub mod cpu;
pub mod huge_pages;
use std::collections::BTreeSet;


use crate::configuration::ResourcePool;

#[derive(thiserror::Error, Debug)]
pub enum Error
{
	#[error(transparent)]
	Cpu(#[from] cpu::Error),
	#[error(transparent)]
	HugePage(#[from] huge_pages::Error),
	#[error("failed to find suitable combination of CPUs and memory")]
	Allocation,
	#[error("Config file cannot include cpus from different numa nodes")]
	NumaDifference,
}
/// Allocates resources based on CPU count after CPU pool allocation
/// 
/// This function is called after `allocate_by_cpu_pools` to ensure all resources
/// are allocated on the same NUMA node. The workflow is:
/// 
/// 1. If user specified specific CPU IDs (`allocate_by_cpu_pools`):
///    - Determines the NUMA node of those CPUs
///    - Passes that NUMA node to this function
/// 2. This function then allocates additional resources:
///    - Finds suitable CPU sets on the specified NUMA node
///    - Allocates corresponding memory
/// 
/// # Arguments
/// * `pool` - Vector of resource requirements with CPU counts
/// * `target_numa` - NUMA node determined by previous CPU pool allocation
pub fn allocate_by_cpu_count(mut pool: Vec<ResourcePool>,target_numa: Option<usize>) -> Result<(), Error>
{
	pool.retain(|p| matches!(p, ResourcePool::CpuCount{..}));
	if pool.len() == 0 {
		return Ok(());
	}


	let total_cpu_count: usize = pool.iter()
	.map(|p| {
		if let ResourcePool::CpuCount { cpu_count, .. } = p {
			*cpu_count
		} else {
			unreachable!()  // Won't happen because we already filtered
		}
	})
	.sum();
				
	// Find NUMA nodes with a suitable CPU set
	for (numa_node, cpu_set) in cpu::find_suitable_cpu_sets(total_cpu_count)?.into_iter()
	.filter(|(numa_node, _)| target_numa.is_none() || *numa_node == target_numa.unwrap()) 
	{//if user specificly defined cpu ids in config file and they also want to allocate some other resource pool with cpu_count tag then allocator should allocate them in same numa node
		match allocate_cpus_n_pages(&pool, cpu_set, numa_node) {
			Ok(_) => return Ok(()),
			Err(Error::HugePage(huge_pages::Error::InsufficientMemory)) => continue,
			Err(error) => return Err(error.into()),
		}
	}
	return Err(Error::Allocation);
}
/// Allocates resources based on user-specified CPU IDs
/// 
/// This function runs first in the allocation process:
/// 1. Verifies all specified CPUs are on the same NUMA node
/// 2. Allocates the requested CPUs and corresponding memory
/// 3. Returns the NUMA node where resources were allocated
/// 
/// The returned NUMA node is used as input for `allocate_by_cpu_count`
/// to ensure all subsequent allocations occur on the same node.
/// 
/// Returns Some(numa_node) if CPUs were allocated, None if no CPU pools were specified
pub fn allocate_by_cpu_pools(mut pools: Vec<ResourcePool>) -> Result<Option<usize>, Error>
{
	pools.retain(|p| matches!(p, ResourcePool::CpuPool {..}));
	if pools.len() == 0 {
		return Ok(None);
	}
	
	let mut final_cpu_list = cpu::CpuSet::new();

	//merging cpu lists
	for pool in &pools {
		if let ResourcePool::CpuPool { cpu_pool, .. } = pool {
			final_cpu_list.extend(cpu::parse_cpu_list(cpu_pool)?);
		}
	}

	//check if provided cpus are in the same numa node
	let numa_node = match sanity_check_numa_nodes(&final_cpu_list) {
		Ok(numa) => numa,
		Err(e) => return Err(e),
	};

	match allocate_cpus_n_pages(&pools, final_cpu_list, numa_node) {
		Ok(_) => return Ok(Some(numa_node)),
		Err(error) => return Err(error.into()),
	}

}


/// Verifies that all specified CPUs belong to the same NUMA node
/// Returns the NUMA node ID if all CPUs are on the same node
pub fn sanity_check_numa_nodes(cpu_set: &BTreeSet<usize>) -> Result<usize, Error> {//change the logic
	let mut numa = usize::MAX;
	for cpu in cpu_set{
		let cpu_numa = cpu::get_numa_node_for_cpu(*cpu)?;
		if numa != usize::MAX {
			if numa != cpu_numa{
				return Err(Error::NumaDifference);
			}
		}
		numa = cpu_numa;
	}
	Ok(numa)
}
/// Performs the actual allocation of CPUs and memory
/// 
/// Allocation strategy:
/// 1. Attempts to allocate memory first
/// 2. Only proceeds with CPU allocation if memory allocation succeeds
/// 3. Rolls back memory allocation if CPU allocation fails
/// 4. If either memory or CPU allocation fails on a NUMA node:
///    - All allocated resources are released
///    - Returns an error indicating insufficient resources
///    - Caller should try allocation on another NUMA node if available
/// Example flow:
/// NUMA Node 0:
///   ✓ Memory allocation successful
///   ✗ CPU allocation failed
///   → Release memory, try NUMA Node 1
/// NUMA Node 1:
///   ✓ Memory allocation successful
///   ✓ CPU allocation successful
///   → Complete allocation successful
fn allocate_cpus_n_pages(pool: &Vec<ResourcePool>, cpu_set: BTreeSet<usize>, numa_node:usize) -> Result<(), Error>{
	let mut allocated_pages:Vec<huge_pages::Allocation> = Vec::with_capacity(pool.len());
	// Try to allocate the memory on the NUMA node ...
	for enclave in pool {
		let memory_mib = match enclave {
			ResourcePool::CpuCount { memory_mib, .. } |
			ResourcePool::CpuPool { memory_mib, .. } => *memory_mib
		};
		let huge_pages_allocation = 
			match huge_pages::Allocation::new(numa_node, memory_mib)
			{
				Ok(allocation) => allocation,
				Err(huge_pages::Error::InsufficientMemory) => {
					//release everything
					for delete in &allocated_pages {
						delete.release_resources();
					}
					return Err(Error::HugePage(huge_pages::Error::InsufficientMemory));
				}
				Err(error) => return Err(error.into()),
			};
		allocated_pages.push(huge_pages_allocation);
	}
	// ... if successful, also allocate the CPU set
	match cpu::Allocation::new(cpu_set) {
		Ok(_) => {return Ok(())},
		Err(_) => {
			for delete in &allocated_pages {
				delete.release_resources();
			}
			return Err(Error::Cpu(cpu::Error::InsufficientCpuPool));
		},
	}
}