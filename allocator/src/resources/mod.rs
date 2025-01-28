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

pub struct Allocation
{
	// Both allocations implement Drop
	#[allow(dead_code)]
	cpu_set_allocation: cpu::Allocation,
	_huge_pages_allocation: huge_pages::Allocation,
}

impl Allocation
{
	#[allow(dead_code)]
	pub fn new(cpu_count: usize, memory_mib: usize) -> Result<Self, Error>
	{
		// Find NUMA nodes with a suitable CPU set
		for (numa_node, cpu_set) in cpu::find_suitable_cpu_sets(cpu_count)?.into_iter()
		{
			// Try to allocate the memory on the NUMA node ...
			let huge_pages_allocation =
				match huge_pages::Allocation::new(numa_node, memory_mib)
				{
					Ok(allocation) => allocation,
					Err(huge_pages::Error::InsufficientMemory) => continue,
					Err(error) => return Err(error.into()),
				};

			// ... if successful, also allocate the CPU set
			let cpu_set_allocation = cpu::Allocation::new(cpu_set)?;

			return Ok(Self
				{
					cpu_set_allocation,
					_huge_pages_allocation: huge_pages_allocation,
				});
		}

		Err(Error::Allocation)
	}
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
}
//All enclaves should be allocated in same numa node if user wants to allocate specific cpus then system should check if they are all in same numa node
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




#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use lazy_static::lazy_static;
	use crate::configuration;
    // Create a global mutex for test synchronization
    lazy_static! {
        static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
    }

    fn create_resource_pool_with_count(memory: usize, cpu_count: usize) -> ResourcePool {
        ResourcePool::CpuCount { 
            memory_mib: memory, 
            cpu_count 
        }
    }

    fn create_resource_pool_with_pool(memory: usize, cpu_pool: &str) -> ResourcePool {
        ResourcePool::CpuPool { 
            memory_mib: memory, 
            cpu_pool: cpu_pool.to_string() 
        }
    }

    #[test]
    fn test_find_n_allocate() {
        let _lock = TEST_MUTEX.lock().unwrap();
        println!("Testing find_n_allocate");
        let pools = vec![
            create_resource_pool_with_count(1024, 2),
            create_resource_pool_with_count(512, 2),
        ];
        println!("Created pools: {:?}", pools);

        match Allocation::allocate_by_cpu_count(pools, Some(0)) {
            Ok(_) => println!("find_n_allocate successful"),
            Err(e) => panic!("find_n_allocate failed with error: {:?}", e),
        }
        let _ = configuration::clear_everything_in_numa_node();
    }

    #[test]
    fn test_find_n_allocate_with_target_numa() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let pools = vec![create_resource_pool_with_count(512, 2)];
        let result = Allocation::allocate_by_cpu_count(pools, Some(0));
        assert!(result.is_ok());
        let _ = configuration::clear_everything_in_numa_node();
    }

    #[test]
    fn test_find_n_allocate_with_insufficient_memory() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let pools = vec![create_resource_pool_with_count(1024000, 2)];
        let result = Allocation::allocate_by_cpu_count(pools, Some(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_find_n_allocate_with_insufficient_cpu() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let pools = vec![create_resource_pool_with_count(1024, usize::MAX)];
        let result = Allocation::allocate_by_cpu_count(pools, Some(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_allocate_by_cpu_pools() {
        let _lock = TEST_MUTEX.lock().unwrap();
        println!("Testing allocate_by_cpu_pools");
        let pools = vec![
            create_resource_pool_with_pool(1024, "1,5"),
            create_resource_pool_with_pool(512, "2,6"),
        ];
        println!("Created pools: {:?}", pools);

        match Allocation::allocate_by_cpu_pools(pools) {
            Ok(numa) => println!("allocate_by_cpu_pools successful with NUMA node: {}", numa.unwrap()),
            Err(e) => panic!("allocate_by_cpu_pools failed with error: {:?}", e),
        }
        let _ = configuration::clear_everything_in_numa_node();
    }
}
