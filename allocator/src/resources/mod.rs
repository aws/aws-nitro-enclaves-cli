//! Sysfs-based enclave resource allocation

mod cpu;
mod huge_pages;

#[derive(thiserror::Error, Debug)]
pub enum Error
{
	#[error("Failed to allocate CPUs: {0}")]
	Cpu(#[from] cpu::Error),
	#[error("Failed to allocate huge pages: {0}")]
	HugePage(#[from] huge_pages::Error),
	#[error("Failed to find suitable combination of CPUs and memory")]
	Allocation,
}

pub struct Allocation
{
	// Both allocations implement Drop
	_cpu_set_allocation: cpu::Allocation,
	_huge_pages_allocation: huge_pages::Allocation,
}

impl Allocation
{
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
					_cpu_set_allocation: cpu_set_allocation,
					_huge_pages_allocation: huge_pages_allocation,
				});
		}

		Err(Error::Allocation)
	}
}
