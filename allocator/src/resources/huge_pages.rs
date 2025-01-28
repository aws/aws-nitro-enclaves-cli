type Pages = std::collections::HashMap<usize, usize>;
type PageSizes = std::collections::BTreeSet<usize>;
#[derive(thiserror::Error, Debug)]
pub enum Error
{
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error(transparent)]
	ParseInt(#[from] std::num::ParseIntError),
	#[error("failed to configure requested memory, this indicates insufficient system resources. Rebooting the system might solve the issue")]
	InsufficientMemory,
	#[error("unexpected sysfs file structure")]
	UnexptectedFileStructure,
}

pub struct Allocation
{
	numa_node: usize,
	allocated_pages: Pages,
}

impl Allocation
{
	pub fn new(numa_node: usize, memory_mib: usize) -> Result<Self, Error>
	{
		let allocated_pages = configure_huge_pages(numa_node, memory_mib)?;

		Ok(Self
		{
			numa_node,
			allocated_pages,
		})
	}
	pub fn release_resources(&self){
		if let Err(error) = release_huge_pages(self.numa_node, &self.allocated_pages)
		{
			log::error!("Failed to release huge pages: {error}");
		}
	}
}

/*impl Drop for Allocation
{
	fn drop(&mut self)
	{
		if let Err(error) = release_huge_pages(self.numa_node, &self.allocated_pages)
		{
			log::error!("Failed to release huge pages: {error}");
		}
	}
}*/

fn configure_huge_pages(numa_node: usize, memory_mib: usize) -> Result<Pages, Error>
{
	let mut remaining_memory = memory_mib * 1024; // Convert to kB
	let mut allocated_pages = Pages::new();

	for page_size in get_huge_page_sizes(numa_node)?.into_iter().rev()
	{
		let needed_pages = remaining_memory / page_size;

		if needed_pages == 0
		{
			continue;
		}

		let huge_pages_path =
			format!("/sys/devices/system/node/node{numa_node}/hugepages/hugepages-{page_size}kB/nr_hugepages");

		let current_pages: usize = std::fs::read_to_string(&huge_pages_path)?.trim()
			.parse()?;
		let new_pages = current_pages + needed_pages;

		std::fs::write(&huge_pages_path, new_pages.to_string())?;

		let actual_pages: usize = std::fs::read_to_string(&huge_pages_path)?.trim()
			.parse()?;
		let actual_allocated_pages = actual_pages - current_pages;

		if actual_allocated_pages > 0
		{
			allocated_pages.insert(page_size, actual_allocated_pages);
			remaining_memory = remaining_memory.saturating_sub(page_size * actual_allocated_pages);
		}

		if remaining_memory == 0
		{
			break;
		}
	}

	if remaining_memory != 0
	{
		release_huge_pages(numa_node, &allocated_pages)?;

		return Err(Error::InsufficientMemory);
	}

	Ok(allocated_pages)
}

pub fn release_huge_pages(numa_node: usize, allocated_pages: &Pages)
	-> Result<(), Error>
{
	for (page_size, &allocated_count) in allocated_pages
	{
		let huge_pages_path =
			format!("/sys/devices/system/node/node{numa_node}/hugepages/hugepages-{page_size}kB/nr_hugepages");
		
		let current_pages: usize = std::fs::read_to_string(&huge_pages_path)?.trim()
			.parse()?;
		let new_pages = current_pages.saturating_sub(allocated_count);
		
		std::fs::write(&huge_pages_path, new_pages.to_string())?;
	}

	Ok(())
}
pub fn release_all_huge_pages(numa_node: usize) -> Result<(), Error> {
	for page_size in get_huge_page_sizes(numa_node)?.into_iter().rev()
	{
		let huge_pages_path =
			format!("/sys/devices/system/node/node{numa_node}/hugepages/hugepages-{page_size}kB/nr_hugepages");
		std::fs::write(&huge_pages_path, "0")?;
	}
	Ok(())
}
fn get_huge_page_sizes(numa_node: usize) -> Result<PageSizes, Error>
{
	let path = format!("/sys/devices/system/node/node{numa_node}/hugepages");

	std::fs::read_dir(path)?
		.map(|entry|
		{
			let file_name = entry?.file_name();
			let file_name = file_name.to_str().ok_or(Error::UnexptectedFileStructure)?;
			
			Ok(file_name.strip_prefix("hugepages-")
				.and_then(|file_name| file_name.strip_suffix("kB"))
				.ok_or(Error::UnexptectedFileStructure)?
				.parse()?)
		})
		.collect()
}