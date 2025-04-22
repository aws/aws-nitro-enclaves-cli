type Pages = std::collections::HashMap<usize, usize>;
type PageSizes = std::collections::BTreeSet<usize>;

/// Path to the sysfs directory containing NUMA node information
#[cfg(not(test))]
const BASE_SYSFS_PATH: &str = "/sys/devices/system/node";

///Mock Path for unit tests
#[cfg(test)]
const BASE_SYSFS_PATH: &str = "/tmp/nitro-cli-allocator/";
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
/// Represents allocated hugepages and their corresponding NUMA node
pub struct Allocation
{
	numa_node: usize,
	allocated_pages: Pages,
}

impl Allocation
{
	/// Allocates memory on a specific NUMA node
    /// This function is typically called after CPU allocation to ensure memory
    /// and CPU allocations are on the same NUMA node for optimal performance.
	pub fn new(numa_node: usize, memory_mib: usize) -> Result<Self, Error>
	{
		let allocated_pages = configure_huge_pages(numa_node, memory_mib)?;

		Ok(Self
		{
			numa_node,
			allocated_pages,
		})
	}
	/// Releases allocated hugepages on the specific NUMA node
	pub fn release_resources(&self){
		if let Err(error) = release_huge_pages(self.numa_node, &self.allocated_pages)
		{
			log::error!("Failed to release huge pages: {error}");
		}
	}
}

/// Configures hugepages on a specific NUMA node
/// 
/// This function attempts to allocate memory using available hugepage sizes,
/// starting with the largest. It uses the Linux sysfs mechanism for allocation.
/// 
/// Note: The actual allocation may differ from the requested amount due to
/// memory fragmentation or system limitations.
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
			format!("{BASE_SYSFS_PATH}/node{numa_node}/hugepages/hugepages-{page_size}kB/nr_hugepages");

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
/// Releases previously allocated hugepages on a specific NUMA node
pub fn release_huge_pages(numa_node: usize, allocated_pages: &Pages)
	-> Result<(), Error>
{
	for (page_size, &allocated_count) in allocated_pages
	{
		let huge_pages_path =
			format!("{BASE_SYSFS_PATH}/node{numa_node}/hugepages/hugepages-{page_size}kB/nr_hugepages");
		
		let current_pages: usize = std::fs::read_to_string(&huge_pages_path)?.trim()
			.parse()?;
		let new_pages = current_pages.saturating_sub(allocated_count);
		
		std::fs::write(&huge_pages_path, new_pages.to_string())?;
	}

	Ok(())
}
/// Releases all hugepages on a specific NUMA node
/// This is typically used before allocation to ensure a clean slate.
pub fn release_all_huge_pages(numa_node: usize) -> Result<(), Error> {
	for page_size in get_huge_page_sizes(numa_node)?.into_iter().rev()
	{
		let huge_pages_path =
			format!("{BASE_SYSFS_PATH}/node{numa_node}/hugepages/hugepages-{page_size}kB/nr_hugepages");
		std::fs::write(&huge_pages_path, "0")?;
	}
	Ok(())
}
/// Retrieves available hugepage sizes for a given NUMA node
/// Hugepage sizes can vary between different architectures.
fn get_huge_page_sizes(numa_node: usize) -> Result<PageSizes, Error>
{
	let path = format!("{BASE_SYSFS_PATH}/node{numa_node}/hugepages");

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;
	use std::path::Path;
	use std::sync::atomic::{AtomicUsize, Ordering};
    
    static ACTIVE_TESTS: AtomicUsize = AtomicUsize::new(0);
    struct TestContext {
        _temp_dir: TempDir,
    }

    impl TestContext {
        fn new() -> Self {
			ACTIVE_TESTS.fetch_add(1, Ordering::SeqCst);
            Self { 
                _temp_dir: TempDir::new().unwrap()
            }
        }

        fn setup_node(&self, numa_node: usize) {
            fs::create_dir_all(
                format!("{}/node{}/hugepages", BASE_SYSFS_PATH, numa_node)
            ).unwrap();
        }

        fn create_hugepage(&self, numa_node: usize, size: usize, content: &str) {
			let dir_path = format!("{}/node{}/hugepages/hugepages-{}kB", 
				BASE_SYSFS_PATH, numa_node, size);
			let file_path = format!("{}/nr_hugepages", dir_path);
			
			println!("Creating directory at: {}", dir_path);
			fs::create_dir_all(&dir_path).unwrap();
			
			println!("Creating file at: {}", file_path);
			fs::write(&file_path, content).unwrap();
			
			// Verify immediately after writing
			assert!(Path::new(&file_path).exists(), 
				"File wasn't created or disappeared immediately: {}", file_path);
		}
		fn read_hugepages(&self, numa_node: usize, size: usize) -> usize {
            let path = PathBuf::from(format!("{}/node{}/hugepages/hugepages-{}kB/nr_hugepages", 
                BASE_SYSFS_PATH, numa_node, size));
            fs::read_to_string(path)
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        }
    }
	impl Drop for TestContext {
        fn drop(&mut self) {
            if ACTIVE_TESTS.fetch_sub(1, Ordering::SeqCst) == 1 {
                let _ = fs::remove_dir_all(BASE_SYSFS_PATH);
            }
        }
    }

    #[test]
    fn test_get_hugepage_sizes() {
        let ctx = TestContext::new();
		//Single NUMA node
		{
			//x86_64 
			{
				ctx.setup_node(0);
				ctx.create_hugepage(0, 2048,"0");
				ctx.create_hugepage(0, 1048576,"0");
				assert_eq!(get_huge_page_sizes(0).unwrap(),BTreeSet::from([1048576,2048]));
			}
			//ARM
			{
				ctx.setup_node(3);
				ctx.create_hugepage(3, 2048,"0");
				ctx.create_hugepage(3, 1048576,"0");
				ctx.create_hugepage(3, 32768,"0");
				ctx.create_hugepage(3, 64,"0");
				assert_eq!(get_huge_page_sizes(3).unwrap(),BTreeSet::from([1048576,2048,32768,64]));
			}
		}
    }
	#[test]
	fn test_release_all_huge_pages() {
        let ctx = TestContext::new();
		ctx.setup_node(2);
		ctx.create_hugepage(2, 2048, "10");
		ctx.create_hugepage(2, 1048576,"1");

		release_all_huge_pages(2).unwrap();

		assert_eq!(ctx.read_hugepages(2,2048),0);
		assert_eq!(ctx.read_hugepages(2,1048576),0);

    }
	#[test]
	fn test_configure_huge_pages_1500mb(){
		let ctx = TestContext::new();
		ctx.setup_node(1);
		ctx.create_hugepage(1, 2048, "0");
		ctx.create_hugepage(1, 1048576,"0");

		configure_huge_pages(1, 1500).unwrap();

		assert_eq!(ctx.read_hugepages(1,2048),238);
		assert_eq!(ctx.read_hugepages(1,1048576),1);
	}
	#[test]
	fn test_configure_huge_pages_2060() {
		let ctx = TestContext::new();
		ctx.setup_node(4);
		ctx.create_hugepage(4, 2048, "0");
		ctx.create_hugepage(4, 1048576,"0");

		configure_huge_pages(4, 2060).unwrap();

		assert_eq!(ctx.read_hugepages(4,2048),6);
		assert_eq!(ctx.read_hugepages(4,1048576),2);
	}
	#[test]
	fn test_configure_huge_pages_512_512() {
		let ctx = TestContext::new();
		ctx.setup_node(5);
		ctx.create_hugepage(5, 2048, "0");
		ctx.create_hugepage(5, 1048576,"0");

		configure_huge_pages(5, 512).unwrap();
		configure_huge_pages(5, 512).unwrap();

		assert_eq!(ctx.read_hugepages(5,2048),512);
		assert_eq!(ctx.read_hugepages(5,1048576),0);
	}
}