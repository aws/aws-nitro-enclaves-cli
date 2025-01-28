pub type CpuSet = std::collections::BTreeSet::<usize>;
type CpuSets = std::collections::HashMap::<usize, CpuSet>;

#[derive(thiserror::Error, Debug)]
pub enum Error
{
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error(transparent)]
	ParseInt(#[from] std::num::ParseIntError),
	#[error("missing CPU pool file, make sure the Nitro Enclaves driver is present")]
	MissingCpuPoolFile,
	#[error("unexpected sysfs file structure")]
	UnexptectedFileStructure,
	#[error("failed to configure requested cpu pool, this indicates insufficient system resources")]
	InsufficientCpuPool,	
}

const CPU_POOL_FILE: &str = "/sys/module/nitro_enclaves/parameters/ne_cpus";

pub struct Allocation
{
	#[allow(dead_code)]
	cpu_set: CpuSet,
}

impl Allocation
{
	pub fn new(cpu_set: CpuSet) -> Result<Self, Error>
	{
		allocate_cpu_set(&cpu_set)?;

		Ok(Self
		{
			cpu_set,
		})
	}
}

/*impl Drop for Allocation
{
	fn drop(&mut self)
	{
		if let Err(error) = deallocate_cpu_set(&self.cpu_set)
		{
			log::error!("Failed to release CPUs: {error}");
		}
	}
}*/

pub fn find_suitable_cpu_sets(cpu_count: usize) -> Result<CpuSets, Error>
{
	let cpu_0_numa_node = get_numa_node_for_cpu(0)?;
	let cpu_0_siblings = get_cpu_siblings(0)?;

	(0 .. get_numa_node_count()?).try_fold(
		CpuSets::new(),
		|mut cpu_sets, numa_node|
		{
			let mut cpus_in_numa_node = get_cpus_in_numa_node(numa_node)?;

			if numa_node == cpu_0_numa_node
			{
				cpus_in_numa_node.retain(|cpu| !cpu_0_siblings.contains(cpu));
			}

			if cpus_in_numa_node.len() < cpu_count
			{
				return Ok(cpu_sets);
			}

			let cores = cpus_in_numa_node.into_iter().try_fold(
				CpuSets::new(),	|mut cores: CpuSets, cpu|
				{
					let core_id = get_core_id(cpu)?;

					cores.entry(core_id).or_default().insert(cpu);

					Ok::<_, Error>(cores)
				})?;

			let mut selected_cpus = CpuSet::new();

			for cpus_in_core in cores.values()
			{
				let siblings = get_cpu_siblings(
					// Safety: We know we have at least one entry in the set
					*cpus_in_core.first().unwrap())?;

				if *cpus_in_core == siblings
				{
					selected_cpus.extend(cpus_in_core);

					if selected_cpus.len() >= cpu_count
					{
						cpu_sets.insert(numa_node, selected_cpus);

						break;
					}
				}
			}

			Ok(cpu_sets)
		})
}

fn allocate_cpu_set(update: &CpuSet) -> Result<(), Error>
{
	let mut cpu_set = get_cpu_pool()?;
	cpu_set.extend(update);

	set_cpu_pool(&cpu_set)
}

pub fn deallocate_cpu_set(update: &CpuSet) -> Result<(), Error>
{
	let mut cpu_set = get_cpu_pool()?;
	cpu_set.retain(|cpu| !update.contains(cpu));

	set_cpu_pool(&cpu_set)
}

fn get_core_id(cpu: usize) -> Result<usize, Error>
{
	let core_id_path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/core_id");
	let content = std::fs::read_to_string(core_id_path)?;

	Ok(content.trim().parse()?)
}

fn get_numa_node_count() -> Result<usize, Error>
{
	let node_path = "/sys/devices/system/node";

	Ok(get_numa_nodes(node_path)?.len())
}

pub fn get_numa_node_for_cpu(cpu: usize) -> Result<usize, Error>
{
	let cpu_path = format!("/sys/devices/system/cpu/cpu{cpu}");

	get_numa_nodes(&cpu_path)?.into_iter().next().ok_or(Error::UnexptectedFileStructure)
}

fn get_numa_nodes(path: &str) -> Result<CpuSet, Error>
{
	std::fs::read_dir(path)?
		.try_fold(CpuSet::new(), |mut set, entry|
		{
			let entry = entry?;
			let file_name = entry.file_name();
			let file_name = file_name.to_str().ok_or(Error::UnexptectedFileStructure)?;

			if let Some(file_name) = file_name.strip_prefix("node")
			{
				set.insert(file_name.parse()?);
			}

			Ok(set)
		})
}

fn get_cpus_in_numa_node(node: usize) -> Result<CpuSet, Error>
{
	let cpu_list_path = format!("/sys/devices/system/node/node{node}/cpulist");

	get_cpu_list(&cpu_list_path)
}

fn get_cpu_siblings(cpu: usize) -> Result<CpuSet, Error>
{
	let thread_siblings_list_path =
		format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");

	get_cpu_list(&thread_siblings_list_path)
}

fn get_cpu_list(list: &str) -> Result<CpuSet, Error>
{
	let list = std::fs::read_to_string(list)?;

	parse_cpu_list(&list)
}

fn get_cpu_pool() -> Result<CpuSet, Error>
{
	if !std::path::Path::new(CPU_POOL_FILE).exists()
	{
		return Err(Error::MissingCpuPoolFile);
	}

	get_cpu_list(CPU_POOL_FILE)
}

fn set_cpu_pool(cpu_set: &CpuSet) -> Result<(), Error>
{
	if !std::path::Path::new(CPU_POOL_FILE).exists()
	{
		return Err(Error::MissingCpuPoolFile);
	}

	let cpu_list = format_cpu_list(cpu_set);

	Ok(match std::fs::write(CPU_POOL_FILE, cpu_list)
	{
		// We expect and invalid input error when writing an empty CPU list, but the driver
		// will still tear down the CPU pool.
		// See: https://github.com/aws/aws-nitro-enclaves-cli/issues/397
		Err(error) if error.kind() == std::io::ErrorKind::InvalidInput && cpu_set.is_empty()
			=> Ok(()),
		other => other,
	}?)
}

pub fn parse_cpu_list(cpu_list: &str) -> Result<CpuSet, Error>
{
	cpu_list.trim().split_terminator(',')
		.try_fold(CpuSet::new(), |mut set, entry|
		{
			if let Some((start, end)) = entry.split_once('-')
			{
				let start: usize = start.parse()?;
				let end: usize = end.parse()?;

				set.extend(start..=end);
			}
			else
			{
				set.insert(entry.parse()?);
			}

			Ok(set)
		})
}

pub fn format_cpu_list(cpu_set: &CpuSet) -> String
{
	let mut cpu_set = cpu_set.iter();

	let Some(first) = cpu_set.next()
		else
		{
			return "\n".to_string();
		};

	let mut cpu_list = Vec::new();
	let last_range = cpu_set.fold(
		*first..=*first,
		|range, &cpu|
		{
			if cpu == *range.end() + 1
			{
				*range.start()..=cpu
			}
			else
			{
				cpu_list.push(format_range(range));

				cpu..=cpu
			}
		});

	cpu_list.push(format_range(last_range));

	cpu_list.join(",") + "\n"
}

fn format_range(range: std::ops::RangeInclusive<usize>) -> String
{
	if range.start() == range.end()
	{
		range.start().to_string()
	}
	else
	{
		format!("{}-{}", range.start(), range.end())
	}
}