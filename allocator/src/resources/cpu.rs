pub type CpuSet = std::collections::BTreeSet<usize>;
type CpuSets = std::collections::HashMap<usize, CpuSet>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("missing CPU pool file, make sure the Nitro Enclaves driver is present")]
    MissingCpuPoolFile,
    #[error("unexpected sysfs file structure")]
    UnexptectedFileStructure,
    #[error(
        "failed to configure requested cpu pool, this indicates insufficient system resources"
    )]
    InsufficientCpuPool,
    #[error("Requested Cpu ID does not exist.")]
    NonExistentCpuID,
}
/// Represents the path to the offline CPU pool file. CPU allocation is performed by writing
/// CPU IDs to this file, with the Nitro Enclaves driver handling the rest of the process.
#[cfg(not(test))]
const CPU_POOL_FILE: &str = "/sys/module/nitro_enclaves/parameters/ne_cpus";
///This constant for mocking test cases.
#[cfg(test)]
const CPU_POOL_FILE: &str = "ne_cpus_for_cpu_test";

pub struct Allocation {
    #[allow(dead_code)]
    cpu_set: CpuSet,
}

impl Allocation {
    pub fn new(cpu_set: CpuSet) -> Result<Self, Error> {
        allocate_cpu_set(&cpu_set)?;

        Ok(Self { cpu_set })
    }
}
/// CPU allocation strategy:
/// 1. Finds suitable NUMA nodes while avoiding CPU 0 and its siblings (reserved for parent instance)
/// 2. Attempts to allocate CPU siblings together for optimal performance
/// 3. Falls back to other NUMA nodes if the current node has insufficient resources
pub fn find_suitable_cpu_sets(cpu_count: usize) -> Result<CpuSets, Error> {
    let cpu_0_numa_node = get_numa_node_for_cpu(0)?;
    let cpu_0_siblings = get_cpu_siblings(0)?;

    (0..get_numa_node_count()?).try_fold(CpuSets::new(), |mut cpu_sets, numa_node| {
        let mut cpus_in_numa_node = get_cpus_in_numa_node(numa_node)?;

        if numa_node == cpu_0_numa_node {
            cpus_in_numa_node.retain(|cpu| !cpu_0_siblings.contains(cpu));
        }

        if cpus_in_numa_node.len() < cpu_count {
            return Ok(cpu_sets);
        }

        let cores =
            cpus_in_numa_node
                .into_iter()
                .try_fold(CpuSets::new(), |mut cores: CpuSets, cpu| {
                    let core_id = get_core_id(cpu)?;

                    cores.entry(core_id).or_default().insert(cpu);

                    Ok::<_, Error>(cores)
                })?;

        let mut selected_cpus = CpuSet::new();

        for cpus_in_core in cores.values() {
            let siblings = get_cpu_siblings(
                // Safety: We know we have at least one entry in the set
                *cpus_in_core.first().unwrap(),
            )?;

            if *cpus_in_core == siblings {
                selected_cpus.extend(cpus_in_core);

                if selected_cpus.len() >= cpu_count {
                    cpu_sets.insert(numa_node, selected_cpus);

                    break;
                }
            }
        }

        Ok(cpu_sets)
    })
}
/// Allocates CPUs by adding them to the existing CPU pool
fn allocate_cpu_set(update: &CpuSet) -> Result<(), Error> {
    let mut cpu_set = get_cpu_pool()?;
    cpu_set.extend(update);

    set_cpu_pool(&cpu_set)
}
/// Deallocates CPUs by removing them from the CPU pool file, which brings them back online
pub fn deallocate_cpu_set(update: &CpuSet) -> Result<(), Error> {
    let mut cpu_set = get_cpu_pool()?;
    cpu_set.retain(|cpu| !update.contains(cpu));

    set_cpu_pool(&cpu_set)
}
/// Retrieves the core ID for a given CPU
fn get_core_id(cpu: usize) -> Result<usize, Error> {
    let core_id_path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/core_id");
    let content = std::fs::read_to_string(core_id_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NonExistentCpuID,
        _ => Error::Io(e),
    })?;

    Ok(content.trim().parse()?)
}
/// Returns the total number of NUMA nodes available in the system
fn get_numa_node_count() -> Result<usize, Error> {
    let node_path = "/sys/devices/system/node";

    Ok(get_numa_nodes(node_path)?.len())
}
/// Identifies which NUMA node a specific CPU belongs to
pub fn get_numa_node_for_cpu(cpu: usize) -> Result<usize, Error> {
    let cpu_path = format!("/sys/devices/system/cpu/cpu{cpu}");

    get_numa_nodes(&cpu_path)?
        .into_iter()
        .next()
        .ok_or(Error::UnexptectedFileStructure)
}
///Reads the sysfs directories and return the NUMA nodes.
fn get_numa_nodes(path: &str) -> Result<CpuSet, Error> {
    std::fs::read_dir(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NonExistentCpuID,
            _ => Error::Io(e),
        })?
        .try_fold(CpuSet::new(), |mut set, entry| {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_str().ok_or(Error::UnexptectedFileStructure)?;

            if let Some(file_name) = file_name.strip_prefix("node") {
                set.insert(file_name.parse()?);
            }

            Ok(set)
        })
}
/// Returns all CPUs belonging to a specific NUMA node
fn get_cpus_in_numa_node(node: usize) -> Result<CpuSet, Error> {
    let cpu_list_path = format!("/sys/devices/system/node/node{node}/cpulist");

    get_cpu_list(&cpu_list_path)
}
/// Retrieves sibling CPUs (threads) for a given CPU ID
fn get_cpu_siblings(cpu: usize) -> Result<CpuSet, Error> {
    let thread_siblings_list_path =
        format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");

    get_cpu_list(&thread_siblings_list_path)
}

fn get_cpu_list(list: &str) -> Result<CpuSet, Error> {
    let list = std::fs::read_to_string(list).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NonExistentCpuID,
        _ => Error::Io(e),
    })?;

    parse_cpu_list(&list)
}

fn get_cpu_pool() -> Result<CpuSet, Error> {
    if !std::path::Path::new(CPU_POOL_FILE).exists() {
        return Err(Error::MissingCpuPoolFile);
    }

    get_cpu_list(CPU_POOL_FILE)
}

fn set_cpu_pool(cpu_set: &CpuSet) -> Result<(), Error> {
    if !std::path::Path::new(CPU_POOL_FILE).exists() {
        return Err(Error::MissingCpuPoolFile);
    }

    let cpu_list = format_cpu_list(cpu_set);

    Ok(match std::fs::write(CPU_POOL_FILE, cpu_list) {
        // We expect and invalid input error when writing an empty CPU list, but the driver
        // will still tear down the CPU pool.
        // See: https://github.com/aws/aws-nitro-enclaves-cli/issues/397
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput && cpu_set.is_empty() => {
            Ok(())
        }
        other => other,
    }?)
}
/// Parses a CPU list string into a CpuSet (BTreeSet<usize>)
/// Format examples: "1,2,3" or "1-4" or "1,3-5,7"
pub fn parse_cpu_list(cpu_list: &str) -> Result<CpuSet, Error> {
    cpu_list
        .trim()
        .split_terminator(',')
        .try_fold(CpuSet::new(), |mut set, entry| {
            if let Some((start, end)) = entry.split_once('-') {
                let start: usize = start.parse()?;
                let end: usize = end.parse()?;

                set.extend(start..=end);
            } else {
                set.insert(entry.parse()?);
            }

            Ok(set)
        })
}
/// Formats a CpuSet into a string representation
/// Examples:
/// - [1,2,3,4] becomes "1-4"
/// - [1,2,3,5,7,8,9] becomes "1-3,5,7-9"
pub fn format_cpu_list(cpu_set: &CpuSet) -> String {
    let mut cpu_set = cpu_set.iter();

    let Some(first) = cpu_set.next() else {
        return "\n".to_string();
    };

    let mut cpu_list = Vec::new();
    let last_range = cpu_set.fold(*first..=*first, |range, &cpu| {
        if cpu == *range.end() + 1 {
            *range.start()..=cpu
        } else {
            cpu_list.push(format_range(range));

            cpu..=cpu
        }
    });

    cpu_list.push(format_range(last_range));

    cpu_list.join(",") + "\n"
}

fn format_range(range: std::ops::RangeInclusive<usize>) -> String {
    if range.start() == range.end() {
        range.start().to_string()
    } else {
        format!("{}-{}", range.start(), range.end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tempfile::NamedTempFile;
    #[test]
    fn test_format_cpu_list() {
        let single_cpu_set: BTreeSet<usize> = [1].into_iter().collect();
        assert_eq!(format_cpu_list(&single_cpu_set), "1\n");
        let consecutive_cpu_set: BTreeSet<usize> = [0, 1, 2, 3].into_iter().collect();
        assert_eq!(format_cpu_list(&consecutive_cpu_set), "0-3\n");
        let non_consecutive_cpu_set: BTreeSet<usize> = [0, 2, 4].into_iter().collect();
        assert_eq!(format_cpu_list(&non_consecutive_cpu_set), "0,2,4\n");
        let mixed_ranges_and_single_cpu_set: BTreeSet<usize> =
            [0, 1, 2, 4, 6, 7, 8].into_iter().collect();
        assert_eq!(
            format_cpu_list(&mixed_ranges_and_single_cpu_set),
            "0-2,4,6-8\n"
        );
    }
    #[test]
    fn test_parse_cpu_list() {
        let single_cpu = parse_cpu_list("1").unwrap();
        assert_eq!(single_cpu, BTreeSet::from([1]));

        let consecutive_cpus = parse_cpu_list("0-3").unwrap();
        assert_eq!(consecutive_cpus, BTreeSet::from([0, 1, 2, 3]));

        let non_consecutive_cpus = parse_cpu_list("0,2,4").unwrap();
        assert_eq!(non_consecutive_cpus, BTreeSet::from([0, 2, 4]));

        let mixed_ranges = parse_cpu_list("0-2,4,6-8").unwrap();
        assert_eq!(mixed_ranges, BTreeSet::from([0, 1, 2, 4, 6, 7, 8]));

        // Error cases
        assert!(parse_cpu_list("abc").is_err());
        assert!(parse_cpu_list("1-abc").is_err());
        assert!(parse_cpu_list(",1").is_err());
    }
    #[test]
    fn test_set_cpu_pool_cases() {
        struct TestCase {
            input: BTreeSet<usize>,
            should_succeed: bool,
            expected_content: Option<&'static str>,
        }

        let test_cases = vec![
            TestCase {
                input: BTreeSet::from([2, 5]),
                should_succeed: true,
                expected_content: Some("2,5\n"),
            },
            TestCase {
                input: BTreeSet::from([0, 1, 2, 3]),
                should_succeed: true,
                expected_content: Some("0-3\n"),
            },
            TestCase {
                input: BTreeSet::new(), // empty set
                should_succeed: true,   // should succeed with InvalidInput error
                expected_content: Some("\n"),
            },
            TestCase {
                input: BTreeSet::from([1, 3, 4, 5, 7]),
                should_succeed: true,
                expected_content: Some("1,3-5,7\n"),
            },
        ];

        for case in test_cases {
            let temp_file = NamedTempFile::new().unwrap(); //print temp file path debug
            std::os::unix::fs::symlink(temp_file.path(), CPU_POOL_FILE).unwrap();

            let result = set_cpu_pool(&case.input);

            if case.should_succeed {
                assert!(result.is_ok());

                if let Some(expected) = case.expected_content {
                    let written_content = std::fs::read_to_string(CPU_POOL_FILE).unwrap();
                    assert_eq!(written_content, expected);
                }
            } else {
                assert!(result.is_err());
            }

            std::fs::remove_file(CPU_POOL_FILE).unwrap();
        }
    }
}
