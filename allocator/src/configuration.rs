use crate::error::Error;
use crate::resources;
use anyhow::Result;
use serde::{Deserialize, Deserializer};

/// Path to the file containing currently allocated (offlined) CPUs
#[cfg(not(test))]
const OFFLINED_CPUS: &str = "/sys/module/nitro_enclaves/parameters/ne_cpus";
const SUPPORTED_ENCLAVES_NUM: usize = 4;
///Mock file for unit tests
#[cfg(test)]
const OFFLINED_CPUS: &str = "ne_cpus";

/// Resource pool configuration types for Nitro Enclaves
///
/// Supports two allocation strategies:
/// 1. CpuCount: Allocator chooses optimal CPU IDs based on count
/// 2. CpuPool: User specifies exact CPU IDs to allocate
#[derive(Debug, PartialEq, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum ResourcePool {
    CpuCount {
        memory_mib: usize,
        cpu_count: usize,
    },
    CpuPool {
        #[serde(deserialize_with = "deserialize_cpu_pool")]
        cpu_pool: String,
        memory_mib: usize,
    },
}
///Serde was failing when just a single number provided for cpu_pool in config file
/// It expects a string but it doesn't deserialize if just a single number provided.
/// e.g: cpu_pool: 2 -> was failing because it expects something like this 2,3,4
/// this function helps serde to deserialize and cover the problematic case.
fn deserialize_cpu_pool<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum {
        String(String),
        Num(usize),
    }

    Ok(match StringOrNum::deserialize(deserializer)? {
        StringOrNum::String(s) => s,
        StringOrNum::Num(n) => n.to_string(),
    })
}

/// Configuration format supporting both single and multiple enclave allocations
///
/// Provides backward compatibility with existing single-enclave configurations
/// while supporting new multiple-enclave allocations.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum ResourcePoolConfig {
    #[serde(rename = "value")]
    Single(ResourcePool),
    #[serde(rename = "value")]
    Multiple(Vec<ResourcePool>),
}
/// Reads and parses the allocator configuration file
///
/// Loads resource requirements from '/etc/nitro_enclaves/allocator.yaml'
/// and returns a vector of resource pools for allocation.
pub fn get_resource_pool_from_config() -> Result<Vec<ResourcePool>> {
    let f = std::fs::File::open(format!(
        "{}/etc/nitro_enclaves/allocator.yaml",
        std::env::var("NITRO_CLI_INSTALL_DIR").unwrap_or("".to_string())
    ))?;
    let config: ResourcePoolConfig =
        serde_yaml::from_reader(f).map_err(|_| Error::ConfigFileCorruption)?;

    Ok(configure_resource_pool(config))
}
/// Processes the configuration into a consistent format
///
/// Handles both single and multiple resource pool configurations.
/// Warns if more than 4 resource pools are specified (maximum supported).
fn configure_resource_pool(config: ResourcePoolConfig) -> Vec<ResourcePool> {
    let pool = match config {
        ResourcePoolConfig::Single(pool) => vec![pool],
        ResourcePoolConfig::Multiple(pools) => pools,
    };

    if pool.len() > SUPPORTED_ENCLAVES_NUM {
        eprintln!("{}", Error::MoreResourcePoolThanSupported);
    }
    pool
}
/// Retrieves currently allocated CPU IDs
///
/// Reads the OFFLINED_CPUS file to determine which CPUs are currently
/// allocated to enclaves. This information is used to:
/// 1. Determine the NUMA node of existing allocations
/// 2. Support cleanup operations
pub fn get_current_allocated_cpu_pool() -> Result<Option<std::collections::BTreeSet<usize>>> {
    let f = std::fs::read_to_string(OFFLINED_CPUS)?;
    if f.trim().is_empty() {
        return Ok(None);
    }
    let cpu_list = resources::cpu::parse_cpu_list(&f[..])?;
    Ok(Some(cpu_list))
}
/// Clears all allocated resources on the current NUMA node
///
/// Process:
/// 1. Identifies currently allocated CPUs
/// 2. Determines their NUMA node
/// 3. Releases all hugepages on that NUMA node
/// 4. Deallocates all CPUs
///
/// This ensures a clean slate before new allocations and prevents
/// resource fragmentation.
pub fn clear_everything_in_numa_node() -> Result<()> {
    match get_current_allocated_cpu_pool()? {
        Some(cpu_list) => {
            //find numa by one of cpuids
            let numa = resources::cpu::get_numa_node_for_cpu(
                cpu_list.clone().into_iter().next().unwrap(),
            )?;
            //release everything
            let _ = resources::huge_pages::release_all_huge_pages(numa)?;
            let _ = resources::cpu::deallocate_cpu_set(&cpu_list);
        }
        None => {}
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn mock_resource_pool_config(yaml_str: &str) -> ResourcePoolConfig {
        let pool: ResourcePoolConfig = serde_yaml::from_str(yaml_str).unwrap();
        pool
    }
    #[test]
    fn test_configure_resource_pool() {
        let single_pool = mock_resource_pool_config(
            r#"
            memory_mib: 1024
            cpu_count: 2
        "#,
        );
        let multiple_pools = mock_resource_pool_config(
            r#"
            - memory_mib: 1024
              cpu_count: 2
            - cpu_pool: "2,5"
              memory_mib: 2048
        "#,
        );
        let single_pool = configure_resource_pool(single_pool);
        let multiple_pools = configure_resource_pool(multiple_pools);
        assert_eq!(
            single_pool,
            vec![ResourcePool::CpuCount {
                memory_mib: 1024,
                cpu_count: 2,
            }]
        );
        assert_eq!(
            single_pool[0],
            ResourcePool::CpuCount {
                memory_mib: 1024,
                cpu_count: 2,
            }
        );
        assert_ne!(
            single_pool[0],
            ResourcePool::CpuPool {
                memory_mib: 1024,
                cpu_pool: "2,5".to_string(),
            }
        );
        assert_eq!(
            multiple_pools,
            vec![
                ResourcePool::CpuCount {
                    memory_mib: 1024,
                    cpu_count: 2,
                },
                ResourcePool::CpuPool {
                    cpu_pool: "2,5".to_string(),
                    memory_mib: 2048,
                },
            ]
        );
    }
    #[test]
    fn test_get_current_allocated_cpu_pool_cases() {
        // Test case struct to organize our test cases
        struct TestCase {
            input: &'static str,
            expected: Option<BTreeSet<usize>>,
        }

        let test_cases = vec![
            TestCase {
                input: "2,5",
                expected: Some(BTreeSet::from([2, 5])),
            },
            TestCase {
                input: "0-3",
                expected: Some(BTreeSet::from([0, 1, 2, 3])),
            },
            TestCase {
                input: "",
                expected: None,
            },
            TestCase {
                input: "1,3-5,7",
                expected: Some(BTreeSet::from([1, 3, 4, 5, 7])),
            },
            // Add more test cases as needed
        ];

        // Run all test cases in sequence
        for case in test_cases {
            let mut temp_file = NamedTempFile::new().unwrap();
            write!(temp_file, "{}", case.input).unwrap();

            let _ = std::fs::remove_file(OFFLINED_CPUS);

            std::os::unix::fs::symlink(temp_file.path(), OFFLINED_CPUS).unwrap();

            let result = get_current_allocated_cpu_pool().unwrap();
            assert_eq!(result, case.expected);

            std::fs::remove_file(OFFLINED_CPUS).unwrap();
        }
    }
}
