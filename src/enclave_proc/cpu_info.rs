// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::common::commands_parser::RunEnclavesArgs;
use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::new_nitro_cli_failure;

/// Path corresponding to the NE CPU pool.
const POOL_FILENAME: &str = "/sys/module/nitro_enclaves/parameters/ne_cpus";

/// The CPU configuration requested by the user.
#[derive(Clone, PartialEq)]
pub enum EnclaveCpuConfig {
    /// A list with the desired CPU IDs.
    List(Vec<u32>),
    /// The number of desired CPU IDs.
    Count(u32),
}

/// Aggregate CPU information for multiple CPUs.
#[derive(Debug)]
pub struct CpuInfo {
    /// The list with the CPUs available for enclaves.
    cpu_ids: Vec<u32>,
}

impl Default for EnclaveCpuConfig {
    fn default() -> Self {
        EnclaveCpuConfig::Count(0)
    }
}

impl CpuInfo {
    /// Create a new `CpuInfo` instance from the current system configuration.
    pub fn new() -> NitroCliResult<Self> {
        Ok(CpuInfo {
            cpu_ids: CpuInfo::get_cpu_info()?,
        })
    }

    /// Get the CPU configuration from the command-line arguments.
    pub fn get_cpu_config(&self, args: &RunEnclavesArgs) -> NitroCliResult<EnclaveCpuConfig> {
        if let Some(cpu_ids) = args.cpu_ids.clone() {
            self.check_cpu_ids(&cpu_ids).map_err(|e| {
                e.add_subaction("Failed to check whether CPU list is valid".to_string())
            })?;
            Ok(EnclaveCpuConfig::List(cpu_ids))
        } else if let Some(cpu_count) = args.cpu_count {
            if self.cpu_ids.len() < cpu_count as usize {
                return Err(new_nitro_cli_failure!(
                    &format!(
                        "Insufficient CPUs available (requested {}, but maximum is {})",
                        cpu_count,
                        self.cpu_ids.len()
                    ),
                    NitroCliErrorEnum::InsufficientCpus
                )
                .add_info(vec!["cpu-count", &cpu_count.to_string()]));
            }
            Ok(EnclaveCpuConfig::Count(cpu_count))
        } else {
            // Should not happen.
            Err(new_nitro_cli_failure!(
                "Invalid CPU configuration argument",
                NitroCliErrorEnum::InvalidArgument
            ))
        }
    }

    /// Verify that a provided list of CPU IDs is valid.
    pub fn check_cpu_ids(&self, cpu_ids: &[u32]) -> NitroCliResult<()> {
        // Ensure there are no duplicate IDs.
        let mut unique_ids = BTreeSet::new();

        for cpu_id in cpu_ids {
            unique_ids.insert(cpu_id);
        }

        if unique_ids.len() < cpu_ids.len() {
            let duplicate_cpus = CpuInfo::get_duplicate_cpus(&unique_ids, cpu_ids);

            return Err(new_nitro_cli_failure!(
                &format!(
                    "CPU IDs list contains {} duplicate(s)",
                    cpu_ids.len() - unique_ids.len()
                ),
                NitroCliErrorEnum::InvalidCpuConfiguration
            )
            .add_info(vec!["cpu-ids", duplicate_cpus.as_str()]));
        }

        // Ensure the requested CPUs are available in the CPU pool.
        for cpu_id in unique_ids {
            if !self.cpu_ids.contains(cpu_id) {
                return Err(new_nitro_cli_failure!(
                    &format!(
                        "The CPU with ID {} is not available in the NE CPU pool",
                        cpu_id
                    ),
                    NitroCliErrorEnum::NoSuchCpuAvailableInPool
                )
                .add_info(vec!["cpu-ids", &cpu_id.to_string()]));
            }
        }

        // At this point, all requested CPU IDs are part of the enclave CPU pool.
        Ok(())
    }

    /// Get a list of all available CPU IDs.
    pub fn get_cpu_candidates(&self) -> Vec<u32> {
        self.cpu_ids.clone()
    }

    /// Parse a `lscpu` line to obtain a numeric value.
    pub fn get_value(line: &str) -> NitroCliResult<u32> {
        let mut line_str = line.to_string();
        line_str.retain(|c| !c.is_whitespace());
        line_str.parse::<u32>().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to parse CPU ID: {}", e),
                NitroCliErrorEnum::MalformedCpuId
            )
        })
    }

    fn parse_cpu_pool_line(line_str: &str) -> NitroCliResult<Vec<u32>> {
        let mut result: Vec<u32> = Vec::new();

        // The CPU pool format is: "id1-id2,id3-id4,..."
        for interval in line_str.split(',') {
            let bounds: Vec<&str> = interval.split('-').collect();
            match bounds.len() {
                1 => result.push(CpuInfo::get_value(bounds[0])?),
                2 => {
                    let start_id = CpuInfo::get_value(bounds[0])?;
                    let end_id = CpuInfo::get_value(bounds[1])?;

                    for cpu_id in start_id..=end_id {
                        result.push(cpu_id);
                    }
                }
                _ => {
                    return Err(new_nitro_cli_failure!(
                        &format!("Invalid CPU ID interval ({})", interval),
                        NitroCliErrorEnum::CpuError
                    ))
                }
            }
        }

        Ok(result)
    }

    /// Parse the CPU pool and build the list of off-line CPUs.
    fn get_cpu_info() -> NitroCliResult<Vec<u32>> {
        let pool_file = File::open(POOL_FILENAME).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to open CPU pool file: {}", e),
                NitroCliErrorEnum::FileOperationFailure
            )
            .add_info(vec![POOL_FILENAME, "Open"])
        })?;
        let file_reader = BufReader::new(pool_file);
        let mut result: Vec<u32> = Vec::new();

        for line in file_reader.lines() {
            let line_str = line.map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to read line from CPU pool file: {}", e),
                    NitroCliErrorEnum::FileOperationFailure
                )
                .add_info(vec![POOL_FILENAME, "Read"])
            })?;
            if line_str.trim().is_empty() {
                continue;
            }

            result.append(&mut CpuInfo::parse_cpu_pool_line(&line_str)?);
        }

        Ok(result)
    }

    /// Get a list of duplicate CPUs.
    fn get_duplicate_cpus(uniques: &BTreeSet<&u32>, cpu_ids: &[u32]) -> String {
        let mut result = String::new();
        for unique_cpu_id in uniques {
            if cpu_ids.iter().filter(|x| x == unique_cpu_id).count() > 1 {
                result.push_str(&(unique_cpu_id.to_string()));
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::construct_error_message;

    #[test]
    fn test_parse_cpu_pool_line() {
        let result0 = CpuInfo::parse_cpu_pool_line("1-3,4-6,7-9");
        assert!(result0.is_ok());
        assert_eq!(result0.unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let result1 = CpuInfo::parse_cpu_pool_line("1-4,7");
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), vec![1, 2, 3, 4, 7]);

        let result2 = CpuInfo::parse_cpu_pool_line("3,5,7,9");
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), vec![3, 5, 7, 9]);

        let result3 = CpuInfo::parse_cpu_pool_line("3+5,7-10");
        assert!(result3.is_err());

        let result4 = CpuInfo::parse_cpu_pool_line("3-a,7-b");
        assert!(result4.is_err());
    }

    #[test]
    fn test_get_value_correct_format() {
        let result0 = CpuInfo::get_value("\t3");
        assert!(result0.is_ok());
        assert_eq!(result0.unwrap(), 3);

        let result1 = CpuInfo::get_value("   \t  4");
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), 4);

        let result2 = CpuInfo::get_value("  \n 12");
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), 12);
    }

    #[test]
    fn test_get_value_incorrect_format() {
        let result0 = CpuInfo::get_value("\t-2");
        assert!(result0.is_err());
        if let Err(err_info) = result0 {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Malformed CPU ID error"));
        }

        let result1 = CpuInfo::get_value("\n\n0x06");
        assert!(result1.is_err());
        if let Err(err_info) = result1 {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Malformed CPU ID error"));
        }

        let result2 = CpuInfo::get_value("     processor");
        assert!(result2.is_err());
        if let Err(err_info) = result2 {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Malformed CPU ID error"));
        }
    }

    #[test]
    fn test_get_cpu_config_invalid_input() {
        let cpu_info = CpuInfo::new().unwrap();
        let mut run_args = RunEnclavesArgs {
            eif_path: String::new(),
            enclave_cid: None,
            memory_mib: 0,
            debug_mode: None,
            cpu_ids: None,
            cpu_count: Some(343),
            enclave_name: Some("testName".to_string()),
        };

        let mut result = cpu_info.get_cpu_config(&run_args);
        assert!(result.is_err());

        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Insufficient CPUs available"));
        }

        run_args.cpu_count = None;
        run_args.cpu_ids = Some(vec![1, 2, 3, 4, 5, 6, 7]);
        result = cpu_info.get_cpu_config(&run_args);
        assert!(result.is_err());

        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("No such CPU available in the pool"));
        }
    }

    #[test]
    fn test_get_cpu_config_valid_input() {
        let cpu_info = CpuInfo::new().unwrap();
        let mut run_args = RunEnclavesArgs {
            eif_path: String::new(),
            enclave_cid: None,
            memory_mib: 0,
            debug_mode: None,
            cpu_ids: None,
            cpu_count: Some(2),
            enclave_name: Some("testName".to_string()),
        };

        let mut result = cpu_info.get_cpu_config(&run_args);
        assert!(result.is_ok());
        assert!(result.unwrap() == EnclaveCpuConfig::Count(2));

        run_args.cpu_count = None;
        run_args.cpu_ids = Some(vec![1, 3]);

        result = cpu_info.get_cpu_config(&run_args);
        assert!(result.is_ok());
        assert!(result.unwrap() == EnclaveCpuConfig::List(vec![1, 3]));
    }

    #[test]
    fn test_get_cpu_candidates() {
        let cpu_info = CpuInfo::new().unwrap();
        let candidate_cpus = cpu_info.get_cpu_candidates();

        assert!(!candidate_cpus.is_empty());
    }

    #[test]
    fn test_check_cpu_ids() {
        let cpu_info = CpuInfo::new().unwrap();
        let mut cpu_ids: Vec<u32> = vec![1];

        let mut result = cpu_info.check_cpu_ids(&cpu_ids);
        assert!(result.is_ok());

        cpu_ids = vec![1, 1];
        result = cpu_info.check_cpu_ids(&cpu_ids);
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Invalid CPU configuration"));
        }

        cpu_ids = vec![1, 3];
        result = cpu_info.check_cpu_ids(&cpu_ids);
        assert!(result.is_ok());

        cpu_ids = vec![1, 3, 5];
        result = cpu_info.check_cpu_ids(&cpu_ids);
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("No such CPU available in the pool"));
        }
    }
}
