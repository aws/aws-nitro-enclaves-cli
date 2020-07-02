// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use std::collections::BTreeSet;
use std::process::Command;

use crate::common::commands_parser::RunEnclavesArgs;
use crate::common::NitroCliResult;

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
    pub fn new() -> Result<Self, String> {
        Ok(CpuInfo {
            cpu_ids: CpuInfo::get_cpu_info()?,
        })
    }

    /// Get the CPU configuration from the command-line arguments.
    pub fn get_cpu_config(&self, args: &RunEnclavesArgs) -> NitroCliResult<EnclaveCpuConfig> {
        if let Some(cpu_ids) = args.cpu_ids.clone() {
            self.check_cpu_ids(&cpu_ids)?;
            Ok(EnclaveCpuConfig::List(cpu_ids))
        } else if let Some(cpu_count) = args.cpu_count {
            if self.cpu_ids.len() < cpu_count as usize {
                return Err(format!(
                    "Insufficient CPUs available (requested {}, but maximum is {}).",
                    cpu_count,
                    self.cpu_ids.len()
                ));
            }
            Ok(EnclaveCpuConfig::Count(cpu_count))
        } else {
            // Should not happen.
            Err("Invalid CPU configuration argument.".to_string())
        }
    }

    /// Verify that a provided list of CPU IDs is valid.
    pub fn check_cpu_ids(&self, cpu_ids: &[u32]) -> Result<(), String> {
        // Ensure there are no duplicate IDs.
        let mut unique_ids = BTreeSet::new();

        for cpu_id in cpu_ids {
            unique_ids.insert(cpu_id);
        }

        if unique_ids.len() < cpu_ids.len() {
            return Err(format!(
                "The CPU ID list contains {} duplicate(s).",
                cpu_ids.len() - unique_ids.len()
            ));
        }

        // Ensure the requested CPUs are available in the CPU pool.
        for cpu_id in unique_ids {
            if !self.cpu_ids.contains(cpu_id) {
                return Err(format!("The CPU with ID {} is not available.", cpu_id));
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
    pub fn get_value(line: &str) -> Result<u32, String> {
        let mut line_str = line.to_string();
        line_str.retain(|c| !c.is_whitespace());
        line_str
            .parse::<u32>()
            .map_err(|e| format!("Failed to parse CPU ID: {}", e))
    }

    /// Parse `lscpu -p=cpu -c` and build the list of off-line CPUs.
    fn get_cpu_info() -> NitroCliResult<Vec<u32>> {
        let mut result: Vec<u32> = Vec::new();
        let output = Command::new("lscpu")
            .arg("-p=cpu")
            .arg("-c")
            .output()
            .map_err(|e| format!("Failed to execute \"lscpu -p=cpu -c\": {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.starts_with('#') {
                continue;
            }

            let cpu_id = CpuInfo::get_value(line)?;
            result.push(cpu_id);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        if let Err(err_str) = result0 {
            assert!(err_str.starts_with("Failed to parse CPU ID"));
        }

        let result1 = CpuInfo::get_value("\n\n0x06");
        assert!(result1.is_err());
        if let Err(err_str) = result1 {
            assert!(err_str.starts_with("Failed to parse CPU ID"));
        }

        let result2 = CpuInfo::get_value("     processor");
        assert!(result2.is_err());
        if let Err(err_str) = result2 {
            assert!(err_str.starts_with("Failed to parse CPU ID"));
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
        };

        let mut result = cpu_info.get_cpu_config(&run_args);
        assert!(result.is_err());

        if let Err(err_str) = result {
            assert!(err_str.starts_with("Insufficient CPUs available"));
        }

        run_args.cpu_count = None;
        run_args.cpu_ids = Some(vec![1, 2, 3, 4, 5, 6, 7]);
        result = cpu_info.get_cpu_config(&run_args);
        assert!(result.is_err());

        if let Err(err_str) = result {
            assert!(err_str.starts_with("The CPU with ID"));
            assert!(err_str.ends_with("is not available."));
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

        assert!(candidate_cpus.len() > 0);
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
        if let Err(err_str) = result {
            assert!(err_str.eq("The CPU ID list contains 1 duplicate(s)."));
        }

        cpu_ids = vec![1, 3];
        result = cpu_info.check_cpu_ids(&cpu_ids);
        assert!(result.is_ok());

        cpu_ids = vec![1, 3, 5];
        result = cpu_info.check_cpu_ids(&cpu_ids);
        assert!(result.is_err());
        if let Err(err_str) = result {
            assert!(err_str.eq("The CPU with ID 5 is not available."));
        }
    }
}
