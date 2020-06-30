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
        let test_proc0 = String::from("processor:\t3");
        let result0 = CpuInfos::get_value(test_proc0);
        assert!(result0.is_ok());
        assert_eq!(result0.unwrap(), 3);

        let test_proc1 = String::from("processor\t  :   \t  4");
        let result1 = CpuInfos::get_value(test_proc1);
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), 4);

        let test_proc2 = String::from("\t\nprocessor\t:  \n 12");
        let result2 = CpuInfos::get_value(test_proc2);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), 12);
    }

    #[test]
    fn test_get_value_incorrect_format() {
        let test_proc0 = String::from("processor:\t-2");
        let result0 = CpuInfos::get_value(test_proc0);
        assert!(result0.is_err());
        if let Err(err_str) = result0 {
            assert!(err_str.eq("invalid digit found in string"));
        }

        let test_proc1 = String::from("processor:\n\n0x06");
        let result1 = CpuInfos::get_value(test_proc1);
        assert!(result1.is_err());
        if let Err(err_str) = result1 {
            assert!(err_str.eq("invalid digit found in string"));
        }

        let test_proc2 = String::from("processor:     processor");
        let result2 = CpuInfos::get_value(test_proc2);
        assert!(result2.is_err());
        if let Err(err_str) = result2 {
            assert!(err_str.eq("invalid digit found in string"));
        }
    }

    #[test]
    fn test_get_core_id_correct() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            for i in 0..cpu_infos.core_ids.len() {
                let cpu_id = i as u32;
                let index = cpu_infos.core_ids.iter().position(|r| r.cpu_id == cpu_id);
                assert_eq!(
                    cpu_infos.get_core_id(cpu_id).unwrap(),
                    cpu_infos.core_ids[index.unwrap()].core_id
                );
            }
        }
    }

    #[test]
    fn test_get_core_id_incorrect() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            let cpu_id0 = 200;
            let result0 = cpu_infos.get_core_id(cpu_id0);

            assert_eq!(result0, None);
        }
    }

    #[test]
    fn test_is_hyperthreading_on_on() {
        let mut cpu_info = Vec::<CpuInfo>::new();

        cpu_info.push(CpuInfo::new(2, 0));
        cpu_info.push(CpuInfo::new(0, 0));

        let result = CpuInfos::is_hyper_threading_on(&cpu_info);

        assert_eq!(result, true);
    }

    #[test]
    fn test_is_hyperthreading_on_off() {
        let mut cpu_info = Vec::<CpuInfo>::new();

        cpu_info.push(CpuInfo::new(3, 1));
        cpu_info.push(CpuInfo::new(0, 0));

        let result = CpuInfos::is_hyper_threading_on(&cpu_info);

        assert_eq!(result, false);
    }

    #[test]
    fn test_get_cpu_ids_invalid_input() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            if cpu_infos.hyper_threading {
                let cpu_count = 1;
                let result = cpu_infos.get_cpu_ids(cpu_count);

                assert!(result.is_err());

                if let Err(err_str) = result {
                    assert!(err_str.eq("cpu_count should be an even number."));
                }
            } else {
                let cpu_count = 43;
                let result = cpu_infos.get_cpu_ids(cpu_count);

                assert!(result.is_err());

                if let Err(err_str) = result {
                    assert!(err_str.starts_with("Could not find the requested number of cpus."));
                }
            }
        }
    }

    #[test]
    fn test_get_cpu_ids_valid_input() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            if cpu_infos.hyper_threading {
                let cpu_count = 2;
                let result = cpu_infos.get_cpu_ids(cpu_count);

                assert!(result.is_ok());
                assert_eq!(2, result.unwrap().len());
            } else {
                let cpu_count = 1;
                let result = cpu_infos.get_cpu_ids(cpu_count);

                assert!(result.is_ok());
                assert_eq!(1, result.unwrap().len());
            }
        }
    }

    #[test]
    fn test_contains_sibling_pairs() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            let cpu_ids = cpu_infos
                .core_ids
                .iter()
                .filter(|r| r.core_id == 0)
                .map(|r| r.cpu_id)
                .collect::<Vec<_>>();

            let result = cpu_infos.contains_sibling_pairs(&cpu_ids);
            if CpuInfos::is_hyper_threading_on(&cpu_infos.core_ids) {
                assert!(result);
            } else {
                assert!(!result);
            }
        }
    }

    #[test]
    fn test_get_cpu_candidates() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            let candidate_cpus = cpu_infos.get_cpu_candidates();

            assert!(candidate_cpus.len() > 0);
        }
    }

    #[test]
    fn test_check_cpu_ids_invalid() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            if cpu_infos.hyper_threading {
                let mut cpu_ids = Vec::<u32>::new();

                cpu_ids.push(1);

                let result = cpu_infos.check_cpu_ids(&cpu_ids);

                assert!(result.is_err());
                if let Err(err_str) = result {
                    assert!(err_str
                        .eq("Hyper-threading is enabled, so sibling pairs need to be provided"));
                }
            } else {
                let mut cpu_ids = Vec::<u32>::new();

                // Add all cpus having core_id set to 0
                for i in 0..cpu_infos.core_ids.len() {
                    // Safe to unwrap since `i` will not exceed the bounds
                    if cpu_infos.core_ids.get(i).unwrap().core_id == 0 {
                        cpu_ids.push(cpu_infos.core_ids.get(i).unwrap().cpu_id);
                    }
                }

                let result = cpu_infos.check_cpu_ids(&cpu_ids);

                assert!(result.is_err());
                if let Err(err_str) = result {
                    assert!(err_str.starts_with("Cpus with core id 0 can't be used."));
                }
            }
        }
    }

    #[test]
    fn test_check_cpu_ids_valid() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            if cpu_infos.hyper_threading {
                let mut cpu_ids = Vec::<u32>::new();

                // Add 2 cpus having core_id != 0
                for i in 0..cpu_infos.core_ids.len() {
                    // Safe to unwrap since `i` will not exceed the bounds
                    if cpu_infos.core_ids.get(i).unwrap().core_id != 0 {
                        cpu_ids.push(cpu_infos.core_ids.get(i).unwrap().cpu_id);

                        if cpu_ids.len() == 2 {
                            break;
                        }
                    }
                }

                let result = cpu_infos.check_cpu_ids(&cpu_ids);

                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn test_get_siblings() {
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            let mut core_ids = HashSet::<u32>::new();

            for i in 0..cpu_infos.core_ids.len() {
                // Safe to unwrap since `i` will not exceed the bounds
                core_ids.insert(cpu_infos.core_ids.get(i).unwrap().core_id);
            }

            let siblings = cpu_infos.get_siblings();

            // Do not consider core_id 0
            assert_eq!(core_ids.len() - 1, siblings.len());
        }
    }
}
