// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CpuInfo {
    core_id: u32,
    cpu_id: u32,
}

impl CpuInfo {
    pub fn new(cpu_id: u32, core_id: u32) -> Self {
        CpuInfo { cpu_id, core_id }
    }
}

#[derive(Debug)]
pub struct CpuInfos {
    pub core_ids: Vec<CpuInfo>,
    pub hyper_threading: bool,
}

impl CpuInfos {
    pub fn new() -> Result<Self, String> {
        let core_ids = CpuInfos::get_cpu_info()?;
        let hyper_threading = CpuInfos::is_hyper_threading_on(&core_ids);
        Ok(CpuInfos {
            core_ids,
            hyper_threading,
        })
    }

    pub fn get_value(mut line: String) -> Result<u32, String> {
        line.retain(|c| !c.is_whitespace());
        let tokens: Vec<&str> = line.split(':').collect();
        let token = *tokens.get(1).unwrap();

        u32::from_str(token).map_err(|err| format!("{}", err))
    }

    pub fn get_cpu_info() -> Result<Vec<CpuInfo>, String> {
        let mut result: Vec<CpuInfo> = Vec::new();
        let mut ids: Vec<u32> = Vec::new();
        let file = File::open("/proc/cpuinfo")
            .map_err(|err| format!("Could not open /proc/cpuinfo: {}", err))?;
        let mut reader = BufReader::new(file);

        loop {
            let mut line = String::new();
            let len = reader
                .read_line(&mut line)
                .map_err(|err| format!("{}", err))?;

            if len == 0 {
                break;
            }

            // given a cpu i, its cpu_id will be at 2*i and
            // its core_id at 2*i+1
            if line.contains("processor") {
                ids.push(CpuInfos::get_value(line)?);
            } else if line.contains("apicid")
                && !line.contains("initial")
                && !line.contains("flags")
            {
                let id = CpuInfos::get_value(line)?;
                ids.push(id >> 1);
            }
        }

        for i in 0..ids.len() / 2 {
            result.push(CpuInfo::new(
                *ids.get(2 * i).unwrap(),
                *ids.get(2 * i + 1).unwrap(),
            ));
        }

        // sort by core_id
        result.sort_by(|a, b| a.core_id.cmp(&b.core_id));
        Ok(result)
    }

    pub fn get_core_id(&self, cpu_id: u32) -> Option<u32> {
        for info in self.core_ids.iter() {
            if info.cpu_id == cpu_id {
                return Some(info.core_id);
            }
        }
        None
    }

    pub fn is_hyper_threading_on(cpu_info: &[CpuInfo]) -> bool {
        for i in 0..cpu_info.len() - 1 {
            if cpu_info.get(i).unwrap().core_id == cpu_info.get(i + 1).unwrap().core_id {
                return true;
            }
        }
        false
    }

    pub fn get_cpu_ids(&self, cpu_count: u32) -> Result<Vec<u32>, String> {
        if self.hyper_threading && cpu_count % 2 != 0 {
            return Err("cpu_count should be an even number.".to_string());
        }

        let mut count: u32 = cpu_count;
        let mut result: Vec<u32> = Vec::new();

        for info in self.core_ids.iter() {
            if info.core_id != 0 {
                result.push(info.cpu_id);
                count -= 1;
            }

            if count == 0 {
                return Ok(result);
            }
        }

        let valid_cpus = if self.hyper_threading {
            self.core_ids.len() - 2
        } else {
            self.core_ids.len() - 1
        };

        Err(format!(
            "Could not find the requested number of cpus. Maximum number of available cpus: {}",
            valid_cpus
        ))
    }

    pub fn contains_sibling_pairs(&self, cpu_ids: &[u32]) -> bool {
        let mut core_ids: HashSet<u32> = HashSet::new();

        for id in cpu_ids.iter() {
            match self.get_core_id(*id) {
                Some(core_id) => {
                    if !core_ids.contains(&core_id) {
                        core_ids.insert(core_id);
                    } else {
                        core_ids.remove(&core_id);
                    }
                }
                _ => return false,
            }
        }

        core_ids.is_empty()
    }

    pub fn get_cpu_candidates(&self) -> Vec<u32> {
        let mut result: Vec<u32> = Vec::new();

        for info in self.core_ids.iter() {
            if info.core_id != 0 {
                result.push(info.cpu_id);
            }
        }
        result
    }

    pub fn check_cpu_ids(&self, cpu_ids: &[u32]) -> Result<(), String> {
        if self.hyper_threading && cpu_ids.len() % 2 != 0 {
            return Err(
                "Hyper-threading is enabled, so sibling pairs need to be provided".to_string(),
            );
        }

        for id in cpu_ids.iter() {
            match self.get_core_id(*id) {
                Some(0) => {
                    return Err(format!(
                        "Cpus with core id 0 can't be used. Hint: You can use {:?}",
                        self.get_cpu_candidates()
                    ))
                }
                None => {
                    return Err(format!(
                        "Cpus ids are not valid. Hint: You can use {:?}",
                        self.get_cpu_candidates()
                    ))
                }
                _ => (),
            }
        }

        if self.hyper_threading && !self.contains_sibling_pairs(cpu_ids) {
            return Err(format!(
                "Hyper-threading is enabled, cpus must be on the same physical core. Hint: The following cpus are siblings {:?}",
                self.get_siblings()
            ));
        }

        Ok(())
    }

    pub fn get_siblings(&self) -> Vec<(u32, u32)> {
        let mut result: Vec<(u32, u32)> = Vec::new();

        // find the pairs of cpu_ids that have the same core_id
        for i in 0..self.core_ids.len() - 1 {
            let info1 = self.core_ids.get(i).unwrap();
            let info2 = self.core_ids.get(i + 1).unwrap();

            if info1.core_id == info2.core_id && info1.core_id != 0 {
                result.push((info1.cpu_id, info2.cpu_id));
            }
        }

        result
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
