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
        let tokens: Vec<&str> = line.split(":").collect();
        let token = *tokens.get(1).unwrap();

        u32::from_str(token).map_err(|err| format!("{}", err))
    }

    pub fn get_cpu_info() -> Result<Vec<CpuInfo>, String> {
        let mut result: Vec<CpuInfo> = Vec::new();
        let mut ids: Vec<u32> = Vec::new();
        let file =
            File::open("/proc/cpuinfo").map_err(|_err| format!("Could not open /proc/cpuinfo"))?;
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

    pub fn is_hyper_threading_on(cpu_info: &Vec<CpuInfo>) -> bool {
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

        let mut count: u32 = cpu_count.clone();
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

        let valid_cpus = match self.hyper_threading {
            true => self.core_ids.len() - 2,
            _ => self.core_ids.len() - 1,
        };

        Err(format!(
            "Could not find the requested number of cpus. Maximum number of available cpus: {}",
            valid_cpus
        ))
    }

    pub fn contains_sibling_pairs(&self, cpu_ids: &Vec<u32>) -> bool {
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

        core_ids.len() == 0
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

    pub fn check_cpu_ids(&self, cpu_ids: &Vec<u32>) -> Result<(), String> {
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

        return Ok(());
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
