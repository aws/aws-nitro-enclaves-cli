// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use serde::Serialize;
use std::collections::BTreeMap;

use crate::common::NitroCliResult;
use crate::enclave_proc::commands::DEBUG_FLAG;
use crate::enclave_proc::resource_manager::EnclaveManager;
use crate::enclave_proc::utils::generate_enclave_id;

#[derive(Serialize)]
pub struct EnclaveDescribeInfo {
    #[serde(rename(serialize = "EnclaveID"))]
    pub enclave_id: String,
    #[serde(rename(serialize = "EnclaveCID"))]
    pub enclave_cid: u64,
    #[serde(rename(serialize = "NumberOfCPUs"))]
    pub cpu_count: u64,
    #[serde(rename(serialize = "MemoryMiB"))]
    pub memory_mib: u64,
    #[serde(rename(serialize = "State"))]
    pub state: String,
    #[serde(rename(serialize = "Flags"))]
    pub flags: String,
}

impl EnclaveDescribeInfo {
    pub fn new(
        enclave_id: String,
        enclave_cid: u64,
        cpu_count: u64,
        memory_mib: u64,
        state: String,
        flags: String,
    ) -> Self {
        EnclaveDescribeInfo {
            enclave_id,
            enclave_cid,
            cpu_count,
            memory_mib,
            state,
            flags,
        }
    }
}

#[derive(Serialize)]
pub struct EnclaveRunInfo {
    #[serde(rename(serialize = "EnclaveID"))]
    enclave_id: String,
    #[serde(rename(serialize = "EnclaveCID"))]
    enclave_cid: u64,
    #[serde(rename(serialize = "NumberOfCPUs"))]
    cpu_count: usize,
    #[serde(rename(serialize = "CPUIDs"))]
    cpu_ids: Vec<u32>,
    #[serde(rename(serialize = "MemoryMiB"))]
    memory_mib: u64,
}

impl EnclaveRunInfo {
    pub fn new(
        enclave_id: String,
        enclave_cid: u64,
        cpu_count: usize,
        cpu_ids: Vec<u32>,
        memory_mib: u64,
    ) -> Self {
        EnclaveRunInfo {
            enclave_id,
            enclave_cid,
            cpu_count,
            cpu_ids,
            memory_mib,
        }
    }
}

#[derive(Serialize)]
pub struct EnclaveBuildInfo {
    #[serde(rename(serialize = "Measurements"))]
    measurements: BTreeMap<String, String>,
}

impl EnclaveBuildInfo {
    pub fn new(measurements: BTreeMap<String, String>) -> Self {
        EnclaveBuildInfo { measurements }
    }
}

pub fn flags_to_string(flags: u16) -> String {
    if flags & DEBUG_FLAG == DEBUG_FLAG {
        "DEBUG_MODE"
    } else {
        "NONE"
    }
    .to_string()
}

pub fn get_enclave_describe_info(
    enclave_manager: &EnclaveManager,
) -> NitroCliResult<EnclaveDescribeInfo> {
    let (slot_uid, enclave_cid, cpus_count, memory_mib, flags, state) =
        enclave_manager.get_description_resources()?;
    let info = EnclaveDescribeInfo::new(
        generate_enclave_id(slot_uid)?,
        enclave_cid,
        cpus_count,
        memory_mib,
        state.to_string(),
        flags_to_string(flags),
    );
    Ok(info)
}

pub fn get_run_enclaves_info(
    enclave_cid: u64,
    slot_id: u64,
    cpu_ids: Vec<u32>,
    memory: u64,
) -> NitroCliResult<EnclaveRunInfo> {
    let info = EnclaveRunInfo::new(
        generate_enclave_id(slot_id)?,
        enclave_cid,
        cpu_ids.len(),
        cpu_ids,
        memory,
    );
    Ok(info)
}

pub fn get_enclave_id(info: &EnclaveRunInfo) -> String {
    info.enclave_id.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that `flags_to_string()` returns the correct String representation
    /// when the DEBUG_FLAG is either set or unset.
    #[test]
    fn test_flags_to_string() {
        let mut flags: u16 = 0;

        flags |= DEBUG_FLAG;
        let mut result = flags_to_string(flags);

        assert!(result.eq("DEBUG_MODE"));

        flags = 0;
        result = flags_to_string(flags);

        assert!(result.eq("NONE"));
    }

    /// Asserts that `get_run_enclaves_info()` returns a result containing
    /// exactly the same values as the supplied arguments.
    #[test]
    fn test_get_run_enclaves_info() {
        let enclave_cid: u64 = 0;
        let slot_id: u64 = 7;
        let cpu_ids: Vec<u32> = vec![1, 3];
        let memory: u64 = 64;

        let result = get_run_enclaves_info(enclave_cid, slot_id, cpu_ids.clone(), memory);

        assert!(result.is_ok());

        if let Ok(result) = result {
            assert_eq!(enclave_cid, result.enclave_cid);
            assert_eq!(cpu_ids.len(), result.cpu_ids.len());
            for (idx, cpu_id) in result.cpu_ids.iter().enumerate() {
                assert_eq!(cpu_ids[idx], *cpu_id);
            }
            assert_eq!(memory, result.memory_mib);
        }
    }

    /// Asserts that `get_enclave_id()` returns the expected enclave
    /// id, which is obtained through a call to `get_run_enclaves_info()`.
    #[test]
    fn test_get_enclave_id() {
        let enclave_cid: u64 = 0;
        let slot_id: u64 = 8;
        let cpu_ids: Vec<u32> = vec![1, 3];
        let memory: u64 = 64;

        let result = get_run_enclaves_info(enclave_cid, slot_id, cpu_ids.clone(), memory);

        assert!(result.is_ok());

        if let Ok(result) = result {
            let this_enclave_id = &result.enclave_id;
            assert!(this_enclave_id.eq(&get_enclave_id(&result)));

            assert_eq!(enclave_cid, result.enclave_cid);
            assert_eq!(cpu_ids.len(), result.cpu_ids.len());
            for (idx, cpu_id) in result.cpu_ids.iter().enumerate() {
                assert_eq!(cpu_ids[idx], *cpu_id);
            }
            assert_eq!(memory, result.memory_mib);
        }
    }
}
