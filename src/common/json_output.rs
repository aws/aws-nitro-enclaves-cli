// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveDescribeInfo {
    #[serde(rename = "EnclaveID")]
    pub enclave_id: String,
    #[serde(rename = "EnclaveCID")]
    pub enclave_cid: u64,
    #[serde(rename = "NumberOfCPUs")]
    pub cpu_count: u64,
    #[serde(rename = "MemoryMiB")]
    pub memory_mib: u64,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Flags")]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveRunInfo {
    #[serde(rename = "EnclaveID")]
    pub enclave_id: String,
    #[serde(rename = "EnclaveCID")]
    pub enclave_cid: u64,
    #[serde(rename = "NumberOfCPUs")]
    pub cpu_count: usize,
    #[serde(rename = "CPUIDs")]
    pub cpu_ids: Vec<u32>,
    #[serde(rename = "MemoryMiB")]
    pub memory_mib: u64,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveTerminateInfo {
    #[serde(rename = "EnclaveID")]
    pub enclave_id: String,
    #[serde(rename = "Terminated")]
    pub terminated: bool,
}

impl EnclaveTerminateInfo {
    pub fn new(enclave_id: String, terminated: bool) -> Self {
        EnclaveTerminateInfo {
            enclave_id,
            terminated,
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
