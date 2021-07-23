// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]
#![allow(clippy::too_many_arguments)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The information to be provided for a `describe-enclaves` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveDescribeInfo {
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "ProcessID")]
    /// The PID of the enclave process which manages the enclave.
    pub process_id: u32,
    #[serde(rename = "EnclaveCID")]
    /// The enclave's CID.
    pub enclave_cid: u64,
    #[serde(rename = "NumberOfCPUs")]
    /// The number of CPUs used by the enclave.
    pub cpu_count: u64,
    #[serde(rename = "CPUIDs")]
    /// The IDs of the CPUs used by the enclave.
    pub cpu_ids: Vec<u32>,
    #[serde(rename = "MemoryMiB")]
    /// The memory provided to the enclave (in MiB).
    pub memory_mib: u64,
    #[serde(rename = "State")]
    /// The current state of the enclave.
    pub state: String,
    #[serde(rename = "Flags")]
    /// The bit-mask which provides the enclave's launch flags.
    pub flags: String,
    #[serde(rename = "PCRs")]
    /// Contains the PCR values.
    pub measurements: BTreeMap<String, String>,
}

impl EnclaveDescribeInfo {
    /// Create a new `EnclaveDescribeInfo` instance from the given enclave information.
    pub fn new(
        enclave_id: String,
        enclave_cid: u64,
        cpu_count: u64,
        cpu_ids: Vec<u32>,
        memory_mib: u64,
        state: String,
        flags: String,
        measurements: BTreeMap<String, String>,
    ) -> Self {
        EnclaveDescribeInfo {
            enclave_id,
            process_id: std::process::id(),
            enclave_cid,
            cpu_count,
            cpu_ids,
            memory_mib,
            state,
            flags,
            measurements,
        }
    }
}

/// The information to be provided for a `run-enclave` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveRunInfo {
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "ProcessID")]
    /// The PID of the enclave process which manages the enclave.
    pub process_id: u32,
    #[serde(rename = "EnclaveCID")]
    /// The enclave's CID.
    pub enclave_cid: u64,
    #[serde(rename = "NumberOfCPUs")]
    /// The number of CPUs used by the enclave.
    pub cpu_count: usize,
    #[serde(rename = "CPUIDs")]
    /// The IDs of the CPUs used by the enclave.
    pub cpu_ids: Vec<u32>,
    #[serde(rename = "MemoryMiB")]
    /// The memory provided to the enclave (in MiB).
    pub memory_mib: u64,
}

impl EnclaveRunInfo {
    /// Create a new `EnclaveRunInfo` instance from the given enclave information.
    pub fn new(
        enclave_id: String,
        enclave_cid: u64,
        cpu_count: usize,
        cpu_ids: Vec<u32>,
        memory_mib: u64,
    ) -> Self {
        EnclaveRunInfo {
            enclave_id,
            process_id: std::process::id(),
            enclave_cid,
            cpu_count,
            cpu_ids,
            memory_mib,
        }
    }
}

/// The information to be provided for a `terminate-enclave` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveTerminateInfo {
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "Terminated")]
    /// A flag indicating if the enclave has terminated.
    pub terminated: bool,
}

impl EnclaveTerminateInfo {
    /// Create a new `EnclaveTerminateInfo` instance from the given enclave information.
    pub fn new(enclave_id: String, terminated: bool) -> Self {
        EnclaveTerminateInfo {
            enclave_id,
            terminated,
        }
    }
}

/// The information to be provided for a `build-enclave` request.
#[derive(Serialize)]
pub struct EnclaveBuildInfo {
    #[serde(rename(serialize = "Measurements"))]
    /// The measurement results (hashes) of various enclave properties.
    measurements: BTreeMap<String, String>,
}

impl EnclaveBuildInfo {
    /// Create a new `EnclaveBuildInfo` instance from the given measurements.
    pub fn new(measurements: BTreeMap<String, String>) -> Self {
        EnclaveBuildInfo { measurements }
    }
}
