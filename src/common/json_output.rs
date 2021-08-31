// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]
#![allow(clippy::too_many_arguments)]

use eif_utils::SignCertificateInfo;
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
        }
    }
}

/// Output structure for describe command containing additional fields,
/// like measurements, not found in older NitroCLI versions
#[derive(Clone, Serialize, Deserialize)]
pub struct DescribeOutput {
    /// Enclave name assigned by the user
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EnclaveName")]
    pub enclave_name: Option<String>,
    #[serde(flatten)]
    /// General describe info found in all versions of NitroCLI
    describe_info: EnclaveDescribeInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    /// Build measurements containing PCRs
    pub build_info: Option<EnclaveBuildInfo>,
}

impl DescribeOutput {
    /// Creates new describe output from available
    pub fn new(
        enclave_name: Option<String>,
        describe_info: EnclaveDescribeInfo,
        build_info: Option<EnclaveBuildInfo>,
    ) -> Self {
        DescribeOutput {
            enclave_name,
            describe_info,
            build_info,
        }
    }
}

/// The information to be provided for a `run-enclave` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveRunInfo {
    #[serde(rename = "EnclaveName")]
    /// The name of the enclave.
    pub enclave_name: String,
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
        enclave_name: String,
        enclave_id: String,
        enclave_cid: u64,
        cpu_count: usize,
        cpu_ids: Vec<u32>,
        memory_mib: u64,
    ) -> Self {
        EnclaveRunInfo {
            enclave_name,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EnclaveName")]
    /// The name of the enclave. Optional for older versions.
    pub enclave_name: Option<String>,
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "Terminated")]
    /// A flag indicating if the enclave has terminated.
    pub terminated: bool,
}

impl EnclaveTerminateInfo {
    /// Create a new `EnclaveTerminateInfo` instance from the given enclave information.
    pub fn new(enclave_name: Option<String>, enclave_id: String, terminated: bool) -> Self {
        EnclaveTerminateInfo {
            enclave_name,
            enclave_id,
            terminated,
        }
    }
}

/// The information to be provided for a `build-enclave` request.
#[derive(Serialize, Clone, Deserialize, Debug)]
pub struct EnclaveBuildInfo {
    #[serde(rename = "Measurements")]
    /// The measurement results (hashes) of various enclave properties.
    pub measurements: BTreeMap<String, String>,
}

impl EnclaveBuildInfo {
    /// Create a new `EnclaveBuildInfo` instance from the given measurements.
    pub fn new(measurements: BTreeMap<String, String>) -> Self {
        EnclaveBuildInfo { measurements }
    }
}

/// The information to be provided for a `describe-eif` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct DescribeEifInfo {
    #[serde(rename = "EifVersion")]
    /// EIF version.
    pub version: u16,
    #[serde(flatten)]
    /// Contains the PCR values.
    pub build_info: EnclaveBuildInfo,
    #[serde(rename = "IsSigned")]
    /// Specifies if the image is signed or not.
    pub is_signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "SigningCertificate")]
    /// Certificate's signature algorithm
    pub cert_info: Option<SignCertificateInfo>,
}

impl DescribeEifInfo {
    /// Create describe information structure for EIF.
    pub fn new(
        version: u16,
        build_info: EnclaveBuildInfo,
        is_signed: bool,
        cert_info: Option<SignCertificateInfo>,
    ) -> Self {
        DescribeEifInfo {
            version,
            build_info,
            is_signed,
            cert_info,
        }
    }
}
