// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]
#![allow(clippy::too_many_arguments)]

use aws_nitro_enclaves_image_format::defs::EifIdentityInfo;
use aws_nitro_enclaves_image_format::utils::eif_reader::SignCertificateInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The information to be provided for a `describe-enclaves` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveDescribeInfo {
    /// Enclave name assigned by the user
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EnclaveName")]
    pub enclave_name: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    /// Build measurements containing PCRs
    pub build_info: Option<EnclaveBuildInfo>,
    /// Assigned or default EIF name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ImageName")]
    pub img_name: Option<String>,
    #[serde(rename = "ImageVersion")]
    /// Assigned or default EIF version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub img_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Metadata")]
    /// EIF metadata
    pub metadata: Option<MetadataDescribeInfo>,
}

impl EnclaveDescribeInfo {
    /// Create a new `EnclaveDescribeInfo` instance from the given enclave information.
    pub fn new(
        enclave_name: Option<String>,
        enclave_id: String,
        enclave_cid: u64,
        cpu_count: u64,
        cpu_ids: Vec<u32>,
        memory_mib: u64,
        state: String,
        flags: String,
        build_info: Option<EnclaveBuildInfo>,
        img_name: Option<String>,
        img_version: Option<String>,
        metadata: Option<MetadataDescribeInfo>,
    ) -> Self {
        EnclaveDescribeInfo {
            enclave_name,
            enclave_id,
            process_id: std::process::id(),
            enclave_cid,
            cpu_count,
            cpu_ids,
            memory_mib,
            state,
            flags,
            build_info,
            img_name,
            img_version,
            metadata,
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
pub struct EifDescribeInfo {
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
    #[serde(rename = "CheckCRC")]
    /// Specifies if the CRC check passed.
    pub crc_check: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "SignatureCheck")]
    /// Specifies if the EIF signature check passed.
    pub sign_check: Option<bool>,
    #[serde(rename = "ImageName")]
    /// Assigned or default EIF name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub img_name: Option<String>,
    #[serde(rename = "ImageVersion")]
    /// Assigned or default EIF version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub img_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Metadata")]
    /// EIF metadata
    pub metadata: Option<MetadataDescribeInfo>,
}

/// Metadata to be included in the describe output
#[derive(Clone, Serialize, Deserialize)]
pub struct MetadataDescribeInfo {
    #[serde(rename = "BuildTime")]
    /// Time of the build
    pub build_time: String,
    #[serde(rename = "BuildTool")]
    /// Tool used for EIF build
    pub build_tool: String,
    #[serde(rename = "BuildToolVersion")]
    /// Version of the build tool
    pub tool_version: String,
    #[serde(rename = "OperatingSystem")]
    /// Enclave OS
    pub operating_system: String,
    #[serde(rename = "KernelVersion")]
    /// Enclave kernel version
    pub kernel_version: String,
    #[serde(rename = "DockerInfo")]
    /// Docker image information
    pub docker_info: serde_json::Value,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    #[serde(rename = "CustomMetadata")]
    #[serde(flatten)]
    /// Metadata added by the user as JSON
    pub custom_metadata: serde_json::Value,
}

impl MetadataDescribeInfo {
    /// Construct metadata output struct
    pub fn new(eif_info: EifIdentityInfo) -> Self {
        MetadataDescribeInfo {
            build_time: eif_info.build_info.build_time,
            build_tool: eif_info.build_info.build_tool,
            tool_version: eif_info.build_info.build_tool_version,
            operating_system: eif_info.build_info.img_os,
            kernel_version: eif_info.build_info.img_kernel,
            docker_info: eif_info.docker_info,
            custom_metadata: eif_info.custom_info,
        }
    }
}
