// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use serde::Serialize;
use std::collections::BTreeMap;

use crate::common::NitroCliResult;
use crate::enclave_proc::cli_dev::NitroEnclavesCmdReply;
use crate::enclave_proc::utils::generate_enclave_id;

#[derive(Serialize)]
pub struct EnclaveDescribeInfo {
    #[serde(rename(serialize = "EnclaveID"))]
    enclave_id: String,
    #[serde(rename(serialize = "EnclaveCID"))]
    enclave_cid: u64,
    #[serde(rename(serialize = "NumberOfCPUs"))]
    cpu_count: u64,
    #[serde(rename(serialize = "MemoryMiB"))]
    memory_mib: u64,
    #[serde(rename(serialize = "State"))]
    state: String,
    #[serde(rename(serialize = "Flags"))]
    flags: String,
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

pub fn get_enclave_describe_info(
    reply: NitroEnclavesCmdReply,
) -> NitroCliResult<EnclaveDescribeInfo> {
    let info = EnclaveDescribeInfo::new(
        generate_enclave_id(reply.slot_uid)?,
        { reply.enclave_cid },
        { reply.nr_cpus },
        reply.mem_size / 1024 / 1024,
        reply.state_to_string(),
        reply.flags_to_string(),
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
