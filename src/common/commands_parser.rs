// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use clap::ArgMatches;
use serde::{Deserialize, Serialize};

use crate::common::NitroCliResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEnclavesArgs {
    pub eif_path: String,
    pub enclave_cid: Option<u64>,
    pub memory_mib: u64,
    pub cpu_ids: Option<Vec<u32>>,
    pub debug_mode: Option<bool>,
    pub cpu_count: Option<u32>,
}

impl RunEnclavesArgs {
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        Ok(RunEnclavesArgs {
            cpu_count: parse_cpu_count(args)?,
            eif_path: parse_eif_path(args)?,
            enclave_cid: parse_enclave_cid(args)?,
            memory_mib: parse_memory(args)?,
            cpu_ids: parse_cpu_ids(args)?,
            debug_mode: debug_mode(args),
        })
    }
}

#[derive(Debug, Clone)]
pub struct BuildEnclavesArgs {
    pub docker_uri: String,
    pub docker_dir: Option<String>,
    pub output: String,
}

impl BuildEnclavesArgs {
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        Ok(BuildEnclavesArgs {
            docker_uri: parse_docker_tag(args).ok_or("Could not find docker-uri argument")?,
            docker_dir: parse_docker_dir(args),
            output: parse_output(args).ok_or("Could not find output argument")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TerminateEnclavesArgs {
    pub enclave_id: String,
}

impl TerminateEnclavesArgs {
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        Ok(TerminateEnclavesArgs {
            enclave_id: parse_enclave_id(args)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DescribeEnclaveArgs {}

impl DescribeEnclaveArgs {
    pub fn new_with(_args: &ArgMatches) -> NitroCliResult<Self> {
        // Nothing to parse for describe-enclaves, but keep it consistent
        // with parsing of the other commands.
        Ok(DescribeEnclaveArgs {})
    }
}

#[derive(Debug, Clone)]
pub struct ConsoleArgs {
    pub enclave_id: String,
}

impl ConsoleArgs {
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        Ok(ConsoleArgs {
            enclave_id: parse_enclave_id(args)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct EmptyArgs {}

fn parse_memory(args: &ArgMatches) -> NitroCliResult<u64> {
    let memory = args
        .value_of("memory")
        .ok_or("Could not find memory argument")?;
    memory
        .parse()
        .map_err(|_err| "memory is not a number".to_string())
}

fn parse_docker_tag(args: &ArgMatches) -> Option<String> {
    args.value_of("docker-uri").map(|val| val.to_string())
}

fn parse_docker_dir(args: &ArgMatches) -> Option<String> {
    args.value_of("docker-dir").map(|val| val.to_string())
}

fn parse_enclave_cid(args: &ArgMatches) -> NitroCliResult<Option<u64>> {
    let enclave_cid = if let Some(enclave_cid) = args.value_of("enclave-cid") {
        let enclave_cid: u64 = enclave_cid
            .parse()
            .map_err(|_err| "enclave-cid is not a number")?;
        Some(enclave_cid)
    } else {
        None
    };
    Ok(enclave_cid)
}

fn parse_eif_path(args: &ArgMatches) -> NitroCliResult<String> {
    let eif_path = args
        .value_of("eif-path")
        .ok_or("Could not find eif-path argument")?;
    Ok(eif_path.to_string())
}

fn parse_enclave_id(args: &ArgMatches) -> NitroCliResult<String> {
    let enclave_id = args
        .value_of("enclave-id")
        .ok_or("Could not find enclave-id argument")?;
    Ok(enclave_id.to_string())
}

fn parse_cpu_ids(args: &ArgMatches) -> NitroCliResult<Option<Vec<u32>>> {
    let cpu_ids_arg = args.values_of("cpu-ids");
    match cpu_ids_arg {
        Some(iterator) => {
            let mut cpu_ids = Vec::new();
            for cpu_id in iterator {
                cpu_ids.push(cpu_id.parse().map_err(|_err| "cpu-id is not a number")?);
            }
            Ok(Some(cpu_ids))
        }
        None => Ok(None),
    }
}

fn parse_cpu_count(args: &ArgMatches) -> NitroCliResult<Option<u32>> {
    let cpu_count = if let Some(cpu_count) = args.value_of("cpu-count") {
        let cpu_count: u32 = cpu_count
            .parse()
            .map_err(|_err| "cpu-count is not a number")?;
        Some(cpu_count)
    } else {
        None
    };
    Ok(cpu_count)
}

fn parse_output(args: &ArgMatches) -> Option<String> {
    args.value_of("output-file").map(|val| val.to_string())
}

fn debug_mode(args: &ArgMatches) -> Option<bool> {
    let val = args.is_present("debug-mode");
    if val {
        Some(val)
    } else {
        None
    }
}
