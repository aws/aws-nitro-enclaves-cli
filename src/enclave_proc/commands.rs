// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::debug;
use std::fs::File;

use crate::common::commands_parser::RunEnclavesArgs;
use crate::common::json_output::EnclaveTerminateInfo;
use crate::common::NitroCliResult;
use crate::enclave_proc::connection::Connection;
use crate::enclave_proc::cpu_info::CpuInfos;
use crate::enclave_proc::resource_manager::{EnclaveManager, EnclaveState};
use crate::enclave_proc::utils::get_enclave_describe_info;

// Hypervisor cid as defined by:
// http://man7.org/linux/man-pages/man7/vsock.7.html
pub const VMADDR_CID_PARENT: u32 = 3;
pub const ENCLAVE_VSOCK_LOADER_PORT: u32 = 7000;
pub const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;
pub const BUFFER_SIZE: usize = 1024;
pub const DEBUG_FLAG: u16 = 0x1;

pub fn run_enclaves(
    args: &RunEnclavesArgs,
    connection: &Connection,
) -> NitroCliResult<EnclaveManager> {
    debug!("run_enclaves");

    let eif_file =
        File::open(&args.eif_path).map_err(|e| format!("Failed to open the eif file: {}", e))?;

    let cpu_infos = CpuInfos::new()?;
    let cpu_ids = if let Some(cpu_ids) = args.cpu_ids.clone() {
        cpu_infos.check_cpu_ids(&cpu_ids)?;
        Some(cpu_ids)
    } else if let Some(cpu_count) = args.cpu_count {
        Some(cpu_infos.get_cpu_ids(cpu_count)?)
    } else {
        // Should not happen
        None
    };

    let mut enclave_manager = EnclaveManager::new(
        args.enclave_cid,
        args.memory_mib,
        cpu_ids.unwrap(),
        eif_file,
        args.debug_mode.unwrap_or(false),
    )
    .map_err(|e| format!("Failed to create enclave: {}", e))?;
    enclave_manager
        .run_enclave(connection)
        .map_err(|e| format!("Failed to run enclave: {}", e))?;
    enclave_manager
        .update_state(EnclaveState::Running)
        .map_err(|e| format!("Failed to update state: {}", e))?;

    Ok(enclave_manager)
}

pub fn terminate_enclaves(
    enclave_manager: &mut EnclaveManager,
    connection: &Connection,
) -> NitroCliResult<()> {
    let enclave_id = enclave_manager.enclave_id.clone();

    debug!("terminate_enclaves");
    enclave_manager.update_state(EnclaveState::Terminating)?;
    if let Err(err) = enclave_manager.terminate_enclave() {
        connection.eprintln(
            format!(
                "Warning: Failed to stop enclave {}\nError message: {:?}",
                enclave_manager.enclave_id, err
            )
            .as_str(),
        )?;
        return Err(err);
    }

    enclave_manager.update_state(EnclaveState::Empty)?;
    connection.eprintln(
        format!(
            "Successfully terminated enclave {}.",
            enclave_manager.enclave_id
        )
        .as_str(),
    )?;

    // We notify the CLI of the termination's status.
    connection.println(
        serde_json::to_string_pretty(&EnclaveTerminateInfo::new(enclave_id, true))
            .map_err(|err| format!("{:?}", err))?
            .as_str(),
    )
}

pub fn describe_enclaves(
    enclave_manager: &EnclaveManager,
    connection: &Connection,
) -> NitroCliResult<()> {
    debug!("describe_enclaves");

    let info = get_enclave_describe_info(enclave_manager)?;
    connection.println(
        serde_json::to_string_pretty(&info)
            .map_err(|err| format!("{:?}", err))?
            .as_str(),
    )
}
