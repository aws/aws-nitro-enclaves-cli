// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use log::debug;
use std::fs::File;

use crate::common::commands_parser::RunEnclavesArgs;
use crate::common::json_output::EnclaveTerminateInfo;
use crate::common::NitroCliResult;
use crate::enclave_proc::connection::Connection;
use crate::enclave_proc::connection::{safe_conn_eprintln, safe_conn_println};
use crate::enclave_proc::cpu_info::CpuInfo;
use crate::enclave_proc::resource_manager::{EnclaveManager, EnclaveState};
use crate::enclave_proc::utils::get_enclave_describe_info;

/// Hypervisor CID as defined by <http://man7.org/linux/man-pages/man7/vsock.7.html>.
pub const VMADDR_CID_PARENT: u32 = 3;

/// The vsock port used to confirm that the enclave has booted.
pub const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;

/// Launch an enclave with the specified arguments and provide the launch status through the given connection.
pub fn run_enclaves(
    args: &RunEnclavesArgs,
    connection: Option<&Connection>,
) -> NitroCliResult<EnclaveManager> {
    debug!("run_enclaves");

    let eif_file =
        File::open(&args.eif_path).map_err(|e| format!("Failed to open the eif file: {}", e))?;

    let cpu_ids = CpuInfo::new()?.get_cpu_config(args)?;
    let mut enclave_manager = EnclaveManager::new(
        args.enclave_cid,
        args.memory_mib,
        cpu_ids,
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

/// Terminate an enclave and provide the termination status through the given connection.
pub fn terminate_enclaves(
    enclave_manager: &mut EnclaveManager,
    connection: Option<&Connection>,
) -> NitroCliResult<()> {
    let enclave_id = enclave_manager.enclave_id.clone();

    debug!("terminate_enclaves");
    enclave_manager.update_state(EnclaveState::Terminating)?;
    if let Err(err) = enclave_manager.terminate_enclave() {
        safe_conn_eprintln(
            connection,
            format!(
                "Warning: Failed to stop enclave {}\nError message: {:?}",
                enclave_manager.enclave_id, err
            )
            .as_str(),
        )?;
        return Err(err);
    }

    enclave_manager.update_state(EnclaveState::Empty)?;
    safe_conn_eprintln(
        connection,
        format!(
            "Successfully terminated enclave {}.",
            enclave_manager.enclave_id
        )
        .as_str(),
    )?;

    // We notify the CLI of the termination's status.
    safe_conn_println(
        connection,
        serde_json::to_string_pretty(&EnclaveTerminateInfo::new(enclave_id, true))
            .map_err(|err| format!("{:?}", err))?
            .as_str(),
    )
}

/// Obtain an enclave's description and provide it through the given connection.
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
