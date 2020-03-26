// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::debug;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{self, Write};

use crate::common::commands_parser::{ConsoleArgs, RunEnclavesArgs};
use crate::common::NitroCliResult;
use crate::enclave_proc::cli_dev::{CliDev, NitroEnclavesSlotInfo};
use crate::enclave_proc::cpu_info::CpuInfos;
use crate::enclave_proc::json_output::get_enclave_describe_info;
use crate::enclave_proc::json_output::EnclaveDescribeInfo;
use crate::enclave_proc::resource_manager::{EnclaveManager, EnclaveState};
use crate::enclave_proc::utils::get_slot_id;
use crate::enclave_proc::utils::Console;

// Hypervisor cid as defined by:
// http://man7.org/linux/man-pages/man7/vsock.7.html
pub const VMADDR_CID_HYPERVISOR: u32 = 0;
pub const VMADDR_CID_PARENT: u32 = 3;
pub const CID_TO_CONSOLE_PORT_OFFSET: u32 = 10000;
pub const ENCLAVE_VSOCK_LOADER_PORT: u32 = 7000;
pub const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;
pub const BUFFER_SIZE: usize = 1024;
pub const DEBUG_FLAG: u16 = 0x1;

pub fn run_enclaves(args: &RunEnclavesArgs) -> NitroCliResult<EnclaveManager> {
    debug!("run_enclaves");

    let eif_file = File::open(&args.eif_path)
        .map_err(|err| format!("Failed to open the eif file: {:?}", err))?;

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
    .map_err(|err| format!("Could not create enclave: {:?}", err))?;
    enclave_manager.run_enclave()?;
    enclave_manager.update_state(EnclaveState::Running)?;

    Ok(enclave_manager)
}

pub fn terminate_enclaves(enclave_manager: &mut EnclaveManager) -> NitroCliResult<()> {
    debug!("terminate_enclaves");

    enclave_manager.update_state(EnclaveState::Terminating)?;
    if let Err(err) = enclave_manager.terminate_enclave() {
        println!(
            "Warning: Failed to stop enclave {}\nError message: {:?}",
            enclave_manager.enclave_id, err
        );
        return Err(err);
    }

    eprintln!(
        "Successfully terminated enclave {}.",
        enclave_manager.enclave_id
    );
    enclave_manager.update_state(EnclaveState::Empty)?;

    Ok(())
}

pub fn describe_enclaves(enclave_manager: &EnclaveManager) -> NitroCliResult<()> {
    debug!("describe_enclaves");

    let info = get_enclave_describe_info(enclave_manager)?;
    let infos: Vec<EnclaveDescribeInfo> = vec![info];

    println!(
        "{}",
        serde_json::to_string_pretty(&infos).map_err(|err| format!("{:?}", err))?
    );

    Ok(())
}

pub fn console_enclaves(args: ConsoleArgs) -> NitroCliResult<()> {
    debug!("console_enclaves");

    let mut cli_dev = CliDev::new()?;
    if !cli_dev.enable()? {
        return Err("Failed to enable cli dev".to_string());
    }

    let slot_id = get_slot_id(args.enclave_id)?;
    let slot_info = NitroEnclavesSlotInfo::new(slot_id);
    let reply = slot_info.submit(&mut cli_dev)?;
    drop(cli_dev);
    let enclave_cid = reply.enclave_cid;

    println!("Connecting to the console for enclave {}...", enclave_cid);
    enclave_console(enclave_cid)
        .map_err(|err| format!("Failed to start enclave logger: {:?}", err))?;
    Ok(())
}

/// Connects to the enclave console and prints it continously
pub fn enclave_console(enclave_cid: u64) -> NitroCliResult<()> {
    let console = Console::new(
        VMADDR_CID_HYPERVISOR,
        u32::try_from(enclave_cid)
            .map_err(|err| format!("Failed to connect to the enclave: {}", err))?
            + CID_TO_CONSOLE_PORT_OFFSET,
    )?;
    println!("Successfully connected to the console.");
    console.read_to(io::stdout().by_ref())?;

    Ok(())
}
