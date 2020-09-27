// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]
#![allow(missing_docs)]

#[macro_use]
extern crate enum_primitive_derive;
extern crate num_traits;

pub mod cli_dev;
pub mod commands_parser;
pub mod cpu_info;
pub mod json_output;
pub mod resource_allocator_driver;
pub mod resource_manager;
pub mod testing_commands;
pub mod utils;

use log::debug;
use std::fs::File;

use crate::common::commands_parser::{ConsoleArgs, RunEnclavesArgs, TerminateEnclavesArgs};
use super::resource_allocator_driver::ResourceAllocatorDriver;
use super::resource_manager::EnclaveResourceManager;
use crate::enclave_proc::cpu_info::EnclaveCpuConfig;

use super::cli_dev::{
    CliDev, NitroEnclavesCmdReply, NitroEnclavesEnclaveStop, NitroEnclavesNextSlot,
    NitroEnclavesSlotCount, NitroEnclavesSlotFree, NitroEnclavesSlotInfo,
};
use std::io::{self, Write};

use super::resource_manager::online_slot_cpus;
use std::convert::TryFrom;
use crate::enclave_proc::utils::get_slot_id;
use crate::enclave_proc::utils::generate_enclave_id;
use crate::common::json_output::{EnclaveDescribeInfo, EnclaveRunInfo};
use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::utils::Console;

use crate::enclave_proc::cpu_info::CpuInfo;
use crate::new_nitro_cli_failure;

// Hypervisor cid as defined by:
// http://man7.org/linux/man-pages/man7/vsock.7.html
pub const VMADDR_CID_HYPERVISOR: u32 = 0;
pub const VMADDR_CID_PARENT: u32 = 3;
pub const CID_TO_CONSOLE_PORT_OFFSET: u32 = 10000;
pub const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;
pub const BUFFER_SIZE: usize = 1024;

pub fn run_enclaves_poweruser(args: &RunEnclavesArgs) -> NitroCliResult<u64> {
    let eif_file = File::open(&args.eif_path)
        .map_err(|err| {
            new_nitro_cli_failure!(
                &format!("Failed to open the eif file: {:?}", err),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

    let cpu_config = CpuInfo::new()?.get_cpu_config(args)?;
    let cpu_ids = match cpu_config {
        EnclaveCpuConfig::List(cpu_ids) => cpu_ids,
        _ => vec![]
    };

    let mut resource_manager = EnclaveResourceManager::new(
        args.enclave_cid,
        args.memory_mib,
        cpu_ids,
        eif_file,
        args.debug_mode.unwrap_or(false),
    )
    .map_err(|err| {
        new_nitro_cli_failure!(
            &format!("Could not create enclave: {:?}", err),
            NitroCliErrorEnum::EnclaveBootFailure
        )
    })?;
    let (enclave_cid, slot_id) = resource_manager.create_enclave()?;

    let cpu_ids = resource_manager.cpu_ids.clone();
    let memory = resource_manager.allocated_memory_mib;

    let info = get_run_enclaves_info(enclave_cid, slot_id, cpu_ids, memory)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&info)
            .map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("{:?}", err),
                    NitroCliErrorEnum::UnspecifiedError
                )
            })?
    );

    Ok(enclave_cid)
}

pub fn terminate_enclaves_poweruser(terminate_args: TerminateEnclavesArgs) -> NitroCliResult<()> {
    debug!("terminate_enclaves");

    let mut cli_dev = CliDev::new()?;
    if !cli_dev.enable()? {
        return Err(NitroCliFailure::new()
        .add_subaction("Failed to enable cli dev".to_string())
        .set_error_code(NitroCliErrorEnum::UnspecifiedError)
        .set_file_and_line(file!(), line!()));
    }

    let enclave_id = terminate_args.enclave_id.clone();
    let slot_id = get_slot_id(terminate_args.enclave_id).map_err(|_| {
        new_nitro_cli_failure!(
            "Failed to obtain the slot id".to_string(),
            NitroCliErrorEnum::UnspecifiedError
        )
    })?;

    // Stop enclave
    let stop = NitroEnclavesEnclaveStop::new(slot_id);
    if let Err(err) = stop.submit(&mut cli_dev) {
        println!(
            "Warning: Failed to stop enclave {}\nError message: {:?}",
            enclave_id, err
        );
    }
    // Slot_free
    let slot_free = NitroEnclavesSlotFree::new(slot_id);
    slot_free.submit(&mut cli_dev)?;

    let resource_allocator_driver = ResourceAllocatorDriver::new()?;
    online_slot_cpus(&resource_allocator_driver, slot_id)?;

    resource_allocator_driver.free(slot_id)?;

    eprintln!("Successfully terminated enclave {}.", enclave_id);

    Ok(())
}

pub fn describe_enclaves_poweruser()
-> NitroCliResult<Vec<NitroEnclavesCmdReply>> {
    debug!("describe_enclaves");
    let mut cli_dev = CliDev::new()?;
    if !cli_dev.enable()? {
        return Err(NitroCliFailure::new()
        .add_subaction("Failed to enable the CLI device".to_string())
        .set_error_code(NitroCliErrorEnum::UnspecifiedError)
        .set_file_and_line(file!(), line!()));
    }
    let slot_count = NitroEnclavesSlotCount::new();
    let reply = slot_count.submit(&mut cli_dev)?;

    let num_slots = reply.slot_count;

    let mut current_slot = 0;
    let mut replies: Vec<NitroEnclavesCmdReply> = Vec::new();
    let mut infos: Vec<EnclaveDescribeInfo> = Vec::new();

    for _i in 0..num_slots {
        let next_slot = NitroEnclavesNextSlot::new(current_slot);
        let reply = next_slot.submit(&mut cli_dev)?;

        let slot_info = NitroEnclavesSlotInfo::new(reply.slot_uid);
        let reply = slot_info.submit(&mut cli_dev)?;
        let info = get_enclave_describe_info(reply)?;
        replies.push(reply.clone());
        infos.push(info);

        current_slot = reply.slot_uid + 1;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&infos).map_err(|err| {
            new_nitro_cli_failure!(
                format!("{:?}", err),
                NitroCliErrorEnum::UnspecifiedError
            )
        })?
    );

    Ok(replies)
}

pub fn console_enclaves_poweruser(args: ConsoleArgs) -> NitroCliResult<()> {
    debug!("console_enclaves");

    let mut cli_dev = CliDev::new()?;
    if !cli_dev.enable()? {
        return Err(NitroCliFailure::new()
        .add_subaction("Failed to enable cli dev".to_string())
        .set_error_code(NitroCliErrorEnum::UnspecifiedError)
        .set_file_and_line(file!(), line!()));
    }

    let slot_id = get_slot_id(args.enclave_id).map_err(|_| {
        new_nitro_cli_failure!(
            "Failed to obtain the slot id".to_string(),
            NitroCliErrorEnum::UnspecifiedError
        )
    })?;
    let slot_info = NitroEnclavesSlotInfo::new(slot_id);
    let reply = slot_info.submit(&mut cli_dev)?;
    drop(cli_dev);
    let enclave_cid = reply.enclave_cid;

    println!("Connecting to the console for enclave {}...", enclave_cid);
    enclave_console_poweruser(enclave_cid)
        .map_err(|err| {
            new_nitro_cli_failure!(
                &format!("Failed to start enclave logger: {:?}", err),
                NitroCliErrorEnum::LoggerError
            )
        })?;
    Ok(())
}

/// Connects to the enclave console and prints it continously
pub fn enclave_console_poweruser(enclave_cid: u64) -> NitroCliResult<()> {
    let console = Console::new(
        VMADDR_CID_HYPERVISOR,
        u32::try_from(enclave_cid)
            .map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to connect to the enclave: {}", err),
                    NitroCliErrorEnum::UnspecifiedError
                )
            })?
            + CID_TO_CONSOLE_PORT_OFFSET,
    )?;
    println!("Successfully connected to the console.");
    console.read_to(io::stdout().by_ref())?;

    Ok(())
}

pub fn get_enclave_describe_info(
    reply: NitroEnclavesCmdReply,
) -> NitroCliResult<EnclaveDescribeInfo> {
    let info = EnclaveDescribeInfo::new(
        generate_enclave_id(reply.slot_uid)?,
        reply.enclave_cid,
        reply.nr_cpus,
        // In the moment is not possible to retrieve the cpu_ids 
        // using the poweruser cli
        vec![],
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