// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::debug;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{self, Write};

use crate::common::commands_parser::{
    ConsoleArgs, DescribeEnclaveArgs, RunEnclavesArgs, TerminateEnclavesArgs,
};
use crate::common::NitroCliResult;
use crate::enclave_proc::cli_dev::{
    CliDev, NitroEnclavesCmdReply, NitroEnclavesEnclaveStop, NitroEnclavesNextSlot,
    NitroEnclavesSlotCount, NitroEnclavesSlotFree, NitroEnclavesSlotInfo,
};
use crate::enclave_proc::cpu_info::CpuInfos;
use crate::enclave_proc::json_output::EnclaveDescribeInfo;
use crate::enclave_proc::json_output::{
    get_enclave_describe_info, get_enclave_id, get_run_enclaves_info,
};
use crate::enclave_proc::resource_allocator_driver::ResourceAllocatorDriver;
use crate::enclave_proc::resource_manager::online_slot_cpus;
use crate::enclave_proc::resource_manager::EnclaveResourceManager;
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

pub fn run_enclaves(args: RunEnclavesArgs) -> NitroCliResult<String> {
    let eif_file = File::open(&args.eif_path)
        .map_err(|err| format!("Failed to open the eif file: {:?}", err))?;

    let cpu_infos = CpuInfos::new()?;
    let cpu_ids = if let Some(cpu_ids) = args.cpu_ids {
        cpu_infos.check_cpu_ids(&cpu_ids)?;
        Some(cpu_ids)
    } else if let Some(cpu_count) = args.cpu_count {
        Some(cpu_infos.get_cpu_ids(cpu_count)?)
    } else {
        // Should not happen
        None
    };

    let mut resource_manager = EnclaveResourceManager::new(
        args.enclave_cid,
        args.memory_mib,
        cpu_ids.unwrap(),
        eif_file,
        args.debug_mode.unwrap_or(false),
    )
    .map_err(|err| format!("Could not create enclave: {:?}", err))?;
    let (enclave_cid, slot_id) = resource_manager.create_enclave()?;

    let cpu_ids = resource_manager.cpu_ids.clone();
    let memory = resource_manager.allocated_memory_mib;

    let info = get_run_enclaves_info(enclave_cid, slot_id, cpu_ids, memory)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&info).map_err(|err| format!("{:?}", err))?
    );

    Ok(get_enclave_id(&info))
}

pub fn terminate_enclaves(terminate_args: TerminateEnclavesArgs) -> NitroCliResult<()> {
    debug!("terminate_enclaves");

    let mut cli_dev = CliDev::new()?;
    if !cli_dev.enable()? {
        return Err("Failed to enable cli dev".to_string());
    }

    let enclave_id = terminate_args.enclave_id.clone();
    let slot_id = get_slot_id(terminate_args.enclave_id)?;

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

pub fn describe_enclaves(
    _describe_args: DescribeEnclaveArgs,
) -> NitroCliResult<Vec<NitroEnclavesCmdReply>> {
    debug!("describe_enclaves");
    let mut cli_dev = CliDev::new()?;
    if !cli_dev.enable()? {
        return Err("Failed to enable the CLI device".to_string());
    }
    let slot_count = NitroEnclavesSlotCount::new();
    let reply = slot_count.submit(&mut cli_dev)?;

    let num_slots = reply.slot_count;

    let mut current_slot = 0;
    let mut replies: Vec<NitroEnclavesCmdReply> = Vec::new();
    let mut infos: Vec<EnclaveDescribeInfo> = Vec::new();

    for _i in { 0..num_slots } {
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
        serde_json::to_string_pretty(&infos).map_err(|err| format!("{:?}", err))?
    );

    Ok(replies)
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
