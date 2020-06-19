// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

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

use commands_parser::{ConsoleArgs, DescribeEnclaveArgs, RunEnclavesArgs, TerminateEnclavesArgs};
use resource_allocator_driver::ResourceAllocatorDriver;
use resource_manager::EnclaveResourceManager;

use crate::cli_dev::{
    CliDev, NitroEnclavesCmdReply, NitroEnclavesEnclaveStop, NitroEnclavesNextSlot,
    NitroEnclavesSlotCount, NitroEnclavesSlotFree, NitroEnclavesSlotInfo,
};
use std::io::{self, Write};
use utils::ExitGracefully;

use crate::resource_manager::online_slot_cpus;
use std::convert::TryFrom;
use utils::get_slot_id;
use utils::Console;

use crate::cpu_info::CpuInfos;
use crate::json_output::EnclaveDescribeInfo;
use crate::json_output::{get_enclave_describe_info, get_run_enclaves_info};

// Hypervisor cid as defined by:
// http://man7.org/linux/man-pages/man7/vsock.7.html
pub const VMADDR_CID_HYPERVISOR: u32 = 0;
pub const VMADDR_CID_PARENT: u32 = 3;
pub const CID_TO_CONSOLE_PORT_OFFSET: u32 = 10000;
pub const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;
pub const BUFFER_SIZE: usize = 1024;
pub type NitroCliResult<T> = Result<T, String>;

pub fn run_enclaves(args: RunEnclavesArgs) -> NitroCliResult<u64> {
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

    Ok(enclave_cid)
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

#[macro_export]
macro_rules! create_app {
    () => {
        App::new("Nitro CLI (Power-user)")
            .about("CLI for Nitro Enclaves device validation")
            .setting(AppSettings::ArgRequiredElseHelp)
            .version(env!("CARGO_PKG_VERSION"))
            .subcommand(
                SubCommand::with_name("run-enclave")
                    .about("Starts a new enclave")
                    .arg(
                        Arg::with_name("cpu-ids")
                            .long("cpu-ids")
                            .help("List of cpu-ids that will be provided to the enclave")
                            .takes_value(true)
                            .multiple(true)
                            .min_values(1)
                            .required_unless("cpu-count")
                            .conflicts_with("cpu-count"),
                    )
                    .arg(
                        Arg::with_name("cpu-count")
                            .long("cpu-count")
                            .help("Number of cpus")
                            .takes_value(true)
                            .required_unless("cpu-ids")
                            .conflicts_with("cpu-ids"),
                    )
                    .arg(
                        Arg::with_name("memory")
                            .long("memory")
                            .help("Memory to allocate for the enclave in MB")
                            .required(true)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::with_name("eif-path")
                            .long("eif-path")
                            .help("Path pointing to a prebuilt Eif image")
                            .required(true)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::with_name("enclave-cid")
                            .long("enclave-cid")
                            .takes_value(true)
                            .help("CID to be used for the newly started enclave"),
                    )
                    .arg(
                        Arg::with_name("debug-mode")
                            .long("debug-mode")
                            .takes_value(false)
                            .help(
                                "Starts enclave in debug-mode. This makes the console of the enclave \
                                available over vsock at CID: VMADDR_CID_HYPERVISOR (0), port: \
                                enclave_cid + 10000. \n The stream could be accessed with the console \
                                sub-command" ,
                            ),
                    ),
            )
            .subcommand(
                SubCommand::with_name("terminate-enclave")
                    .about("Terminates an enclave")
                    .arg(
                        Arg::with_name("enclave-id")
                            .long("enclave-id")
                            .takes_value(true)
                            .help("Enclave ID, used to uniquely identify an enclave")
                            .required(true),
                    ),
            )
            .subcommand(
                SubCommand::with_name("describe-enclaves")
                    .about("Returns a list of the running enclaves"),
            )
            .subcommand(
                SubCommand::with_name("console")
                    .about("Connect to the console of an enclave")
                    .arg(
                        Arg::with_name("enclave-id")
                            .long("enclave-id")
                            .takes_value(true)
                            .help("Enclave ID, used to uniquely identify an enclave")
                            .required(true),
                    ),
            )
    };
}
