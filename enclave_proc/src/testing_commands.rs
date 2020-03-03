// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use super::cli_dev::*;

use crate::resource_manager::ResourceAllocator;
use crate::ExitGracefully;
use crate::NitroCliResult;
use crate::ResourceAllocatorDriver;
use clap::{App, Arg, ArgMatches, SubCommand};
use eif_loader;
use log::debug;
use num_traits::FromPrimitive;
use std::fs::File;

pub fn match_cmd(args: &ArgMatches) {
    match args.subcommand() {
        ("execute-dev-cmd", Some(args)) => {
            execute_command(args).ok_or_exit(args.usage());
        }
        ("send-image", Some(args)) => {
            send_eif(args).ok_or_exit(args.usage());
        }
        ("free-slot", Some(args)) => {
            free_slot(args).ok_or_exit(args.usage());
        }
        ("alloc-mem", Some(args)) => {
            alloc_mem(args).ok_or_exit(args.usage());
        }
        (&_, _) => {}
    }
}

pub fn execute_command(args: &ArgMatches) -> NitroCliResult<()> {
    let cmd_id = args.value_of("cmd-id").expect(args.usage());
    let cmd_id: u32 = cmd_id.parse().unwrap();
    let cmd_id = NitroEnclavesCmdType::from_u32(cmd_id)
        .expect(&format!("Invalid cmd_id \n{}\n", args.usage()));
    let cmd_body = args
        .value_of("cmd-body")
        .ok_or("Invalid cmd-body".to_string())?;
    let mut cli = CliDev::new()?;
    cli.enable()?;
    let reply = match cmd_id {
        NitroEnclavesCmdType::NitroEnclavesEnclaveStart => {
            let cmd: NitroEnclavesEnclaveStart = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesGetSlot => {
            let cmd: NitroEnclavesGetSlot = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesEnclaveStop => {
            let cmd: NitroEnclavesEnclaveStop = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesSlotAlloc => {
            let cmd: NitroEnclavesSlotAlloc = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesSlotFree => {
            let cmd: NitroEnclavesSlotFree = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesSlotAddMem => {
            let cmd: NitroEnclavesSlotAddMem = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesSlotAddVcpu => {
            let cmd: NitroEnclavesSlotAddVcpu = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesSlotCount => {
            let cmd: NitroEnclavesSlotCount = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesNextSlot => {
            let cmd: NitroEnclavesNextSlot = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesSlotInfo => {
            let cmd: NitroEnclavesSlotInfo = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesSlotAddBulkVcpu => {
            let cmd: NitroEnclavesSlotAddBulkVcpu = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesDestroy => {
            let cmd: NitroEnclavesDestroy = serde_json::from_str(cmd_body)
                .map_err(|err| format!("Invalid json format for command: {}", err))?;
            cmd.submit(&mut cli)
        }
        NitroEnclavesCmdType::NitroEnclavesMaxCmd => {
            panic!(format!("\n Max command{}\n", args.usage()));
        }
        NitroEnclavesCmdType::NitroEnclavesInvalidCmd => {
            panic!(format!("\n Invalid cmd {}\n", args.usage()));
        }
    }?;
    debug!("CmdReply {:?}", reply);
    Ok(())
}

pub fn send_eif(args: &ArgMatches) -> NitroCliResult<()> {
    let enclave_cid = args
        .value_of("enclave-cid")
        .ok_or("enclave-cid not specified")?;
    let enclave_port = args
        .value_of("loader-port")
        .ok_or("loader-port not specified")?;
    let enclave_token = args.value_of("token").ok_or("token not specified")?;
    let eif_path = args.value_of("eif-path").ok_or("eif-path  not specified")?;
    let mut eif_image =
        File::open(eif_path).map_err(|err| format!("Could not open eif image: {:?}", err))?;

    let enclave_cid: u32 = enclave_cid
        .parse()
        .map_err(|_| format!("Invalid enclave-cid format"))?;

    let enclave_port: u32 = enclave_port
        .parse()
        .map_err(|_| format!("Invalid enclave-port format"))?;

    let enclave_token: u64 = enclave_token
        .parse()
        .map_err(|_| format!("Invalid token format"))?;

    eif_loader::send_image(
        &mut eif_image,
        enclave_cid,
        enclave_port,
        enclave_token.to_be_bytes(),
        crate::resource_manager::between_packets_delay(),
    )
    .map_err(|err| format!("Failed to send eif Image: {:?}", err))?;
    Ok(())
}

pub fn free_slot(args: &ArgMatches) -> NitroCliResult<()> {
    let slot_id = args.value_of("slot-uid").ok_or("slot-uid not specified")?;

    let slot_id: u64 = slot_id
        .parse()
        .map_err(|_| format!("Invalid slot-uid format"))?;

    let mut cli_dev = CliDev::new()?;

    let slot_free = NitroEnclavesSlotFree::new(slot_id);
    slot_free.submit(&mut cli_dev)?;

    let resource_allocator_driver = ResourceAllocatorDriver::new()?;
    resource_allocator_driver.free(slot_id)?;
    Ok(())
}

pub fn alloc_mem(args: &ArgMatches) -> NitroCliResult<()> {
    let mem_size = args
        .value_of("mem-size")
        .ok_or("memory size not specified")?;

    let mem_size: u64 = mem_size
        .parse()
        .map_err(|_| format!("Invalid mem-size format"))?;

    let mut resource_allocator = ResourceAllocator::new(0, mem_size, 1)?;
    let regions = resource_allocator.allocate()?;
    for region in regions {
        println!("mem_gpa={}\nmem_size={}", region.mem_gpa, region.mem_size)
    }
    Ok(())
}
