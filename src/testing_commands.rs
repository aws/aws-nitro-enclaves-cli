// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use clap::{App, Arg, ArgMatches, SubCommand};
use log::debug;
use num_traits::FromPrimitive;
use std::fs::File;

use super::cli_dev::*;
use crate::common::{ExitGracefully, NitroCliResult};
use crate::resource_manager::ResourceAllocator;
use crate::ResourceAllocatorDriver;
use crate::{ENCLAVE_READY_VSOCK_PORT, VMADDR_CID_PARENT};
use eif_loader;

pub fn initialize<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.subcommand(
        SubCommand::with_name("execute-dev-cmd")
            .about("[Power user] Executes the given command on the cli device")
            .after_help(
                r#" Examples for starting an enclave:
./nitro-cli execute-dev-cmd --cmd-id 4 --cmd-body '{}'
./nitro-cli execute-dev-cmd --cmd-id 6 --cmd-body '{"slot_uid":0,"paddr":335544320,"size":67108864}'

./nitro-cli execute-dev-cmd --cmd-id 7 --cmd-body '{"slot_uid":0,"cpu_id":2}'
./nitro-cli execute-dev-cmd --cmd-id 7 --cmd-body '{"slot_uid":0,"cpu_id":3}'
./nitro-cli execute-dev-cmd --cmd-id 1 --cmd-body '{"slot_uid":0,"enclave_cid":10000}'
./nitro-cli send-image --eif-path from_docker.eif --enclave-cid 10000 --loader-port 7000"#,
            )
            .arg(
                Arg::with_name("cmd-id")
                    .long("cmd-id")
                    .help("Commands id as defined by the cli-dev")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("cmd-body")
                    .help("Command body in json format")
                    .long("cmd-body")
                    .takes_value(true)
                    .required(true),
            ),
    )
    .subcommand(
        SubCommand::with_name("send-image")
            .about("[Power user] Sends boot image to an enclave")
            .arg(
                Arg::with_name("enclave-cid")
                    .long("enclave-cid")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("eif-path")
                    .long("eif-path")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("loader-port")
                    .long("loader-port")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("token")
                    .long("token")
                    .takes_value(true)
                    .required(true),
            ),
    )
    .subcommand(
        SubCommand::with_name("free-slot")
            .about("[Power user] Frees resources for slot ")
            .arg(
                Arg::with_name("slot-uid")
                    .long("slot-uid")
                    .takes_value(true)
                    .required(true),
            ),
    )
    .subcommand(
        SubCommand::with_name("alloc-mem")
            .about("[Power user] Allocates a single memory region using the resource allocator driver ")
            .arg(
                Arg::with_name("mem-size")
                    .long("mem-size")
                    .takes_value(true)
                    .required(true),
            ),
    )
}

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

    eif_loader::enclave_ready(VMADDR_CID_PARENT, ENCLAVE_READY_VSOCK_PORT)
        .map_err(|err| format!("Waiting on enclave to boot failed with error {:?}", err))?;
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
