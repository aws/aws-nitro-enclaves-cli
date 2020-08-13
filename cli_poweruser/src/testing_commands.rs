// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use super::cli_dev::*;

use crate::resource_allocator_driver::nitro_cli_slot_mem_region;
use crate::resource_manager::ResourceAllocator;
use crate::ExitGracefully;
use crate::NitroCliResult;
use crate::ResourceAllocatorDriver;

use clap::{App, Arg, ArgMatches, SubCommand};
use eif_loader;
use log::debug;
use num_traits::FromPrimitive;

use std::fs::OpenOptions;
use std::io::SeekFrom;
use std::io::Write;

use std::io::Read;
use std::io::Seek;

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
        SubCommand::with_name("wait-ready")
            .about("[Power user] Wait in order to receive the 'ready' signal after booting an enclave")
            .arg(
                Arg::with_name("enclave-cid")
                    .long("enclave-cid")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("vsock-ready-port")
                    .long("vsock-ready-port")
                    .takes_value(true)
                    .required(true),
            ),
    )
    .subcommand(
        SubCommand::with_name("free-slot")
            .about("[Power user] Frees resources for slot")
            .arg(
                Arg::with_name("slot-uid")
                    .long("slot-uid")
                    .takes_value(true)
                    .required(true),
            ),
    )
    .subcommand(
        SubCommand::with_name("alloc-mem")
            .about(
                "[Power user] Allocates a single memory region using the resource allocator driver",
            )
            .arg(
                Arg::with_name("mem-size")
                    .long("mem-size")
                    .takes_value(true)
                    .required(true),
            ),
    )
    .subcommand(
        SubCommand::with_name("alloc-mem-with-file")
            .about(
                "[Power user] Allocates a single memory region using the resource allocator driver and populates it with the corresponding chunk of the supplied EIF",
            )
            .arg(
                Arg::with_name("mem-size")
                    .long("mem-size")
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
                Arg::with_name("eif-offset")
                    .long("eif-offset")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("write")
                    .long("write")
                    .takes_value(false)
                    .required(false),
            ),
    )
    .subcommand(
        SubCommand::with_name("write-mem")
            .about(
                "[Power user] Write a chunk of a file to a previously-allocated physical memory region not yet owned by an enclave",
            )
            .arg(
                Arg::with_name("file-path")
                    .short("f")
                    .long("file-path")
                    .takes_value(true)
                    .required(true)
            )
            .arg(
                Arg::with_name("file-offset")
                    .short("o")
                    .long("file-offset")
                    .takes_value(true)
                    .required(true)
            )
            .arg(
                Arg::with_name("mem-address")
                    .short("a")
                    .long("mem-address")
                    .takes_value(true)
                    .required(true)
            )
            .arg(
                Arg::with_name("mem-size")
                    .short("s")
                    .long("mem-size")
                    .takes_value(true)
                    .required(true)
            )
    )
}

pub fn match_cmd(args: &ArgMatches) {
    match args.subcommand() {
        ("execute-dev-cmd", Some(args)) => {
            execute_command(args).ok_or_exit(args.usage());
        }
        ("wait-ready", Some(args)) => {
            wait_ready_signal(args).ok_or_exit(args.usage());
        }
        ("free-slot", Some(args)) => {
            free_slot(args).ok_or_exit(args.usage());
        }
        ("alloc-mem", Some(args)) => {
            alloc_mem(args).ok_or_exit(args.usage());
        }
        ("alloc-mem-with-file", Some(args)) => {
            alloc_mem_with_file(args).ok_or_exit(args.usage());
        }
        ("write-mem", Some(args)) => {
            write_mem(args).ok_or_exit(args.usage());
        }
        (&_, _) => {}
    }
}

pub fn execute_command(args: &ArgMatches) -> NitroCliResult<()> {
    let cmd_id = args
        .value_of("cmd-id")
        .unwrap_or_else(|| panic!("{}", args.usage()));
    let cmd_id: u32 = cmd_id.parse().unwrap();
    let cmd_id = NitroEnclavesCmdType::from_u32(cmd_id)
        .unwrap_or_else(|| panic!("Invalid cmd_id \n{}\n", args.usage()));
    let cmd_body = args
        .value_of("cmd-body")
        .ok_or_else(|| "Invalid cmd-body".to_string())?;
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

pub fn wait_ready_signal(args: &ArgMatches) -> NitroCliResult<()> {
    let enclave_cid = args
        .value_of("enclave-cid")
        .ok_or("enclave-cid not specified")?;
    let vsock_ready_port = args
        .value_of("vsock-ready-port")
        .ok_or("vsock-ready-port not specified")?;
    let enclave_cid: u32 = enclave_cid
        .parse()
        .map_err(|err| format!("Invalid enclave-cid format: {}", err))?;
    let vsock_ready_port: u32 = vsock_ready_port
        .parse()
        .map_err(|err| format!("Invalid vsock-ready-port specified: {}", err))?;

    let _ = eif_loader::enclave_ready(enclave_cid, vsock_ready_port).map_err(|err| {
        format!(
            "Failed to receive 'ready' signal from the enclave: {:?}",
            err
        )
    });

    Ok(())
}

pub fn free_slot(args: &ArgMatches) -> NitroCliResult<()> {
    let slot_id = args.value_of("slot-uid").ok_or("slot-uid not specified")?;

    let slot_id: u64 = slot_id
        .parse()
        .map_err(|err| format!("Invalid slot-uid format: {}", err))?;

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
        .map_err(|err| format!("Invalid mem-size format: {}", err))?;

    let mut resource_allocator = ResourceAllocator::new(0, mem_size, 1)?;
    let regions = resource_allocator.allocate()?;
    for region in regions {
        println!("mem_gpa={}\nmem_size={}", region.mem_gpa, region.mem_size)
    }
    Ok(())
}

/// Writes a specific chunk of the eif file into the supplied memory region
fn fill_region_from_file(
    region: &nitro_cli_slot_mem_region,
    eif_path: String,
    eif_offset: u64,
) -> std::io::Result<u64> {
    let mut eif_file = OpenOptions::new().read(true).open(eif_path)?;
    let mut dev_mem = OpenOptions::new().write(true).open("/dev/mem")?;
    let mut buf = [0u8; 4096];
    let mut written: u64 = 0;

    eif_file.seek(SeekFrom::Start(eif_offset))?;
    dev_mem.seek(SeekFrom::Start(region.mem_gpa))?;

    while written < region.mem_size {
        let write_size = std::cmp::min(buf.len(), (region.mem_size - written) as usize);
        let write_size = eif_file.read(&mut buf[..write_size])?;

        if write_size == 0 {
            return eif_file.seek(SeekFrom::Current(0));
        }

        dev_mem.write_all(&buf[..write_size])?;
        dev_mem.flush()?;
        written += write_size as u64;
    }

    eif_file.seek(SeekFrom::Current(0))
}

pub fn alloc_mem_with_file(args: &ArgMatches) -> NitroCliResult<()> {
    let mem_size = args
        .value_of("mem-size")
        .ok_or("memory size not specified")?;
    let eif_path = args
        .value_of("eif-path")
        .ok_or("EIF file path not specified")?;
    let eif_offset = args
        .value_of("eif-offset")
        .ok_or("offset in the EIF file not specified")?;
    let should_write = args.is_present("write");

    let mem_size: u64 = mem_size
        .parse()
        .map_err(|err| format!("Invalid mem-size format: {}", err))?;
    let eif_offset: u64 = eif_offset
        .parse()
        .map_err(|err| format!("Invalid eif-offset format: {}", err))?;

    let mut new_offset = eif_offset;
    let mut resource_allocator = ResourceAllocator::new(0, mem_size, 1)?;
    let regions = resource_allocator.allocate()?;

    for region in regions {
        if should_write {
            new_offset = fill_region_from_file(&region, eif_path.to_string(), new_offset)
                .map_err(|e| format!("fill_region_from_file failed: {}", e))?;
        }
        println!(
            "mem_gpa={}\nmem_size={}\nnew_eif_offset={}",
            region.mem_gpa, region.mem_size, new_offset
        )
    }

    Ok(())
}

pub fn write_mem(args: &ArgMatches) -> NitroCliResult<()> {
    let file_path = args
        .value_of("file-path")
        .ok_or("file path not specified")?;
    let file_offset = args
        .value_of("file-offset")
        .ok_or("file offset not specified")?
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse file offset: {}", e))?;
    let mem_address = args
        .value_of("mem-address")
        .ok_or("memory address not specified")?
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse memory address: {}", e))?;
    let mem_size = args
        .value_of("mem-size")
        .ok_or("memory size not specified")?
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse memory size: {}", e))?;
    let mem_region = nitro_cli_slot_mem_region {
        slot_uid: 0,
        mem_gpa: mem_address,
        mem_size,
    };

    fill_region_from_file(&mem_region, file_path.to_string(), file_offset)
        .map_err(|e| format!("fill_region_from_file failed: {}", e))?;
    Ok(())
}
