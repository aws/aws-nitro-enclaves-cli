// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use clap::{App, AppSettings, Arg, SubCommand};
use log::info;
use std::os::unix::net::UnixStream;

use nitro_cli::common::commands_parser::{
    BuildEnclavesArgs, ConsoleArgs, EmptyArgs, RunEnclavesArgs, TerminateEnclavesArgs,
};
use nitro_cli::common::{enclave_proc_command_send_single, logger};
use nitro_cli::common::{EnclaveProcessCommandType, ExitGracefully};
use nitro_cli::enclave_proc_comm::{
    enclave_proc_command_send_all, enclave_proc_connect_to_single, enclave_proc_fetch_output,
    enclave_proc_get_cid, enclave_proc_output_failed_conns, enclave_proc_spawn,
};
use nitro_cli::{build_enclaves, console_enclaves, create_app};

fn main() {
    // Command line specification for NitroEnclaves CLI.
    let app = create_app!();
    let args = app.get_matches();
    let logger = logger::init_logger();
    let mut replies: Vec<UnixStream> = vec![];

    logger.update_logger_id(format!("nitro-cli:{}", std::process::id()).as_str());
    info!("Start Nitro CLI");

    match args.subcommand() {
        ("run-enclave", Some(args)) => {
            let run_args = RunEnclavesArgs::new_with(args).ok_or_exit(args.usage());
            let mut comm =
                enclave_proc_spawn(&logger).ok_or_exit("Enclave process spawning failed.");

            enclave_proc_command_send_single(
                &EnclaveProcessCommandType::Run,
                Some(&run_args),
                &mut comm,
            )
            .ok_or_exit("Failed to send single command.");
            info!("Sent command: Run");
            replies.push(comm);

            let empty_conns = enclave_proc_fetch_output(&replies[..]);
            enclave_proc_output_failed_conns(empty_conns);
        }
        ("terminate-enclave", Some(args)) => {
            let terminate_args = TerminateEnclavesArgs::new_with(args).ok_or_exit(args.usage());
            let mut comm = enclave_proc_connect_to_single(&terminate_args.enclave_id)
                .ok_or_exit("Failed to open socket.");
            // TODO: Replicate output of old CLI on invalid enclave IDs.
            enclave_proc_command_send_single::<EmptyArgs>(
                &EnclaveProcessCommandType::Terminate,
                None,
                &mut comm,
            )
            .ok_or_exit("Failed to send terminate command.");
            info!("Sent command: Terminate");
            replies.push(comm);

            let empty_conns = enclave_proc_fetch_output(&replies[..]);
            enclave_proc_output_failed_conns(empty_conns);
        }
        ("describe-enclaves", _) => {
            let (comms, comm_errors) = enclave_proc_command_send_all::<EmptyArgs>(
                &EnclaveProcessCommandType::Describe,
                None,
            )
            .ok_or_exit("Failed to broadcast describe command.");
            replies.extend(comms);
            info!("Sent command: Describe");

            let empty_conns = enclave_proc_fetch_output(&replies[..]);
            enclave_proc_output_failed_conns(comm_errors + empty_conns);

            // If no connection could be read, print an empty JSON array.
            if replies.len() == empty_conns {
                println!("[]");
            }
        }
        ("build-enclave", Some(args)) => {
            let build_args = BuildEnclavesArgs::new_with(args).ok_or_exit(args.usage());
            build_enclaves(build_args).ok_or_exit(args.usage());
        }
        ("console", Some(args)) => {
            let console_args = ConsoleArgs::new_with(args).ok_or_exit(args.usage());
            let enclave_cid = enclave_proc_get_cid(&console_args.enclave_id)
                .ok_or_exit("Failed to read enclave CID.");
            console_enclaves(enclave_cid).ok_or_exit(args.usage());
        }
        (&_, _) => {}
    }
}
