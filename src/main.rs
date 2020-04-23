// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use clap::{App, AppSettings, Arg, SubCommand};
use log::info;
use std::os::unix::net::UnixStream;

use nitro_cli::build_enclaves;
use nitro_cli::common::commands_parser::EmptyArgs;
use nitro_cli::common::commands_parser::{
    BuildEnclavesArgs, ConsoleArgs, RunEnclavesArgs, TerminateEnclavesArgs,
};
use nitro_cli::common::logger;
use nitro_cli::common::{create_resources_dir, enclave_proc_command_send_single, handle_signals};
use nitro_cli::common::{EnclaveProcessCommandType, ExitGracefully};
use nitro_cli::create_app;
use nitro_cli::enclave_proc_comm::{
    enclave_proc_command_send_all, enclave_proc_connect_to_single, enclave_proc_connection_close,
    enclave_proc_fetch_output, enclave_proc_spawn,
};

fn main() {
    // Command line specification for NitroEnclaves CLI.
    let logger = logger::init_logger();
    let mut replies: Vec<UnixStream> = vec![];

    // Initialize the resources directory.
    create_resources_dir().ok_or_exit("Failed to create resources directory.");

    logger.update_logger_id(format!("nitro-cli:{}", std::process::id()).as_str());
    info!("Start Nitro CLI");

    let app = create_app!();
    let args = app.get_matches();

    match args.subcommand() {
        ("run-enclave", Some(args)) => {
            handle_signals();
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
            enclave_proc_fetch_output(&replies);
            enclave_proc_connection_close(&replies);
        }
        ("terminate-enclave", Some(args)) => {
            handle_signals();
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
            enclave_proc_fetch_output(&replies);
            enclave_proc_connection_close(&replies);
        }
        ("describe-enclaves", _) => {
            // TODO: Replicate output of old CLI when no enclaves are available.
            replies.extend(
                enclave_proc_command_send_all::<EmptyArgs>(
                    &EnclaveProcessCommandType::Describe,
                    None,
                )
                .ok_or_exit("Failed to broadcast describe command."),
            );
            info!("Sent command: Describe");
            enclave_proc_fetch_output(&replies);
            enclave_proc_connection_close(&replies);
        }
        ("build-enclave", Some(args)) => {
            let build_args = BuildEnclavesArgs::new_with(args).ok_or_exit(args.usage());
            build_enclaves(build_args).ok_or_exit(args.usage());
        }
        ("console", Some(args)) => {
            let console_args = ConsoleArgs::new_with(args).ok_or_exit(args.usage());
            let mut comm = enclave_proc_connect_to_single(&console_args.enclave_id)
                .ok_or_exit("Failed to open socket.");
            // TODO: Replicate output of old CLI on invalid enclave IDs.
            enclave_proc_command_send_single::<EmptyArgs>(
                &EnclaveProcessCommandType::Console,
                None,
                &mut comm,
            )
            .ok_or_exit("Failed to send console command.");
            info!("Sent command: Console");
            replies.push(comm);
            enclave_proc_fetch_output(&replies);
            enclave_proc_connection_close(&replies);
        }
        (&_, _) => {}
    }
}
