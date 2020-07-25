// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

//! This is the entry point for the Nitro CLI process.

use clap::{App, AppSettings, Arg, SubCommand};
use log::info;
use std::os::unix::net::UnixStream;

use nitro_cli::common::commands_parser::{
    BuildEnclavesArgs, ConsoleArgs, EmptyArgs, RunEnclavesArgs, TerminateEnclavesArgs,
};
use nitro_cli::common::json_output::{EnclaveDescribeInfo, EnclaveRunInfo, EnclaveTerminateInfo};
use nitro_cli::common::{enclave_proc_command_send_single, logger};
use nitro_cli::common::{EnclaveProcessCommandType, ExitGracefully};
use nitro_cli::enclave_proc_comm::{
    enclave_proc_command_send_all, enclave_proc_connect_to_single, enclave_proc_get_cid,
    enclave_proc_spawn, enclave_process_handle_all_replies,
};
use nitro_cli::{build_enclaves, console_enclaves, create_app, terminate_all_enclaves};

/// *Nitro CLI* application entry point.
fn main() {
    // Custom version (possibly including build commit).
    // Dummy code line to trigger CI tests
    let commit_id = env!("COMMIT_ID");
    let version_str: String = match commit_id.len() {
        0 => env!("CARGO_PKG_VERSION").to_string(),
        _ => format!(
            "{} (build commit: {})",
            env!("CARGO_PKG_VERSION"),
            commit_id
        ),
    };

    // Command-line specification for the Nitro CLI.
    let mut app = create_app!();
    app = app.version(&*version_str);
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
                EnclaveProcessCommandType::Run,
                Some(&run_args),
                &mut comm,
            )
            .ok_or_exit("Failed to send single command.");

            info!("Sent command: Run");
            replies.push(comm);
            enclave_process_handle_all_replies::<EnclaveRunInfo>(&mut replies, 0, false, vec![0])
                .ok_or_exit(args.usage());
        }
        ("terminate-enclave", Some(args)) => {
            if args.is_present("all") {
                terminate_all_enclaves().ok_or_exit(
                    "Failed to terminate all running enclaves belonging to current user.",
                );
            } else {
                let terminate_args = TerminateEnclavesArgs::new_with(args).ok_or_exit(args.usage());
                let mut comm = enclave_proc_connect_to_single(&terminate_args.enclave_id)
                    .ok_or_exit("Failed to open socket.");
                // TODO: Replicate output of old CLI on invalid enclave IDs.
                enclave_proc_command_send_single::<EmptyArgs>(
                    EnclaveProcessCommandType::Terminate,
                    None,
                    &mut comm,
                )
                .ok_or_exit("Failed to send terminate command.");

                info!("Sent command: Terminate");
                replies.push(comm);
                enclave_process_handle_all_replies::<EnclaveTerminateInfo>(
                    &mut replies,
                    0,
                    false,
                    vec![0],
                )
                .ok_or_exit(args.usage());
            }
        }
        ("describe-enclaves", _) => {
            let (comms, comm_errors) = enclave_proc_command_send_all::<EmptyArgs>(
                EnclaveProcessCommandType::Describe,
                None,
            )
            .ok_or_exit("Failed to broadcast describe command.");

            info!("Sent command: Describe");
            replies.extend(comms);
            enclave_process_handle_all_replies::<EnclaveDescribeInfo>(
                &mut replies,
                comm_errors,
                true,
                vec![0],
            )
            .ok_or_exit(args.usage());
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
