// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
#![deny(warnings)]

//! This is the entry point for the Nitro CLI process.

extern crate lazy_static;

use clap::{App, AppSettings, Arg, SubCommand};
use log::info;
use std::os::unix::net::UnixStream;

use nitro_cli::common::commands_parser::{
    BuildEnclavesArgs, ConsoleArgs, DescribeEnclavesArgs, EmptyArgs, ExplainArgs, PcrArgs,
    RunEnclavesArgs, TerminateEnclavesArgs,
};
use nitro_cli::common::document_errors::explain_error;
use nitro_cli::common::json_output::{EnclaveDescribeInfo, EnclaveRunInfo, EnclaveTerminateInfo};
use nitro_cli::common::{
    enclave_proc_command_send_single, logger, NitroCliErrorEnum, NitroCliFailure, NitroCliResult,
};
use nitro_cli::common::{EnclaveProcessCommandType, ExitGracefully};
use nitro_cli::enclave_proc::resource_manager::NE_ENCLAVE_DEBUG_MODE;
use nitro_cli::enclave_proc_comm::{
    enclave_proc_command_send_all, enclave_proc_connect_to_single, enclave_proc_get_cid,
    enclave_proc_get_flags, enclave_proc_spawn, enclave_process_handle_all_replies,
};
use nitro_cli::{
    build_enclaves, console_enclaves, create_app, describe_eif, get_all_enclave_names,
    get_file_pcr, new_enclave_name, new_nitro_cli_failure, terminate_all_enclaves,
};

const RUN_ENCLAVE_STR: &str = "Run Enclave";
const DESCRIBE_ENCLAVE_STR: &str = "Describe Enclave";
const DESCRIBE_EIF_STR: &str = "Describe EIF";
const TERMINATE_ENCLAVE_STR: &str = "Terminate Enclave";
const TERMINATE_ALL_ENCLAVES_STR: &str = "Terminate All Enclaves";
const BUILD_ENCLAVE_STR: &str = "Build Enclave";
const ENCLAVE_CONSOLE_STR: &str = "Enclave Console";
const EXPLAIN_ERR_STR: &str = "Explain Error";
const NEW_NAME_STR: &str = "New Enclave Name";
const FILE_PCR_STR: &str = "File PCR";

/// *Nitro CLI* application entry point.
fn main() {
    let version_str: String = env!("CARGO_PKG_VERSION").to_string();

    // Command-line specification for the Nitro CLI.
    let mut app = create_app!();
    app = app.version(&*version_str);
    let args = app.get_matches();
    let logger = logger::init_logger()
        .map_err(|e| e.set_action("Logger initialization".to_string()))
        .ok_or_exit_with_errno(None);
    let mut replies: Vec<UnixStream> = vec![];

    logger
        .update_logger_id(format!("nitro-cli:{}", std::process::id()).as_str())
        .map_err(|e| e.set_action("Update CLI Process Logger ID".to_string()))
        .ok_or_exit_with_errno(None);
    info!("Start Nitro CLI");

    match args.subcommand() {
        Some(("run-enclave", args)) => {
            let mut run_args = RunEnclavesArgs::new_with(args)
                .map_err(|err| {
                    err.add_subaction("Failed to construct RunEnclave arguments".to_string())
                        .set_action(RUN_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            let mut comm = enclave_proc_spawn(&logger)
                .map_err(|err| {
                    err.add_subaction("Failed to spawn enclave process".to_string())
                        .set_action(RUN_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);

            let names = get_all_enclave_names()
                .map_err(|e| {
                    e.add_subaction("Failed to handle all enclave process replies".to_string())
                        .set_action("Get Enclaves Name".to_string())
                })
                .ok_or_exit_with_errno(None);
            run_args.enclave_name = Some(
                new_enclave_name(run_args.clone(), names)
                    .map_err(|err| {
                        err.add_subaction("Failed to assign a new enclave name".to_string())
                            .set_action(NEW_NAME_STR.to_string())
                    })
                    .ok_or_exit_with_errno(None),
            );

            enclave_proc_command_send_single(
                EnclaveProcessCommandType::Run,
                Some(&run_args),
                &mut comm,
            )
            .map_err(|e| {
                e.add_subaction("Failed to send single command".to_string())
                    .set_action(RUN_ENCLAVE_STR.to_string())
            })
            .ok_or_exit_with_errno(None);

            info!("Sent command: Run");
            replies.push(comm);
            let run_info = enclave_process_handle_all_replies::<EnclaveRunInfo>(
                &mut replies,
                0,
                false,
                vec![0],
            )
            .map_err(|e| {
                e.add_subaction("Failed to handle all enclave process replies".to_string())
                    .set_action(RUN_ENCLAVE_STR.to_string())
            })
            .ok_or_exit_with_errno(None);
            let enclave_cid = run_info
                .first()
                .map(|run_info| run_info.enclave_cid)
                .ok_or_else(|| {
                    new_nitro_cli_failure!(
                        "Enclave CID was not reported",
                        NitroCliErrorEnum::EnclaveConsoleConnectionFailure
                    )
                })
                .ok_or_exit_with_errno(None);
            if run_args.attach_console {
                console_enclaves(enclave_cid, None)
                    .map_err(|e| {
                        e.add_subaction("Failed to connect to enclave console".to_string())
                            .set_action(ENCLAVE_CONSOLE_STR.to_string())
                    })
                    .ok_or_exit_with_errno(None);
            }
        }
        Some(("terminate-enclave", args)) => {
            if args.is_present("all") {
                terminate_all_enclaves()
                    .map_err(|e| {
                        e.add_subaction("Failed to terminate all running enclaves".to_string())
                            .set_action(TERMINATE_ALL_ENCLAVES_STR.to_string())
                    })
                    .ok_or_exit_with_errno(None);
            } else {
                let terminate_args = TerminateEnclavesArgs::new_with(args)
                    .map_err(|err| {
                        err.add_subaction(
                            "Failed to construct TerminateEnclave arguments".to_string(),
                        )
                        .set_action(TERMINATE_ENCLAVE_STR.to_string())
                    })
                    .ok_or_exit_with_errno(None);
                let mut comm = enclave_proc_connect_to_single(&terminate_args.enclave_id)
                    .map_err(|e| {
                        e.add_subaction("Failed to connect to enclave process".to_string())
                            .set_action(TERMINATE_ENCLAVE_STR.to_string())
                    })
                    .ok_or_exit_with_errno(None);
                // TODO: Replicate output of old CLI on invalid enclave IDs.
                enclave_proc_command_send_single::<EmptyArgs>(
                    EnclaveProcessCommandType::Terminate,
                    None,
                    &mut comm,
                )
                .map_err(|e| {
                    e.add_subaction("Failed to send single command".to_string())
                        .set_action(TERMINATE_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);

                info!("Sent command: Terminate");
                replies.push(comm);
                enclave_process_handle_all_replies::<EnclaveTerminateInfo>(
                    &mut replies,
                    0,
                    false,
                    vec![0],
                )
                .map_err(|e| {
                    e.add_subaction("Failed to handle all enclave process replies".to_string())
                        .set_action(TERMINATE_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            }
        }
        Some(("describe-enclaves", args)) => {
            let describe_args = DescribeEnclavesArgs::new_with(args);
            let (comms, comm_errors) = enclave_proc_command_send_all::<DescribeEnclavesArgs>(
                EnclaveProcessCommandType::Describe,
                Some(&describe_args),
            )
            .map_err(|e| {
                e.add_subaction(
                    "Failed to send DescribeEnclave command to all enclave processes".to_string(),
                )
                .set_action(DESCRIBE_ENCLAVE_STR.to_string())
            })
            .ok_or_exit_with_errno(None);

            info!("Sent command: Describe");
            replies.extend(comms);
            enclave_process_handle_all_replies::<EnclaveDescribeInfo>(
                &mut replies,
                comm_errors,
                true,
                vec![0],
            )
            .map_err(|e| {
                e.add_subaction("Failed to handle all enclave process replies".to_string())
                    .set_action(DESCRIBE_ENCLAVE_STR.to_string())
            })
            .ok_or_exit_with_errno(None);
        }
        Some(("build-enclave", args)) => {
            let build_args = BuildEnclavesArgs::new_with(args)
                .map_err(|e| {
                    e.add_subaction("Failed to construct BuildEnclave arguments".to_string())
                        .set_action(BUILD_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            build_enclaves(build_args)
                .map_err(|e| {
                    e.add_subaction("Failed to build enclave".to_string())
                        .set_action(BUILD_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
        }
        Some(("describe-eif", args)) => {
            let eif_path = args
                .value_of("eif-path")
                .map(|val| val.to_string())
                .unwrap();
            describe_eif(eif_path)
                .map_err(|e| {
                    e.add_subaction("Failed to describe EIF".to_string())
                        .set_action(DESCRIBE_EIF_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
        }
        Some(("console", args)) => {
            let console_args = ConsoleArgs::new_with(args)
                .map_err(|e| {
                    e.add_subaction("Failed to construct Console arguments".to_string())
                        .set_action(ENCLAVE_CONSOLE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            let enclave_cid = enclave_proc_get_cid(&console_args.enclave_id)
                .map_err(|e| {
                    e.add_subaction("Failed to retrieve enclave CID".to_string())
                        .set_action(ENCLAVE_CONSOLE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            let enclave_flags = enclave_proc_get_flags(&console_args.enclave_id)
                .map_err(|e| {
                    e.add_subaction("Failed to retrieve enclave flags".to_string())
                        .set_action(ENCLAVE_CONSOLE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            if enclave_flags & NE_ENCLAVE_DEBUG_MODE == 0 {
                let _result : NitroCliResult<()> = Err(new_nitro_cli_failure!(
                    "The enclave was not started with the debug flag set, include '--debug-mode' in the run-enclave command",
                    NitroCliErrorEnum::EnclaveConsoleConnectionFailure
                ))
                .map_err(|e| {
                    e.add_subaction("Failed to connect to enclave console".to_string())
                        .set_action(ENCLAVE_CONSOLE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            }

            console_enclaves(enclave_cid, console_args.disconnect_timeout_sec)
                .map_err(|e| {
                    e.add_subaction("Failed to connect to enclave console".to_string())
                        .set_action(ENCLAVE_CONSOLE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
        }
        Some(("pcr", args)) => {
            let pcr_args = PcrArgs::new_with(args)
                .map_err(|e| {
                    e.add_subaction("Failed to construct PCR arguments".to_string())
                        .set_action(FILE_PCR_STR.to_string())
                })
                .ok_or_exit_with_errno(None);

            get_file_pcr(pcr_args.path, pcr_args.pcr_type)
                .map_err(|e| {
                    e.add_subaction("Failed to get the PCR hash of the file contents".to_string())
                        .set_action(FILE_PCR_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
        }
        Some(("explain", args)) => {
            let explain_args = ExplainArgs::new_with(args)
                .map_err(|e| {
                    e.add_subaction("Failed to construct Explain arguments".to_string())
                        .set_action(EXPLAIN_ERR_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            explain_error(explain_args.error_code_str);
        }
        Some((&_, _)) | None => (),
    }
}
