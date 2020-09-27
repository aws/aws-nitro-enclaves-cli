// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
#![deny(warnings)]

//! This is the entry point for the Nitro CLI process.

use clap::{App, AppSettings, Arg, SubCommand};

use enclave_api::common::document_errors::explain_error;
use enclave_api::common::json_output::{EnclaveDescribeInfo, EnclaveRunInfo, EnclaveTerminateInfo};
use enclave_api::common::{ExitGracefully, NitroCliErrorEnum, NitroCliFailure};
use enclave_api::enclave_proc_comm::enclave_proc_get_cid;
use enclave_api::new_nitro_cli_failure;
use enclave_api::{Enclave, EnclaveConf, EnclaveCpuConfig, EnclaveFlags};

use nitro_cli::commands_parser::{
    BuildEnclavesArgs, ConsoleArgs, ExplainArgs, RunEnclavesArgs, TerminateEnclavesArgs,
};
use nitro_cli::{build_enclaves, console_enclaves, create_app};

fn terminate_enclave_print(enclave_id: &str) {
    Enclave::terminate_id(&enclave_id)
        .map_err(|e| {
            e.add_subaction("Failed to terminate enclave".to_string())
                .set_action(TERMINATE_ENCLAVE_STR.to_string())
        })
        .ok_or_exit_with_errno(None);
    let enclave_terminate_info = EnclaveTerminateInfo {
        enclave_id: enclave_id.to_string(),
        terminated: true,
    };
    let enclave_terminate_info_string = serde_json::to_string_pretty(&enclave_terminate_info)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!(
                    "Failed to parse terminate enclave message from enclave process: {:}",
                    e
                ),
                NitroCliErrorEnum::SerdeError
            )
            .set_action(TERMINATE_ENCLAVE_STR.to_string())
        })
        .ok_or_exit_with_errno(None);
    println!("{}", enclave_terminate_info_string);
}

const RUN_ENCLAVE_STR: &str = "Run Enclave";
const DESCRIBE_ENCLAVE_STR: &str = "Describe Enclave";
const TERMINATE_ENCLAVE_STR: &str = "Terminate Enclave";
const TERMINATE_ALL_ENCLAVES_STR: &str = "Terminate All Enclaves";
const BUILD_ENCLAVE_STR: &str = "Build Enclave";
const ENCLAVE_CONSOLE_STR: &str = "Enclave Console";
const EXPLAIN_ERR_STR: &str = "Explain Error";

/// *Nitro CLI* application entry point.
fn main() {
    // Custom version (possibly including build commit).
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

    match args.subcommand() {
        ("run-enclave", Some(args)) => {
            let run_args = RunEnclavesArgs::new_with(args)
                .map_err(|err| {
                    err.add_subaction("Failed to construct RunEnclave arguments".to_string())
                        .set_action(RUN_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            let conf = EnclaveConf {
                eif_path: run_args.eif_path,
                mem_size: run_args.memory_mib,
                cpu_conf: {
                    if run_args.cpu_count.is_some() {
                        EnclaveCpuConfig::Count(run_args.cpu_count.unwrap())
                    } else {
                        EnclaveCpuConfig::List(run_args.cpu_ids.unwrap())
                    }
                },
                cid: run_args.enclave_cid,
                flags: {
                    if run_args.debug_mode.is_some() {
                        EnclaveFlags::DEBUG_MODE
                    } else {
                        EnclaveFlags::NONE
                    }
                },
            };

            let enclave = Enclave::run(conf)
                .map_err(|e| {
                    e.add_subaction("Failed to run enclave".to_string())
                        .set_action(RUN_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            let enclave_run_info: EnclaveRunInfo = enclave.into();
            let run_info_string = serde_json::to_string_pretty(&enclave_run_info)
                .map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!(
                            "Failed to parse run enclave message from enclave process: {:}",
                            e
                        ),
                        NitroCliErrorEnum::SerdeError
                    )
                    .set_action(RUN_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            println!("{}", run_info_string);
        }
        ("terminate-enclave", Some(args)) => {
            if args.is_present("all") {
                let enclave_ids = Enclave::list()
                    .map_err(|e| {
                        e.add_subaction("Failed to fetch list of all running enclaves".to_string())
                            .set_action(TERMINATE_ALL_ENCLAVES_STR.to_string())
                    })
                    .ok_or_exit_with_errno(None);

                for enclave_id in enclave_ids {
                    terminate_enclave_print(&enclave_id);
                }
            } else {
                let terminate_args = TerminateEnclavesArgs::new_with(args)
                    .map_err(|err| {
                        err.add_subaction(
                            "Failed to construct TerminateEnclave arguments".to_string(),
                        )
                        .set_action(TERMINATE_ENCLAVE_STR.to_string())
                    })
                    .ok_or_exit_with_errno(None);

                terminate_enclave_print(&terminate_args.enclave_id);
            }
        }
        ("describe-enclaves", _) => {
            let enclave_ids = Enclave::list()
                .map_err(|e| {
                    e.add_subaction("Failed to fetch list of all running enclaves".to_string())
                        .set_action(DESCRIBE_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);

            let enclave_describe_infos: Vec<EnclaveDescribeInfo> = enclave_ids
                .iter()
                .filter_map(|enclave_id| Enclave::describe(enclave_id.to_string()).ok())
                .map(|enclave| enclave.into())
                .collect();

            let describe_info_string = serde_json::to_string_pretty(&enclave_describe_infos)
                .map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!(
                            "Failed to parse run enclave message from enclave process: {:}",
                            e
                        ),
                        NitroCliErrorEnum::SerdeError
                    )
                    .set_action(DESCRIBE_ENCLAVE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            println!("{}", describe_info_string);
        }
        ("build-enclave", Some(args)) => {
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
        ("console", Some(args)) => {
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
            console_enclaves(enclave_cid)
                .map_err(|e| {
                    e.add_subaction("Failed to connect to enclave console".to_string())
                        .set_action(ENCLAVE_CONSOLE_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
        }
        ("explain", Some(args)) => {
            let explain_args = ExplainArgs::new_with(args)
                .map_err(|e| {
                    e.add_subaction("Failed to construct Explain arguments".to_string())
                        .set_action(EXPLAIN_ERR_STR.to_string())
                })
                .ok_or_exit_with_errno(None);
            explain_error(explain_args.error_code_str);
        }
        (&_, _) => {}
    }
}
