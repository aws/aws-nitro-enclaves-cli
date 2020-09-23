// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use clap::{App, AppSettings, Arg, SubCommand};
use env_logger;
use log::info;

use nitro_cli_poweruser::commands_parser::{
    ConsoleArgs, DescribeEnclaveArgs, RunEnclavesArgs, TerminateEnclavesArgs,
};
use nitro_cli_poweruser::utils::handle_signals;
use nitro_cli_poweruser::utils::ExitGracefully;
use nitro_cli_poweruser::{
    console_enclaves, create_app, describe_enclaves, enclave_console, run_enclaves,
    terminate_enclaves, testing_commands,
};

fn main() {
    // Command line specification for NitroEnclaves CLI.
    env_logger::init();
    info!("Start Nitro CLI (Power-user)");

    let app = create_app!();
    let app = testing_commands::initialize(app);
    let args = app.get_matches();

    testing_commands::match_cmd(&args);

    match args.subcommand() {
        ("run-enclave", Some(args)) => {
            handle_signals();
            let run_args = RunEnclavesArgs::new_with(args).ok_or_exit(args.usage());
            run_enclaves(run_args).ok_or_exit(args.usage());
        }
        ("terminate-enclave", Some(args)) => {
            handle_signals();
            let terminate_args = TerminateEnclavesArgs::new_with(args).ok_or_exit(args.usage());
            terminate_enclaves(terminate_args).ok_or_exit(args.usage());
        }
        ("describe-enclaves", Some(args)) => {
            let describe_args = DescribeEnclaveArgs::new_with(args).ok_or_exit(args.usage());
            describe_enclaves(describe_args).ok_or_exit(args.usage());
        }
        ("console", Some(args)) => {
            let console_args = ConsoleArgs::new_with(args).ok_or_exit(args.usage());
            console_enclaves(console_args).ok_or_exit(args.usage());
        }
        ("console-cid", Some(args)) => {
            let console_args = ConsoleArgs::new_with(args).ok_or_exit(args.usage());
            enclave_console(console_args.enclave_cid).ok_or_exit(args.usage());
        }
        (&_, _) => {}
    }
}