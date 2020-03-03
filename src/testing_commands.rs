// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use clap::{App, Arg, ArgMatches, SubCommand};
use log::debug;

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
            debug!("Execute-dev-cmd: {:?}", args);
            // TODO: execute_command(args).ok_or_exit(args.usage());
        }
        ("send-image", Some(args)) => {
            debug!("Send-image: {:?}", args);
            // TODO: send_eif(args).ok_or_exit(args.usage());
        }
        ("free-slot", Some(args)) => {
            debug!("Free-slot: {:?}", args);
            // TODO: free_slot(args).ok_or_exit(args.usage());
        }
        ("alloc-mem", Some(args)) => {
            debug!("Alloc-mem: {:?}", args);
            // TODO: alloc_mem(args).ok_or_exit(args.usage());
        }
        (&_, _) => {}
    }
}
