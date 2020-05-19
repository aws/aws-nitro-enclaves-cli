// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

pub mod common;
pub mod enclave_proc;
pub mod enclave_proc_comm;
pub mod utils;

use log::debug;
use serde::Serialize;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use common::commands_parser::BuildEnclavesArgs;
use common::NitroCliResult;
use enclave_build;

use utils::Console;

// Hypervisor cid as defined by:
// http://man7.org/linux/man-pages/man7/vsock.7.html
pub const VMADDR_CID_HYPERVISOR: u32 = 0;
pub const CID_TO_CONSOLE_PORT_OFFSET: u32 = 10000;

#[derive(Serialize)]
pub struct EnclaveBuildInfo {
    #[serde(rename(serialize = "Measurements"))]
    measurements: BTreeMap<String, String>,
}

impl EnclaveBuildInfo {
    pub fn new(measurements: BTreeMap<String, String>) -> Self {
        EnclaveBuildInfo { measurements }
    }
}

pub fn build_enclaves(args: BuildEnclavesArgs) -> NitroCliResult<()> {
    debug!("build_enclaves");
    eprintln!("Start building the Enclave Image...");
    build_from_docker(&args.docker_uri, &args.docker_dir, &args.output)?;
    Ok(())
}

pub fn build_from_docker(
    docker_uri: &String,
    docker_dir: &Option<String>,
    output_path: &String,
) -> NitroCliResult<(File, BTreeMap<String, String>)> {
    let blobs_path = blobs_path()?;
    let mut cmdline_file = File::open(format!("{}/cmdline", blobs_path))
        .map_err(|err| format!("Could not open kernel command line file: {}", err))?;

    let mut cmdline = String::new();
    cmdline_file
        .read_to_string(&mut cmdline)
        .map_err(|err| format!("Failed to read kernel command line: {:?}", err))?;

    let mut file_output = OpenOptions::new()
        .read(true)
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)
        .map_err(|err| format!("Could not create output file: {}", err))?;

    let mut docker2eif = enclave_build::Docker2Eif::new(
        docker_uri.clone(),
        format!("{}/init", blobs_path),
        format!("{}/bzImage", blobs_path),
        cmdline.trim().to_string(),
        format!("{}/linuxkit", blobs_path),
        &mut file_output,
        artifacts_path()?,
    )
    .map_err(|err| format!("Failed to create Eif image: {:?}", err))?;

    if let Some(docker_dir) = docker_dir {
        docker2eif
            .build_docker_image(docker_dir.clone())
            .map_err(|err| format!("Failed to build docker image {:?}", err))?;
    } else {
        docker2eif
            .pull_docker_image()
            .map_err(|err| format!("Failed to pull docker image {:?}", err))?;
    }
    let measurements = docker2eif
        .create()
        .map_err(|err| format!("Failed to create Eif image: {:?}", err))?;
    eprintln!("Enclave Image successfully created.");

    let info = EnclaveBuildInfo::new(measurements.clone());
    println!(
        "{}",
        serde_json::to_string_pretty(&info).map_err(|err| format!("{:?}", err))?
    );

    Ok((file_output, measurements))
}

/// Returns the value of NITRO_CLI_BLOBS environment variable
///
/// Environment variable that specify where all the blobs necessary for building
/// an Image are.
/// As of now the blobs are:
///    bzImage: A kernel image
///    init: The initial init process that is bootstraping the environment
///    linuxkit: A slightly modified version of linuxkit
///    cmdline: A file containing the kernel commandline
fn blobs_path() -> NitroCliResult<String> {
    // TODO Improve error message with a suggestion to the user
    // consider using the default path used by rpm install
    std::env::var("NITRO_CLI_BLOBS")
        .map_err(|_err| "NITRO_CLI_BLOBS environment variable is not set".to_string())
}

/// Returns the value of NITRO_CLI_ARTIFACTS environment variable
///
/// This variable configures the path where the build artifacts should be saved
fn artifacts_path() -> NitroCliResult<String> {
    if let Ok(artifacts) = std::env::var("NITRO_CLI_ARTIFACTS") {
        std::fs::create_dir_all(artifacts.clone()).map_err(|err| {
            format!(
                "Could not create artifacts path {}: {}",
                artifacts,
                err.to_string()
            )
        })?;
        Ok(artifacts)
    } else if let Ok(home) = std::env::var("HOME") {
        let artifacts = format!("{}/.nitro_cli/", home);
        std::fs::create_dir_all(artifacts.clone()).map_err(|err| {
            format!(
                "Could not create artifacts path {}: {}",
                artifacts,
                err.to_string()
            )
        })?;
        Ok(artifacts)
    } else {
        Err(
            "Could not find a folder for the cli artifacts, set either the \
                 HOME or NITRO_CLI_ARTIFACTS"
                .to_string(),
        )
    }
}

/// Wrapper over the console connection function.
pub fn console_enclaves(enclave_cid: u64) -> NitroCliResult<()> {
    debug!("console_enclaves");
    println!("Connecting to the console for enclave {}...", enclave_cid);
    enclave_console(enclave_cid)
        .map_err(|err| format!("Failed to start enclave logger: {:?}", err))?;
    Ok(())
}

/// Connects to the enclave console and prints it continously.
pub fn enclave_console(enclave_cid: u64) -> NitroCliResult<()> {
    let console = Console::new(
        VMADDR_CID_HYPERVISOR,
        u32::try_from(enclave_cid)
            .map_err(|err| format!("Failed to connect to the enclave: {}", err))?
            + CID_TO_CONSOLE_PORT_OFFSET,
    )?;
    println!("Successfully connected to the console.");
    console.read_to(io::stdout().by_ref())?;

    Ok(())
}

#[macro_export]
macro_rules! create_app {
    () => {
        App::new("Nitro CLI")
            .about("CLI for enclave lifetime management")
            .setting(AppSettings::ArgRequiredElseHelp)
            .version(env!("CARGO_PKG_VERSION"))
            .subcommand(
                SubCommand::with_name("run-enclave")
                    .about("Starts a new enclave")
                    .arg(
                        Arg::with_name("cpu-ids")
                            .long("cpu-ids")
                            .help("List of cpu-ids that will be provided to the enclave")
                            .takes_value(true)
                            .multiple(true)
                            .min_values(1)
                            .required_unless("cpu-count")
                            .conflicts_with("cpu-count"),
                    )
                    .arg(
                        Arg::with_name("cpu-count")
                            .long("cpu-count")
                            .help("Number of cpus")
                            .takes_value(true)
                            .required_unless("cpu-ids")
                            .conflicts_with("cpu-ids"),
                    )
                    .arg(
                        Arg::with_name("memory")
                            .long("memory")
                            .help("Memory to allocate for the enclave in MB")
                            .required(true)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::with_name("eif-path")
                            .long("eif-path")
                            .help("Path pointing to a prebuilt Eif image")
                            .required(true)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::with_name("enclave-cid")
                            .long("enclave-cid")
                            .takes_value(true)
                            .help("CID to be used for the newly started enclave"),
                    )
                    .arg(
                        Arg::with_name("debug-mode")
                            .long("debug-mode")
                            .takes_value(false)
                            .help(
                                "Starts enclave in debug-mode. This makes the console of the enclave \
                                available over vsock at CID: VMADDR_CID_HYPERVISOR (0), port: \
                                enclave_cid + 10000. \n The stream could be accessed with the console \
                                sub-command" ,
                            ),
                    ),
            )
            .subcommand(
                SubCommand::with_name("terminate-enclave")
                    .about("Terminates an enclave")
                    .arg(
                        Arg::with_name("enclave-id")
                            .long("enclave-id")
                            .takes_value(true)
                            .help("Enclave ID, used to uniquely identify an enclave")
                            .required(true),
                    ),
            )
            .subcommand(
                SubCommand::with_name("build-enclave")
                    .about("Builds an enclave image and saves it to a file")
                    .arg(
                        Arg::with_name("docker-uri")
                            .long("docker-uri")
                            .help(
                                "Uri pointing to an existing docker container or to be created  \
                                 locally when docker-dir is present",
                            )
                            .required(true)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::with_name("docker-dir")
                            .long("docker-dir")
                            .help("Local path to a directory containing a Dockerfile")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::with_name("output-file")
                            .long("output-file")
                            .help("Location where the Enclave Image should be saved")
                            .group("action")
                            .required(true)
                            .takes_value(true),
                    ),
            )
            .subcommand(
                SubCommand::with_name("describe-enclaves")
                    .about("Returns a list of the running enclaves"),
            )
            .subcommand(
                SubCommand::with_name("console")
                    .about("Connect to the console of an enclave")
                    .arg(
                        Arg::with_name("enclave-id")
                            .long("enclave-id")
                            .takes_value(true)
                            .help("Enclave ID, used to uniquely identify an enclave")
                            .required(true),
                    ),
            )
    };
}
