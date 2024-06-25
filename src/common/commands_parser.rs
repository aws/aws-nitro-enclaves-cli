// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use clap::ArgMatches;
use libc::VMADDR_CID_HOST;
#[cfg(test)]
use libc::VMADDR_CID_LOCAL;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::str::FromStr;

use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult, VMADDR_CID_PARENT};
use crate::get_id_by_name;
use crate::new_nitro_cli_failure;
use crate::utils::PcrType;

/// The arguments used by the `run-enclave` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEnclavesArgs {
    /// The path to the enclave image file.
    pub eif_path: String,
    /// The optional enclave CID
    pub enclave_cid: Option<u64>,
    /// The amount of memory that will be given to the enclave.
    pub memory_mib: u64,
    /// An optional list of CPU IDs that will be given to the enclave.
    pub cpu_ids: Option<Vec<u32>>,
    /// A flag indicating if the enclave will be started in debug mode.
    #[serde(default)]
    pub debug_mode: bool,
    /// Attach to the console immediately if using debug mode.
    #[serde(default)]
    pub attach_console: bool,
    /// The number of CPUs that the enclave will receive.
    pub cpu_count: Option<u32>,
    /// Enclave name set by the user.
    pub enclave_name: Option<String>,
}

impl RunEnclavesArgs {
    /// Construct a new `RunEnclavesArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        if let Some(config_file) = args.value_of("config") {
            let file = File::open(config_file).map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to open config file: {:?}", err),
                    NitroCliErrorEnum::FileOperationFailure
                )
                .add_info(vec![config_file, "Open"])
            })?;

            let mut json: RunEnclavesArgs = serde_json::from_reader(file).map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Invalid JSON format for config file: {:?}", err),
                    NitroCliErrorEnum::SerdeError
                )
            })?;
            if json.cpu_count.is_none() && json.cpu_ids.is_none() {
                return Err(new_nitro_cli_failure!(
                    "Missing both `cpu-count` and `cpu-ids`",
                    NitroCliErrorEnum::MissingArgument
                ));
            }
            if json.cpu_count.is_some() && json.cpu_ids.is_some() {
                return Err(new_nitro_cli_failure!(
                    "`cpu-count` and `cpu-ids` cannot be used together",
                    NitroCliErrorEnum::ConflictingArgument
                ));
            }

            // attach_console implies debug_mode
            json.debug_mode = json.debug_mode || json.attach_console;

            Ok(json)
        } else {
            Ok(RunEnclavesArgs {
                cpu_count: parse_cpu_count(args)
                    .map_err(|err| err.add_subaction("Parse CPU count".to_string()))?,
                eif_path: parse_eif_path(args)
                    .map_err(|err| err.add_subaction("Parse EIF path".to_string()))?,
                enclave_cid: parse_enclave_cid(args)
                    .map_err(|err| err.add_subaction("Parse enclave CID".to_string()))?,
                memory_mib: parse_memory(args)
                    .map_err(|err| err.add_subaction("Parse memory".to_string()))?,
                cpu_ids: parse_cpu_ids(args)
                    .map_err(|err| err.add_subaction("Parse CPU IDs".to_string()))?,
                debug_mode: debug_mode(args),
                attach_console: attach_console(args),
                enclave_name: parse_enclave_name(args)
                    .map_err(|err| err.add_subaction("Parse enclave name".to_string()))?,
            })
        }
    }
}

/// The arguments used by the `build-enclave` command.
#[derive(Debug, Clone)]
pub struct BuildEnclavesArgs {
    /// The URI to the Docker image.
    pub docker_uri: String,
    /// The directory containing the Docker image.
    pub docker_dir: Option<String>,
    /// The path where the enclave image file will be written to.
    pub output: String,
    /// The path to the signing certificate for signed enclaves.
    pub signing_certificate: Option<String>,
    /// The path to the private key for signed enclaves.
    pub private_key: Option<String>,
    /// The name of the enclave image.
    pub img_name: Option<String>,
    /// The version of the enclave image.
    pub img_version: Option<String>,
    /// The path to custom metadata JSON file
    pub metadata: Option<String>,
}

impl BuildEnclavesArgs {
    /// Construct a new `BuildEnclavesArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        let signing_certificate = parse_signing_certificate(args);
        let private_key = parse_private_key(args);

        match (&signing_certificate, &private_key) {
            (Some(_), None) => {
                return Err(new_nitro_cli_failure!(
                    "`private-key` argument not found",
                    NitroCliErrorEnum::MissingArgument
                )
                .add_info(vec!["private-key"]))
            }
            (None, Some(_)) => {
                return Err(new_nitro_cli_failure!(
                    "`signing-certificate` argument not found",
                    NitroCliErrorEnum::MissingArgument
                )
                .add_info(vec!["signing-certificate"]))
            }
            _ => (),
        };

        Ok(BuildEnclavesArgs {
            docker_uri: parse_docker_tag(args).ok_or_else(|| {
                new_nitro_cli_failure!(
                    "`docker-uri` argument not found",
                    NitroCliErrorEnum::MissingArgument
                )
                .add_info(vec!["docker-uri"])
            })?,
            docker_dir: parse_docker_dir(args),
            output: parse_output(args).ok_or_else(|| {
                new_nitro_cli_failure!(
                    "`output` argument not found",
                    NitroCliErrorEnum::MissingArgument
                )
                .add_info(vec!["output"])
            })?,
            signing_certificate,
            private_key,
            img_name: parse_image_name(args),
            img_version: parse_image_version(args),
            metadata: parse_metadata(args),
        })
    }
}

/// The arguments used by the `terminate-enclave` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminateEnclavesArgs {
    /// The ID of the enclave that is to be terminated.
    pub enclave_id: String,
}

impl TerminateEnclavesArgs {
    /// Construct a new `TerminateEnclavesArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        // If a name is given, find the corresponding EnclaveID
        match parse_enclave_name(args)
            .map_err(|e| e.add_subaction("Parse Enclave Name".to_string()))?
        {
            Some(name) => Ok(TerminateEnclavesArgs {
                enclave_id: get_id_by_name(name)
                    .map_err(|e| e.add_subaction("Get ID by Name".to_string()))?,
            }),
            None => Ok(TerminateEnclavesArgs {
                enclave_id: parse_enclave_id(args)
                    .map_err(|e| e.add_subaction("Parse enclave ID".to_string()))?,
            }),
        }
    }
}

/// The arguments used by the `console` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleArgs {
    /// The ID of the enclave whose console is to be shown.
    pub enclave_id: String,
    /// The time in seconds after the console disconnects from the enclave.
    pub disconnect_timeout_sec: Option<u64>,
}

impl ConsoleArgs {
    /// Construct a new `ConsoleArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        // If a name is given, find the corresponding EnclaveID
        let enclave_id = match parse_enclave_name(args)
            .map_err(|e| e.add_subaction("Parse Enclave Name".to_string()))?
        {
            Some(name) => {
                get_id_by_name(name).map_err(|e| e.add_subaction("Get ID by Name".to_string()))?
            }
            None => parse_enclave_id(args)
                .map_err(|e| e.add_subaction("Parse enclave ID".to_string()))?,
        };

        Ok(ConsoleArgs {
            enclave_id,
            disconnect_timeout_sec: parse_disconnect_timeout(args)
                .map_err(|e| e.add_subaction("Parse disconnect timeout".to_string()))?,
        })
    }
}

/// Empty set of arguments.
#[derive(Serialize, Deserialize)]
pub struct EmptyArgs {}

/// The arguments used by `describe-enclaves` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescribeEnclavesArgs {
    /// True if metadata is requested.
    pub metadata: bool,
}

impl DescribeEnclavesArgs {
    /// Construct a new `DescribeEnclavesArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> Self {
        DescribeEnclavesArgs {
            metadata: args.is_present("metadata"),
        }
    }
}

/// The arguments used by the `explain` command.
#[derive(Debug, Clone)]
pub struct ExplainArgs {
    /// The error code of the error to explain.
    pub error_code_str: String,
}

impl ExplainArgs {
    /// Construct a new `ExplainArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        Ok(ExplainArgs {
            error_code_str: parse_error_code_str(args)
                .map_err(|e| e.add_subaction("Parse error code".to_string()))?,
        })
    }
}

/// The arguments used by `pcr` command
pub struct PcrArgs {
    /// Path to the file needed for hashing
    pub path: String,
    /// The type of file we need to hash
    pub pcr_type: PcrType,
}

impl PcrArgs {
    /// Construct a new `PcrArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        let (val_name, pcr_type) = match args.is_present("signing-certificate") {
            true => ("signing-certificate", PcrType::SigningCertificate),
            false => ("input", PcrType::DefaultType),
        };
        let path = parse_file_path(args, val_name)
            .map_err(|e| e.add_subaction("Parse PCR file".to_string()))?;
        Ok(Self { path, pcr_type })
    }
}

/// Parse file path to hash from the command-line arguments.
fn parse_file_path(args: &ArgMatches, val_name: &str) -> NitroCliResult<String> {
    let path = args.value_of(val_name).ok_or_else(|| {
        new_nitro_cli_failure!(
            "`input` or `signing-certificate` argument not found",
            NitroCliErrorEnum::MissingArgument
        )
    })?;
    Ok(path.to_string())
}

#[derive(Debug)]
enum MemoryUnit {
    Mebibytes,
    Gibibytes,
    Tebibytes,
}

#[derive(Debug)]
struct UnknownMemoryUnitErr;

impl MemoryUnit {
    fn to_mebibytes(&self) -> u64 {
        match self {
            MemoryUnit::Mebibytes => 1,
            MemoryUnit::Gibibytes => 1024,
            MemoryUnit::Tebibytes => 1024 * 1024,
        }
    }
}

impl FromStr for MemoryUnit {
    type Err = UnknownMemoryUnitErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "M" | "m" | "" => Ok(MemoryUnit::Mebibytes),
            "G" | "g" => Ok(MemoryUnit::Gibibytes),
            "T" | "t" => Ok(MemoryUnit::Tebibytes),
            _ => Err(UnknownMemoryUnitErr),
        }
    }
}

/// Parse the requested amount of enclave memory from the command-line arguments.
/// It can be just a number like 123, or it can end in a size indicator like 100M or 10G.
/// If the size indicator is missing, it defaults to M.
/// If the size indicator is not M, G or T, it returns an error.
///
/// # Arguments
/// * `args` - The command-line arguments.
pub fn parse_memory(args: &ArgMatches) -> NitroCliResult<u64> {
    let memory = args.value_of("memory").ok_or_else(|| {
        new_nitro_cli_failure!(
            "`memory` argument not found",
            NitroCliErrorEnum::MissingArgument
        )
    })?;

    let (num_str, size_str) = match memory.find(|c: char| !c.is_numeric()) {
        Some(index) => memory.split_at(index),
        None => (memory, ""),
    };
    let num = num_str.parse::<u64>().map_err(|_| {
        new_nitro_cli_failure!(
            "`memory` argument does not contain a number",
            NitroCliErrorEnum::InvalidArgument
        )
        .add_info(vec!["memory", memory])
    })?;

    let unit = size_str.parse::<MemoryUnit>().map_err(|_| {
        new_nitro_cli_failure!(
            "`memory` argument does not contain a valid size indicator",
            NitroCliErrorEnum::InvalidArgument
        )
        .add_info(vec!["memory", memory])
    })?;
    Ok(num * unit.to_mebibytes())
}

/// Parse the Docker tag from the command-line arguments.
fn parse_docker_tag(args: &ArgMatches) -> Option<String> {
    args.value_of("docker-uri").map(|val| val.to_string())
}

/// Parse the Docker directory from the command-line arguments.
fn parse_docker_dir(args: &ArgMatches) -> Option<String> {
    args.value_of("docker-dir").map(|val| val.to_string())
}

/// Parse the enclave's required CID from the command-line arguments.
fn parse_enclave_cid(args: &ArgMatches) -> NitroCliResult<Option<u64>> {
    let enclave_cid = if let Some(enclave_cid) = args.value_of("enclave-cid") {
        let enclave_cid: u64 = enclave_cid.parse().map_err(|_| {
            new_nitro_cli_failure!(
                "`enclave-cid` is not a number",
                NitroCliErrorEnum::InvalidArgument
            )
            .add_info(vec!["enclave-cid", enclave_cid])
        })?;

        // Do not use well-known CID values - 0, 1, 2 - as the enclave CID.
        // VMADDR_CID_ANY = -1U
        // VMADDR_CID_HYPERVISOR = 0
        // VMADDR_CID_LOCAL = 1
        // VMADDR_CID_HOST = 2
        // Note: 0 is used as a placeholder to auto-generate a CID.
        // <http://man7.org/linux/man-pages/man7/vsock.7.html>
        if enclave_cid == 0 {
            eprintln!("The enclave CID will be auto-generated as the provided CID is 0");
        }

        if enclave_cid > 0 && enclave_cid <= VMADDR_CID_HOST as u64 {
            return Err(new_nitro_cli_failure!(
                &format!(
                    "CID {} is a well-known CID, not to be used for enclaves",
                    enclave_cid
                ),
                NitroCliErrorEnum::InvalidArgument
            ));
        }

        if enclave_cid == u32::MAX as u64 {
            return Err(new_nitro_cli_failure!(
                &format!(
                    "CID {} is a well-known CID, not to be used for enclaves",
                    enclave_cid
                ),
                NitroCliErrorEnum::InvalidArgument
            ));
        }

        // Do not use the CID of the parent VM as the enclave CID.
        if enclave_cid == VMADDR_CID_PARENT as u64 {
            return Err(new_nitro_cli_failure!(
                &format!(
                    "CID {} is the CID of the parent VM, not to be used for enclaves",
                    enclave_cid
                ),
                NitroCliErrorEnum::InvalidArgument
            ));
        }

        // 64-bit CIDs are not yet supported for the vsock device.
        if enclave_cid > u32::MAX as u64 {
            return Err(new_nitro_cli_failure!(
                &format!(
                    "CID {} is higher than the maximum supported (u32 max) for a vsock device",
                    enclave_cid
                ),
                NitroCliErrorEnum::InvalidArgument
            ));
        }

        Some(enclave_cid)
    } else {
        None
    };

    Ok(enclave_cid)
}

/// Parse the enclave image file path from the command-line arguments.
fn parse_eif_path(args: &ArgMatches) -> NitroCliResult<String> {
    let eif_path = args.value_of("eif-path").ok_or_else(|| {
        new_nitro_cli_failure!(
            "`eif-path` argument not found",
            NitroCliErrorEnum::MissingArgument
        )
    })?;
    Ok(eif_path.to_string())
}

/// Parse the enclave's ID from the command-line arguments.
fn parse_enclave_id(args: &ArgMatches) -> NitroCliResult<String> {
    let enclave_id = args.value_of("enclave-id").ok_or_else(|| {
        new_nitro_cli_failure!(
            "`enclave-id` argument not found",
            NitroCliErrorEnum::MissingArgument
        )
    })?;
    Ok(enclave_id.to_string())
}

/// Parse the disconnect timeout from the command-line arguments.
fn parse_disconnect_timeout(args: &ArgMatches) -> NitroCliResult<Option<u64>> {
    let disconnect_timeout = match args.value_of("disconnect-timeout") {
        Some(arg) => Some(arg.parse::<u64>().map_err(|_| {
            new_nitro_cli_failure!(
                "`disconnect-timeout` argument can't be parsed as a number",
                NitroCliErrorEnum::InvalidArgument
            )
            .add_info(vec![
                "disconnect-timeout",
                args.value_of("disconnect-timeout").unwrap(),
            ])
        })?),
        None => None,
    };
    Ok(disconnect_timeout)
}

/// Parse the list of requested CPU IDs from the command-line arguments.
fn parse_cpu_ids(args: &ArgMatches) -> NitroCliResult<Option<Vec<u32>>> {
    let cpu_ids_arg = args.values_of("cpu-ids");
    match cpu_ids_arg {
        Some(iterator) => {
            let mut cpu_ids = Vec::new();
            for cpu_id in iterator {
                cpu_ids.push(cpu_id.parse().map_err(|_| {
                    new_nitro_cli_failure!(
                        "`cpu-id` is not a number",
                        NitroCliErrorEnum::InvalidArgument
                    )
                    .add_info(vec!["cpu-id", cpu_id])
                })?);
            }
            Ok(Some(cpu_ids))
        }
        None => Ok(None),
    }
}

/// Parse the requested number of CPUs from the command-line arguments.
fn parse_cpu_count(args: &ArgMatches) -> NitroCliResult<Option<u32>> {
    let cpu_count = if let Some(cpu_count) = args.value_of("cpu-count") {
        let cpu_count: u32 = cpu_count.parse().map_err(|_| {
            new_nitro_cli_failure!(
                "`cpu-count` is not a number",
                NitroCliErrorEnum::InvalidArgument
            )
            .add_info(vec!["cpu-count", cpu_count])
        })?;
        Some(cpu_count)
    } else {
        None
    };
    Ok(cpu_count)
}

/// Parse the path of an output file from the command-line arguments.
fn parse_output(args: &ArgMatches) -> Option<String> {
    args.value_of("output-file").map(|val| val.to_string())
}

/// Parse the debug-mode flag from the command-line arguments.
fn debug_mode(args: &ArgMatches) -> bool {
    args.is_present("debug-mode") || args.is_present("attach-console")
}

/// Parse the attach-console flag from the command-line arguments.
fn attach_console(args: &ArgMatches) -> bool {
    args.is_present("attach-console")
}

/// Parse the enclave name from the command-line arguments.
fn parse_enclave_name(args: &ArgMatches) -> NitroCliResult<Option<String>> {
    Ok(args.value_of("enclave-name").map(|e| e.to_string()))
}

fn parse_signing_certificate(args: &ArgMatches) -> Option<String> {
    args.value_of("signing-certificate")
        .map(|val| val.to_string())
}

fn parse_private_key(args: &ArgMatches) -> Option<String> {
    args.value_of("private-key").map(|val| val.to_string())
}

fn parse_image_name(args: &ArgMatches) -> Option<String> {
    args.value_of("image_name").map(|val| val.to_string())
}

fn parse_image_version(args: &ArgMatches) -> Option<String> {
    args.value_of("image_version").map(|val| val.to_string())
}

fn parse_metadata(args: &ArgMatches) -> Option<String> {
    args.value_of("metadata").map(|val| val.to_string())
}

fn parse_error_code_str(args: &ArgMatches) -> NitroCliResult<String> {
    let error_code_str = args.value_of("error-code").ok_or_else(|| {
        new_nitro_cli_failure!(
            "`error-code` argument not found",
            NitroCliErrorEnum::MissingArgument
        )
    })?;
    Ok(error_code_str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::construct_error_message;
    use crate::create_app;

    use clap::{App, AppSettings, Arg, SubCommand};

    /// Parse the path of the JSON config file
    fn parse_config_file(args: &ArgMatches) -> NitroCliResult<String> {
        let config_file = args.value_of("config").ok_or(new_nitro_cli_failure!(
            "`config` argument not found",
            NitroCliErrorEnum::MissingArgument
        ))?;
        Ok(config_file.to_string())
    }

    #[test]
    fn test_parse_memory() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256_mb",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
        ];

        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_memory(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Invalid argument provided"))
        }

        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
        ];

        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_memory(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert_eq!(result, Ok(256));

        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "100M",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
        ];

        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_memory(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert_eq!(result, Ok(100));

        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "10G",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
        ];

        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_memory(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert_eq!(result, Ok(10_240));

        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "2T",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
        ];

        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_memory(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert_eq!(result, Ok(2 * 1024 * 1024));
    }

    #[test]
    fn test_parse_docker_tag() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "build-enclave",
            "--docker-uri",
            "mytag",
            "--docker-dir",
            "/home/user/non_existing_dir",
            "--output-file",
            "sample_eif.eif",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_docker_tag(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("build-enclave")
                .unwrap(),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "mytag");
    }

    #[test]
    fn test_parse_docker_dir() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "build-enclave",
            "--docker-uri",
            "mytag",
            "--docker-dir",
            "/home/user/non_existing_dir",
            "--output-file",
            "sample_eif.eif",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_docker_dir(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("build-enclave")
                .unwrap(),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "/home/user/non_existing_dir");
    }

    #[test]
    fn test_parse_enclave_cid_correct() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--enclave-cid",
            "10",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_enclave_cid(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_ok());

        if let Some(parsed_cid) = result.unwrap() {
            assert_eq!(parsed_cid, 10);
        }
    }

    #[test]
    fn test_parse_enclave_cid_to_be_autogenerated() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--enclave-cid",
            "0",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_enclave_cid(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_ok());

        if let Some(parsed_cid) = result.unwrap() {
            assert_eq!(parsed_cid, 0);
        }
    }

    #[test]
    fn test_parse_enclave_cid_str() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--enclave-cid",
            "0x1g",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_enclave_cid(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Invalid argument provided"))
        }
    }

    #[test]
    fn test_parse_enclave_cid_well_known_cid_local() {
        let app = create_app!();
        let cid_local = VMADDR_CID_LOCAL.to_string();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--enclave-cid",
            &cid_local,
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_enclave_cid(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Invalid argument provided"));
        }
    }

    #[test]
    fn test_parse_enclave_cid_well_known_cid_host() {
        let app = create_app!();
        let cid_host = VMADDR_CID_HOST.to_string();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--enclave-cid",
            &cid_host,
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_enclave_cid(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Invalid argument provided"));
        }
    }

    #[test]
    fn test_parse_enclave_cid_parent_vm() {
        let app = create_app!();
        let parent_vm_cid = VMADDR_CID_PARENT.to_string();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--enclave-cid",
            &parent_vm_cid,
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_enclave_cid(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Invalid argument provided"));
        }
    }

    #[test]
    fn test_parse_enclave_cid_negative() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--enclave-cid",
            "-18",
        ];
        let matches = app.get_matches_from_safe(args);
        // Error (got unexpected value ["-1"])
        assert!(matches.is_err());
    }

    #[test]
    fn test_parse_eif_path() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "256",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_eif_path(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "non_existing_eif.eif");
    }

    #[test]
    fn test_parse_enclave_id() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "terminate-enclave",
            "--enclave-id",
            "i-0000-enc-1234",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_enclave_id(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("terminate-enclave")
                .unwrap(),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "i-0000-enc-1234");
    }

    #[test]
    fn test_parse_cpu_ids_correct() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--cpu-ids",
            "1",
            "3",
            "--eif-path",
            "non_existing_eif.eif",
            "--memory",
            "64",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_cpu_ids(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_ok());

        if let Some(parsed_cpu_ids) = result.unwrap() {
            assert_eq!(parsed_cpu_ids.len(), 2);
            assert_eq!(parsed_cpu_ids[0], 1);
            assert_eq!(parsed_cpu_ids[1], 3);
        }
    }

    #[test]
    fn test_parse_cpu_ids_negative() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--cpu-ids",
            "1",
            "-5",
            "--eif-path",
            "non_existing_eif.eif",
            "--memory 64",
        ];
        let matches = app.get_matches_from_safe(args);
        // Error (got unexpected value ["-5"])
        assert!(matches.is_err());
    }

    #[test]
    fn test_parse_cpu_ids_str() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--cpu-ids",
            "1",
            "three",
            "--eif-path",
            "non_existing_eif.eif",
            "--memory",
            "64",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_cpu_ids(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Invalid argument provided"));
        }
    }

    #[test]
    fn test_parse_cpu_count_correct() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--memory",
            "64",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_cpu_count(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_ok());

        if let Some(parsed_cpu_count) = result.unwrap() {
            assert_eq!(parsed_cpu_count, 2);
        }
    }

    #[test]
    fn test_parse_cpu_count_str() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--cpu-count",
            "2n",
            "--eif-path",
            "non_existing_eif.eif",
            "--memory",
            "64",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_cpu_count(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_err());
        if let Err(err_info) = result {
            let err_str = construct_error_message(&err_info);
            assert!(err_str.contains("Invalid argument provided"));
        }
    }

    #[test]
    fn test_parse_output() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "build-enclave",
            "--docker-uri",
            "mytag",
            "--docker-dir",
            "/home/user/non_existing_dir",
            "--output-file",
            "sample_eif.eif",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_output(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("build-enclave")
                .unwrap(),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "sample_eif.eif");
    }

    #[test]
    fn test_parse_output_not_supplied() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "build-enclave",
            "--docker-uri",
            "mytag",
            "--docker-dir",
            "/home/user/non_existing_dir",
        ];
        let matches = app.get_matches_from_safe(args);
        // Error (the following required argument were not supplied)
        assert!(matches.is_err());
    }

    #[test]
    fn test_debug_mode_supplied() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "64",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
            "--debug-mode",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = debug_mode(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result);
    }

    #[test]
    fn test_debug_mode_not_supplied() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--memory",
            "64",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = debug_mode(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(!result);
    }

    #[test]
    fn test_attach_console_supplied() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--attach-console",
            "--memory",
            "64",
            "--cpu-count",
            "2",
            "--eif-path",
            "non_existing_eif.eif",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let matches = matches
            .as_ref()
            .unwrap()
            .subcommand_matches("run-enclave")
            .unwrap();
        let attach_console = attach_console(matches);
        let debug_mode = debug_mode(matches);
        assert!(attach_console);
        assert!(debug_mode);
    }

    #[test]
    fn test_parse_json_config() {
        let app = create_app!();
        let args = vec![
            "nitro-cli",
            "run-enclave",
            "--config",
            "non_existing_config.json",
        ];
        let matches = app.get_matches_from_safe(args);
        assert!(matches.is_ok());

        let result = parse_config_file(
            matches
                .as_ref()
                .unwrap()
                .subcommand_matches("run-enclave")
                .unwrap(),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "non_existing_config.json");
    }
}
