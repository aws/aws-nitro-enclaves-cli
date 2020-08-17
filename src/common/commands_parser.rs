// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use std::fs::File;

use crate::common::{ExitGracefully, NitroCliResult};

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
    pub debug_mode: Option<bool>,
    /// The number of CPUs that the enclave will receive.
    pub cpu_count: Option<u32>,
}

impl RunEnclavesArgs {
    /// Construct a new `RunEnclavesArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        if let Some(config_file) = args.value_of("config") {
            let file = File::open(config_file).ok_or_exit("Invalid file path");

            let json: RunEnclavesArgs =
                serde_json::from_reader(file).ok_or_exit("Invalid json format for file");
            if json.cpu_count == None && json.cpu_ids == None {
                let error: NitroCliResult<()> =
                    Err(String::from("missing field `cpu_count` or `cpu_ids`"));
                error.ok_or_exit("Invalid json format for file");
            }
            if json.cpu_count.is_some() && json.cpu_ids.is_some() {
                let error: NitroCliResult<()> = Err(String::from(
                    "`cpu_count` and `cpu_ids` cannot be used together",
                ));
                error.ok_or_exit("Invalid json format for file");
            }

            Ok(json)
        } else {
            Ok(RunEnclavesArgs {
                cpu_count: parse_cpu_count(args)?,
                eif_path: parse_eif_path(args)?,
                enclave_cid: parse_enclave_cid(args)?,
                memory_mib: parse_memory(args)?,
                cpu_ids: parse_cpu_ids(args)?,
                debug_mode: debug_mode(args),
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
}

impl BuildEnclavesArgs {
    /// Construct a new `BuildEnclavesArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        let signing_certificate = parse_signing_certificate(args);
        let private_key = parse_private_key(args);

        match (&signing_certificate, &private_key) {
            (Some(_), None) => return Err("Could not find private-key argument".to_string()),
            (None, Some(_)) => {
                return Err("Could not find signing-certificate argument".to_string())
            }
            _ => (),
        };

        Ok(BuildEnclavesArgs {
            docker_uri: parse_docker_tag(args).ok_or("Could not find docker-uri argument")?,
            docker_dir: parse_docker_dir(args),
            output: parse_output(args).ok_or("Could not find output argument")?,
            signing_certificate,
            private_key,
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
        Ok(TerminateEnclavesArgs {
            enclave_id: parse_enclave_id(args)?,
        })
    }
}

/// The arguments used by the `console` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleArgs {
    /// The ID of the enclave whose console is to be shown.
    pub enclave_id: String,
}

impl ConsoleArgs {
    /// Construct a new `ConsoleArgs` instance from the given command-line arguments.
    pub fn new_with(args: &ArgMatches) -> NitroCliResult<Self> {
        Ok(ConsoleArgs {
            enclave_id: parse_enclave_id(args)?,
        })
    }
}

/// The arguments used by the `describe-enclaves` command.
#[derive(Serialize, Deserialize)]
pub struct EmptyArgs {}

/// Parse the requested amount of enclave memory from the command-line arguments.
fn parse_memory(args: &ArgMatches) -> NitroCliResult<u64> {
    let memory = args
        .value_of("memory")
        .ok_or("Could not find memory argument")?;
    memory
        .parse()
        .map_err(|_err| "memory is not a number".to_string())
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
        let enclave_cid: u64 = enclave_cid
            .parse()
            .map_err(|_err| "enclave-cid is not a number")?;
        Some(enclave_cid)
    } else {
        None
    };
    Ok(enclave_cid)
}

/// Parse the enclave image file path from the command-line arguments.
fn parse_eif_path(args: &ArgMatches) -> NitroCliResult<String> {
    let eif_path = args
        .value_of("eif-path")
        .ok_or("Could not find eif-path argument")?;
    Ok(eif_path.to_string())
}

/// Parse the enclave's ID from the command-line arguments.
fn parse_enclave_id(args: &ArgMatches) -> NitroCliResult<String> {
    let enclave_id = args
        .value_of("enclave-id")
        .ok_or("Could not find enclave-id argument")?;
    Ok(enclave_id.to_string())
}

/// Parse the list of requested CPU IDs from the command-line arguments.
fn parse_cpu_ids(args: &ArgMatches) -> NitroCliResult<Option<Vec<u32>>> {
    let cpu_ids_arg = args.values_of("cpu-ids");
    match cpu_ids_arg {
        Some(iterator) => {
            let mut cpu_ids = Vec::new();
            for cpu_id in iterator {
                cpu_ids.push(cpu_id.parse().map_err(|_err| "cpu-id is not a number")?);
            }
            Ok(Some(cpu_ids))
        }
        None => Ok(None),
    }
}

/// Parse the requested number of CPUs from the command-line arguments.
fn parse_cpu_count(args: &ArgMatches) -> NitroCliResult<Option<u32>> {
    let cpu_count = if let Some(cpu_count) = args.value_of("cpu-count") {
        let cpu_count: u32 = cpu_count
            .parse()
            .map_err(|_err| "cpu-count is not a number")?;
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
fn debug_mode(args: &ArgMatches) -> Option<bool> {
    let val = args.is_present("debug-mode");
    if val {
        Some(val)
    } else {
        None
    }
}

fn parse_signing_certificate(args: &ArgMatches) -> Option<String> {
    args.value_of("signing-certificate")
        .map(|val| val.to_string())
}

fn parse_private_key(args: &ArgMatches) -> Option<String> {
    args.value_of("private-key").map(|val| val.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::create_app;

    use clap::{App, AppSettings, Arg, SubCommand};

    /// Parse the path of the JSON config file
    fn parse_config_file(args: &ArgMatches) -> NitroCliResult<String> {
        let config_file = args
            .value_of("config")
            .ok_or("Could not find config argument")?;
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
        assert_eq!(result.unwrap_err(), "memory is not a number");
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
        assert_eq!(result.unwrap_err(), "enclave-cid is not a number");
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
        assert_eq!(result.unwrap_err(), "cpu-id is not a number");
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
        assert_eq!(result.unwrap_err(), "cpu-count is not a number");
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
        assert!(result.is_some());
        assert!(result.unwrap());
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
        assert!(result.is_none());
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
