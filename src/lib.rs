// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]
#![allow(clippy::too_many_arguments)]

//! This crate provides the functionality for the Nitro CLI process.

/// The common module (shared between the CLI and enclave process).
pub mod common;
/// The enclave process module.
pub mod enclave_proc;
/// The module covering the communication between a CLI instance and enclave processes.
pub mod enclave_proc_comm;
/// The CLI-specific utilities module.
pub mod utils;

use aws_nitro_enclaves_image_format::defs::eif_hasher::EifHasher;
use aws_nitro_enclaves_image_format::utils::eif_reader::EifReader;
use aws_nitro_enclaves_image_format::utils::eif_signer::EifSigner;
use aws_nitro_enclaves_image_format::utils::SignKeyData;
use aws_nitro_enclaves_image_format::{generate_build_info, utils::get_pcrs};
use log::{debug, info};
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use common::commands_parser::{BuildEnclavesArgs, EmptyArgs, RunEnclavesArgs, SignEifArgs};
use common::json_output::{
    EifDescribeInfo, EnclaveBuildInfo, EnclaveTerminateInfo, MetadataDescribeInfo,
};
use common::{enclave_proc_command_send_single, get_sockets_dir_path};
use common::{EnclaveProcessCommandType, NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use enclave_proc_comm::{
    enclave_proc_command_send_all, enclave_proc_handle_outputs, enclave_process_handle_all_replies,
};

use utils::{Console, PcrType};

/// Hypervisor CID as defined by <http://man7.org/linux/man-pages/man7/vsock.7.html>.
pub const VMADDR_CID_HYPERVISOR: u32 = 0;

/// An offset applied to an enclave's CID in order to determine its console port.
pub const CID_TO_CONSOLE_PORT_OFFSET: u32 = 10000;

/// Default blobs path to be used if the corresponding environment variable is not set.
const DEFAULT_BLOBS_PATH: &str = "/usr/share/nitro_enclaves/blobs/";

/// Build an enclave image file with the provided arguments.
pub fn build_enclaves(args: BuildEnclavesArgs) -> NitroCliResult<()> {
    debug!("build_enclaves");
    eprintln!("Start building the Enclave Image...");
    build_from_docker(
        &args.docker_uri,
        &args.docker_dir,
        &args.output,
        &args.signing_certificate,
        &args.private_key,
        &args.img_name,
        &args.img_version,
        &args.metadata,
    )
    .map_err(|e| e.add_subaction("Failed to build EIF from docker".to_string()))?;
    Ok(())
}

/// Build an enclave image file from a Docker image.
pub fn build_from_docker(
    docker_uri: &str,
    docker_dir: &Option<String>,
    output_path: &str,
    signing_certificate: &Option<String>,
    private_key: &Option<String>,
    img_name: &Option<String>,
    img_version: &Option<String>,
    metadata_path: &Option<String>,
) -> NitroCliResult<(File, BTreeMap<String, String>)> {
    let blobs_path =
        blobs_path().map_err(|e| e.add_subaction("Failed to retrieve blobs path".to_string()))?;
    let cmdline_file_path = format!("{blobs_path}/cmdline");
    let mut cmdline_file = File::open(cmdline_file_path.clone()).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Could not open kernel command line file: {e:?}"),
            NitroCliErrorEnum::FileOperationFailure
        )
        .add_info(vec![&cmdline_file_path, "Open"])
    })?;

    let mut cmdline = String::new();
    cmdline_file.read_to_string(&mut cmdline).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to read kernel command line: {e:?}"),
            NitroCliErrorEnum::FileOperationFailure
        )
        .add_info(vec![&cmdline_file_path, "Read"])
    })?;

    let mut file_output = OpenOptions::new()
        .read(true)
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Could not create output file: {e:?}"),
                NitroCliErrorEnum::FileOperationFailure
            )
            .add_info(vec![output_path, "Open"])
        })?;

    let kernel_image_name = match std::env::consts::ARCH {
        "aarch64" => "Image",
        "x86_64" => "bzImage",
        _ => "undefined",
    };

    let kernel_path = format!("{blobs_path}/{kernel_image_name}");
    let build_info = generate_build_info!(&format!("{kernel_path}.config")).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Could not generate build info: {e:?}"),
            NitroCliErrorEnum::EifBuildingError
        )
    })?;

    let mut docker2eif = enclave_build::Docker2Eif::new(
        docker_uri.to_string(),
        format!("{blobs_path}/init"),
        format!("{blobs_path}/nsm.ko"),
        kernel_path,
        cmdline.trim().to_string(),
        format!("{blobs_path}/linuxkit"),
        &mut file_output,
        artifacts_path()?,
        signing_certificate,
        private_key,
        img_name.clone(),
        img_version.clone(),
        metadata_path.clone(),
        build_info,
    )
    .map_err(|err| {
        new_nitro_cli_failure!(
            &format!("Failed to create EIF image: {err:?}"),
            NitroCliErrorEnum::EifBuildingError
        )
    })?;

    if let Some(docker_dir) = docker_dir {
        docker2eif
            .build_docker_image(docker_dir.clone())
            .map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to build docker image: {err:?}"),
                    NitroCliErrorEnum::DockerImageBuildError
                )
            })?;
    } else {
        docker2eif.pull_docker_image().map_err(|err| {
            new_nitro_cli_failure!(
                &format!("Failed to pull docker image: {err:?}"),
                NitroCliErrorEnum::DockerImagePullError
            )
        })?;
    }
    let measurements = docker2eif.create().map_err(|err| {
        new_nitro_cli_failure!(
            &format!("Failed to create EIF image: {err:?}"),
            NitroCliErrorEnum::EifBuildingError
        )
    })?;
    eprintln!("Enclave Image successfully created.");

    let info = EnclaveBuildInfo::new(measurements.clone());
    println!(
        "{}",
        serde_json::to_string_pretty(&info).map_err(|err| new_nitro_cli_failure!(
            &format!("Failed to display EnclaveBuild data: {err:?}"),
            NitroCliErrorEnum::SerdeError
        ))?
    );

    Ok((file_output, measurements))
}

/// Creates new enclave name
///
/// Requests the names of all running instances and checks the
/// occurrence of the chosen name for the new enclave.
pub fn new_enclave_name(run_args: RunEnclavesArgs, names: Vec<String>) -> NitroCliResult<String> {
    let enclave_name = match run_args.enclave_name {
        Some(enclave_name) => enclave_name,
        None => {
            // Get name of EIF file from path eg. path/to/eif/hello.eif -> hello
            // If the extension is missing, the whole file name will be chosen
            let path_split: Vec<&str> = run_args.eif_path.split('/').collect();
            path_split[path_split.len() - 1]
                .trim_end_matches(".eif")
                .to_string()
        }
    };

    let mut idx = 0;
    let mut result_name = enclave_name.clone();

    // If duplicates are found, add index to name eg. testName -> testName_1 -> testName_2 ..
    while names.contains(&result_name) {
        idx += 1;
        result_name = enclave_name.clone() + &'_'.to_string() + &idx.to_string();
    }

    Ok(result_name)
}

/// Returns information related to the given EIF
///
/// Calculates PCRs 0, 1, 2, 8 at each call in addition to metadata,
/// EIF details, identification provided by the user at build.
pub fn describe_eif(eif_path: String) -> NitroCliResult<EifDescribeInfo> {
    let mut eif_reader = EifReader::from_eif(eif_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to initialize EIF reader: {e:?}"),
            NitroCliErrorEnum::EifParsingError
        )
    })?;
    let measurements = get_pcrs(
        &mut eif_reader.image_hasher,
        &mut eif_reader.bootstrap_hasher,
        &mut eif_reader.app_hasher,
        &mut eif_reader.cert_hasher,
        Sha384::new(),
        eif_reader.signature_section.is_some(),
    )
    .map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to get PCR values: {e:?}"),
            NitroCliErrorEnum::EifParsingError
        )
    })?;

    let mut describe_meta: Option<MetadataDescribeInfo> = None;
    let mut img_name: Option<String> = None;
    let mut img_version: Option<String> = None;

    if let Some(meta) = eif_reader.get_metadata() {
        img_name = Some(meta.img_name.clone());
        img_version = Some(meta.img_version.clone());
        describe_meta = Some(MetadataDescribeInfo::new(meta));
    }

    let mut info = EifDescribeInfo {
        version: eif_reader.get_header().version,
        build_info: EnclaveBuildInfo::new(measurements.clone()),
        is_signed: false,
        cert_info: None,
        crc_check: eif_reader.check_crc(),
        sign_check: None,
        img_name,
        img_version,
        metadata: describe_meta,
    };

    // Check if signature section is present
    if measurements.contains_key("PCR8") {
        let cert_info = eif_reader
            .get_certificate_info(measurements)
            .map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to get certificate sigining info: {err:?}"),
                    NitroCliErrorEnum::EifParsingError
                )
            })?;
        info.is_signed = true;
        info.cert_info = Some(cert_info);
        info.sign_check = eif_reader.sign_check;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&info)
            .map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to display EIF describe data: {err:?}"),
                    NitroCliErrorEnum::SerdeError
                )
            })?
            .as_str(),
    );

    Ok(info)
}

/// Signs EIF with the given key and certificate. If EIF already has a signature, it will be replaced.
pub fn sign_eif(args: SignEifArgs) -> NitroCliResult<()> {
    let sign_info = match (&args.private_key, &args.signing_certificate) {
        (Some(key), Some(cert)) => SignKeyData::new(key, Path::new(&cert)).map_or_else(
            |e| {
                eprintln!("Could not read signing info: {e:?}");
                None
            },
            Some,
        ),
        _ => None,
    };

    let signer = EifSigner::new(sign_info).ok_or_else(|| {
        new_nitro_cli_failure!(
            format!("Failed to create EifSigner"),
            NitroCliErrorEnum::EIFSigningError
        )
    })?;

    signer.sign_image(&args.eif_path).map_err(|e| {
        new_nitro_cli_failure!(
            format!("Failed to sign image: {}", e),
            NitroCliErrorEnum::EIFSigningError
        )
    })?;

    eprintln!("Enclave Image successfully signed.");

    let mut eif_reader = EifReader::from_eif(args.eif_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to initialize EIF reader: {e:?}"),
            NitroCliErrorEnum::EifParsingError
        )
    })?;
    eif_reader
        .get_measurements()
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to get PCR values: {e:?}"),
                NitroCliErrorEnum::EifParsingError
            )
        })
        .and_then(|measurements| {
            let info = EnclaveBuildInfo::new(measurements);
            let printed_info = serde_json::to_string_pretty(&info).map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to display EnclaveBuild data: {err:?}"),
                    NitroCliErrorEnum::SerdeError
                )
            })?;
            println!("{printed_info}");
            Ok(())
        })
}

/// Returns the value of the `NITRO_CLI_BLOBS` environment variable.
///
/// This variable specifies where all the blobs necessary for building
/// an enclave image are stored. As of now the blobs are:
/// - *bzImage*: A kernel image if the local arch is x86_64 or
/// - *Image*  : A kernel image if the local arch is aarch64
/// - *init*: The initial init process that is bootstraping the environment.
/// - *linuxkit*: A slightly modified version of linuxkit.
/// - *cmdline*: A file containing the kernel commandline.
fn blobs_path() -> NitroCliResult<String> {
    // TODO Improve error message with a suggestion to the user
    // consider using the default path used by rpm install
    let blobs_res = std::env::var("NITRO_CLI_BLOBS");

    Ok(blobs_res.unwrap_or_else(|_| DEFAULT_BLOBS_PATH.to_string()))
}

/// Returns the value of the `NITRO_CLI_ARTIFACTS` environment variable.
///
/// This variable configures the path where the build artifacts should be saved.
fn artifacts_path() -> NitroCliResult<String> {
    if let Ok(artifacts) = std::env::var("NITRO_CLI_ARTIFACTS") {
        std::fs::create_dir_all(artifacts.clone()).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Could not create artifacts path {artifacts}: {e:?}"),
                NitroCliErrorEnum::FileOperationFailure
            )
            .add_info(vec![&artifacts, "Create"])
        })?;
        Ok(artifacts)
    } else if let Ok(home) = std::env::var("HOME") {
        let artifacts = format!("{home}/.nitro_cli/");
        std::fs::create_dir_all(artifacts.clone()).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Could not create artifacts path {artifacts}: {e:?}"),
                NitroCliErrorEnum::FileOperationFailure
            )
            .add_info(vec![&artifacts, "Create"])
        })?;
        Ok(artifacts)
    } else {
        Err(new_nitro_cli_failure!(
            "Could not find a folder for the CLI artifacts, set either HOME or NITRO_CLI_ARTIFACTS",
            NitroCliErrorEnum::ArtifactsPathNotSet
        ))
    }
}

/// Wrapper over the console connection function.
pub fn console_enclaves(
    enclave_cid: u64,
    disconnect_timeout_sec: Option<u64>,
) -> NitroCliResult<()> {
    debug!("console_enclaves");
    println!("Connecting to the console for enclave {enclave_cid}...");
    enclave_console(enclave_cid, disconnect_timeout_sec)?;
    Ok(())
}

/// Connects to the enclave console and prints it continously.
pub fn enclave_console(
    enclave_cid: u64,
    disconnect_timeout_sec: Option<u64>,
) -> NitroCliResult<()> {
    let console = Console::new(
        VMADDR_CID_HYPERVISOR,
        u32::try_from(enclave_cid).map_err(|err| {
            new_nitro_cli_failure!(
                &format!("Failed to parse enclave CID: {err:?}"),
                NitroCliErrorEnum::IntegerParsingError
            )
        })? + CID_TO_CONSOLE_PORT_OFFSET,
    )
    .map_err(|e| e.add_subaction("Connect to enclave console".to_string()))?;
    println!("Successfully connected to the console.");
    console
        .read_to(io::stdout().by_ref(), disconnect_timeout_sec)
        .map_err(|e| e.add_subaction("Connect to enclave console".to_string()))?;

    Ok(())
}

/// Terminates all enclave instances belonging to the current user (or all
/// instances, if the current user has `root` permissions).
pub fn terminate_all_enclaves() -> NitroCliResult<()> {
    let sockets_dir = get_sockets_dir_path();
    let mut replies: Vec<UnixStream> = vec![];
    let sockets = std::fs::read_dir(sockets_dir.as_path()).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Error while accessing sockets directory: {e:?}"),
            NitroCliErrorEnum::FileOperationFailure
        )
        .add_info(vec![
            sockets_dir
                .as_path()
                .to_str()
                .unwrap_or("Invalid unicode directory name"),
            "Read",
        ])
    })?;

    let mut err_socket_files: usize = 0;
    let mut failed_connections: Vec<PathBuf> = Vec::new();
    for socket in sockets {
        let entry = match socket {
            Ok(value) => value,
            Err(_) => {
                err_socket_files += 1;
                continue;
            }
        };

        // Send a `terminate-enclave` command through each socket,
        // irrespective of the enclave process owner. The security policy
        // inside the enclave process is responsible with checking the
        // command's permissions.
        let mut stream = match UnixStream::connect(entry.path()) {
            Ok(value) => value,
            Err(_) => {
                failed_connections.push(entry.path());
                continue;
            }
        };

        if enclave_proc_command_send_single::<EmptyArgs>(
            EnclaveProcessCommandType::Terminate,
            None,
            &mut stream,
        )
        .is_err()
        {
            failed_connections.push(entry.path());
        } else {
            replies.push(stream);
        }
    }

    // Remove stale socket files.
    for stale_socket in &failed_connections {
        info!("Deleting stale socket: {:?}", stale_socket);
        let _ = std::fs::remove_file(stale_socket);
    }

    enclave_process_handle_all_replies::<EnclaveTerminateInfo>(
        &mut replies,
        failed_connections.len() + err_socket_files,
        true,
        vec![0, libc::EACCES],
    )
    .map_err(|e| e.add_subaction("Failed to handle all enclave processes replies".to_string()))
    .map(|_| ())
}

/// Queries all enclaves for their name
pub fn get_all_enclave_names() -> NitroCliResult<Vec<String>> {
    let (comms, _) =
        enclave_proc_command_send_all::<EmptyArgs>(EnclaveProcessCommandType::GetEnclaveName, None)
            .map_err(|e| {
                e.add_subaction(
                    "Failed to send GetEnclaveName command to all enclave processes".to_string(),
                )
                .set_action("Get Enclave Names".to_string())
            })?;

    let mut replies: Vec<UnixStream> = vec![];
    replies.extend(comms);
    let objects = enclave_proc_handle_outputs::<String>(&mut replies)
        .iter()
        .map(|v| v.0.clone())
        .collect();
    Ok(objects)
}

/// Sends the name to all the running enclaves and expects a response
/// with the ID of the one that uniquely matched
pub fn get_id_by_name(name: String) -> NitroCliResult<String> {
    let (comms, _) = enclave_proc_command_send_all::<String>(
        EnclaveProcessCommandType::GetIDbyName,
        Some(&name),
    )
    .map_err(|e| {
        e.add_subaction("Failed to send GetIDbyName command to all enclave processes".to_string())
            .set_action("Get Enclave Names".to_string())
    })?;

    let mut replies: Vec<UnixStream> = vec![];
    replies.extend(comms);
    let mut objects: Vec<String> = enclave_proc_handle_outputs::<String>(&mut replies)
        .iter()
        .map(|v| v.0.clone())
        .collect();

    // Check if the name was not found or if there are multiple matches
    if objects.len() != 1 {
        return Err(new_nitro_cli_failure!(
            match objects.len() {
                0 => "No enclave matched the given name.".to_string(),
                _ => "Conflicting enclave names have been found.".to_string(),
            },
            NitroCliErrorEnum::EnclaveNamingError
        ));
    }

    Ok(objects.remove(0))
}

/// For the given file, return the PCR value
///
/// Based on the pcr_type, calculate the PCR hash of the input. The default
/// type takes the bytes of the input file and adds them to the hasher.
/// The certificate type performs additional serialization before hashing.
pub fn get_file_pcr(path: String, pcr_type: PcrType) -> NitroCliResult<BTreeMap<String, String>> {
    let mut key = "PCR".to_string();
    // Initialize hasher
    let mut hasher = EifHasher::new_without_cache(Sha384::new()).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Could not create hasher: {e:?}"),
            NitroCliErrorEnum::HasherError
        )
    })?;
    let mut file = File::open(path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to open file: {e:?}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to read file: {e:?}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    // Treat the input buffer by PCR type
    match pcr_type {
        PcrType::DefaultType => {}
        PcrType::SigningCertificate => {
            key = "PCR8".to_string();
            let cert = openssl::x509::X509::from_pem(&buf[..]).map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to deserialize .pem: {e:?}"),
                    NitroCliErrorEnum::HasherError
                )
            })?;
            buf = cert.to_der().map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to serialize certificate: {e:?}"),
                    NitroCliErrorEnum::HasherError
                )
            })?;
        }
    }
    hasher.write_all(&buf).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Could not write to hasher: {e:?}"),
            NitroCliErrorEnum::HasherError
        )
    })?;
    let hash = hex::encode(hasher.tpm_extend_finalize_reset().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Could not get result for hasher: {e:?}"),
            NitroCliErrorEnum::HasherError
        )
    })?);

    let mut result = BTreeMap::new();
    result.insert(key, hash);
    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to display PCR(s): {err:?}"),
                    NitroCliErrorEnum::SerdeError
                )
            })?
            .as_str(),
    );
    Ok(result)
}

/// Macro defining the arguments configuration for a *Nitro CLI* application.
#[macro_export]
macro_rules! create_app {
    () => {
        Command::new("Nitro CLI")
            .about("CLI for enclave lifetime management")
            .arg_required_else_help(true)
            .subcommand(
                Command::new("run-enclave")
                    .about("Starts a new enclave")
                    .arg(
                        Arg::new("cpu-ids")
                            .long("cpu-ids")
                            .help("List of cpu-ids that will be provided to the enclave")
                            .num_args(1..)
                            .required_unless_present_any(["cpu-count", "config"])
                            .conflicts_with_all(["cpu-count", "config"]),
                    )
                    .arg(
                        Arg::new("cpu-count")
                            .long("cpu-count")
                            .help("Number of cpus")
                            .required_unless_present_any(["cpu-ids", "config"])
                            .conflicts_with_all(["cpu-ids", "config"]),
                    )
                    .arg(
                        Arg::new("memory")
                            .long("memory")
                            .help(
                                "Memory to allocate for the enclave in MB. Depending on the available \
                                pages, more might be allocated."
                            )
                            .required_unless_present("config")
                            .conflicts_with("config"),
                    )
                    .arg(
                        Arg::new("eif-path")
                            .long("eif-path")
                            .help("Path pointing to a prebuilt Eif image")
                            .required_unless_present("config")
                            .conflicts_with("config"),
                    )
                    .arg(
                        Arg::new("enclave-cid")
                            .long("enclave-cid")
                            .help("CID to be used for the newly started enclave")
                            .conflicts_with("config"),
                    )
                    .arg(
                        Arg::new("debug-mode")
                            .long("debug-mode")
                            .action(clap::ArgAction::SetTrue)
                            .help(
                                "Starts enclave in debug-mode. This makes the console of the enclave \
                                available over vsock at CID: VMADDR_CID_HYPERVISOR (0), port: \
                                enclave_cid + 10000. \n The stream could be accessed with the console \
                                sub-command"
                            )
                            .conflicts_with("config"),
                    )
                    .arg(
                        Arg::new("attach-console")
                            .long("attach-console")
                            .action(clap::ArgAction::SetTrue)
                            .help(
                                "Attach the enclave console immediately after starting the enclave. \
                                (implies debug-mode)"
                            )
                    )
                    .arg(
                        Arg::new("enclave-name")
                            .long("enclave-name")
                            .help("Custom name assigned to the enclave by the user")
                            .conflicts_with("config"),
                    )
                    .arg(
                        Arg::new("config")
                            .long("config")
                            .value_name("json-config")
                            .help("Config is used to read enclave settings from JSON file"),
                    ),
            )
            .subcommand(
                Command::new("terminate-enclave")
                    .about("Terminates an enclave")
                    .arg(
                        Arg::new("enclave-id")
                            .long("enclave-id")
                            .help("Enclave ID, used to uniquely identify an enclave")
                            .required_unless_present_any(["all", "enclave-name"])
                            .conflicts_with_all(["all", "enclave-name"]),
                    )
                    .arg(
                        Arg::new("all")
                            .long("all")
                            .action(clap::ArgAction::SetTrue)
                            .help("Terminate all running enclave instances belonging to the current user")
                            .required_unless_present_any(["enclave-id", "enclave-name"])
                            .conflicts_with_all(["enclave-id", "enclave-name"]),
                    )
                    .arg(
                        Arg::new("enclave-name")
                            .long("enclave-name")
                            .help("Enclave name, used to uniquely identify an enclave")
                            .required_unless_present_any(["enclave-id", "all"])
                            .conflicts_with_all(["enclave-id", "all"]),
                    ),
            )
            .subcommand(
                Command::new("build-enclave")
                    .about("Builds an enclave image and saves it to a file")
                    .arg(
                        Arg::new("docker-uri")
                            .long("docker-uri")
                            .help(
                                "Uri pointing to an existing docker container or to be created \
                                locally when docker-dir is present"
                            )
                            .required(true),
                    )
                    .arg(
                        Arg::new("docker-dir")
                            .long("docker-dir")
                            .help("Local path to a directory containing a Dockerfile"),
                    )
                    .arg(
                        Arg::new("output-file")
                            .long("output-file")
                            .help("Location where the Enclave Image should be saved")
                            .required(true),
                    )
                    .arg(
                        Arg::new("signing-certificate")
                            .long("signing-certificate")
                            .help("Local path to developer's X509 signing certificate.")
                            .requires("private-key"),
                    )
                    .arg(
                        Arg::new("private-key")
                            .long("private-key")
                            .help("KMS key ARN or local path to developer's Eliptic Curve private key.")
                            .requires("signing-certificate"),
                    )
                    .arg(
                        Arg::new("image_name")
                            .long("name")
                            .help("Name for enclave image"),
                    )
                    .arg(
                        Arg::new("image_version")
                            .long("version")
                            .help("Version of the enclave image"),
                    )
                    .arg(
                        Arg::new("metadata")
                            .long("metadata")
                            .help("Path to JSON containing the custom metadata provided by the user."),
                    ),
            )
            .subcommand(
                Command::new("describe-eif")
                    .about("Returns information about the EIF found at a given path.")
                    .arg(
                        Arg::new("eif-path")
                            .long("eif-path")
                            .help("Path to the EIF to describe.")
                            .required(true),
                    ),
            )
            .subcommand(
                Command::new("describe-enclaves")
                    .about("Returns a list of the running enclaves")
                    .arg(
                        Arg::new("metadata")
                            .long("metadata")
                            .help("Adds EIF metadata of the current enclaves to the command output.")
                            .action(clap::ArgAction::SetTrue)
                        ),
            )
            .subcommand(
                Command::new("console")
                    .about("Connect to the console of an enclave")
                    .arg(
                        Arg::new("enclave-id")
                            .long("enclave-id")
                            .help("Enclave ID, used to uniquely identify an enclave")
                            .required_unless_present("enclave-name")
                            .conflicts_with("enclave-name"),
                    )
                    .arg(
                        Arg::new("disconnect-timeout")
                            .long("disconnect-timeout")
                            .help("The time in seconds after the console disconnects from the enclave"),
                    )
                    .arg(
                        Arg::new("enclave-name")
                            .long("enclave-name")
                            .help("Enclave name, used to uniquely identify an enclave")
                            .required_unless_present("enclave-id")
                            .conflicts_with("enclave-id"),
                    ),
            )
            .subcommand(
                Command::new("pcr")
                    .about("Return the PCR hash value of the given input")
                    .arg(
                        Arg::new("signing-certificate")
                            .long("signing-certificate")
                            .help("Takes the path to the '.pem' signing certificate and returns PCR8. Can be used to identify the certificate used to sign an EIF")
                            .required_unless_present("input")
                            .conflicts_with("input"),
                    )
                    .arg(
                        Arg::new("input")
                            .long("input")
                            .help("Given a path to a file, returns the PCR hash of the bytes it contains")
                            .required_unless_present("signing-certificate")
                            .conflicts_with("signing-certificate"),
                    ),
            )
            .subcommand(
                Command::new("explain")
                    .about("Display detailed information about an error returned by a misbehaving Nitro CLI command")
                    .arg(
                        Arg::new("error-code")
                            .long("error-code")
                            .help("Error code, as returned by the misbehaving Nitro CLI command")
                            .required(true),
                    ),
            )
            .subcommand(
                Command::new("sign-eif")
                    .about("Sign EIF with the given key")
                    .arg(
                        Arg::new("eif-path")
                            .long("eif-path")
                            .help("Path pointing to a prebuilt Eif image")
                    )
                    .arg(
                        Arg::new("signing-certificate")
                            .long("signing-certificate")
                            .help("Local path to developer's X509 signing certificate.")
                            .requires("private-key"),
                    )
                    .arg(
                        Arg::new("private-key")
                            .long("private-key")
                            .help("KMS key ARN or local path to developer's Eliptic Curve private key.")
                            .requires("signing-certificate"),
                    )
            )
    };
}
