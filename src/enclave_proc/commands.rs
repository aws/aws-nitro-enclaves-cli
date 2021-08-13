// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use eif_utils::{get_pcrs, EifReader, PcrSignatureChecker};
use log::debug;
use serde_json::Value;
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;
use std::fs::File;
use std::thread::JoinHandle;

use crate::common::commands_parser::RunEnclavesArgs;
use crate::common::construct_error_message;
use crate::common::json_output::{DescribeMetadata, EnclaveBuildInfo, EnclaveTerminateInfo};
use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::enclave_proc::connection::Connection;
use crate::enclave_proc::connection::{safe_conn_eprintln, safe_conn_println};
use crate::enclave_proc::cpu_info::CpuInfo;
use crate::enclave_proc::resource_manager::{EnclaveManager, EnclaveState};
use crate::enclave_proc::utils::{get_enclave_describe_info, InfoLevel};
use crate::new_nitro_cli_failure;

/// Thread handle from parallel computing of PCRs
pub type PcrThread = Option<JoinHandle<NitroCliResult<(BTreeMap<String, String>, Value)>>>;

/// Information retuned by run_enclave function.
pub struct RunEnclaveResult {
    /// Manager structure describing the enclave.
    pub enclave_manager: EnclaveManager,
    /// Handle of the thread that computes PCRs.
    pub pcr_thread: PcrThread,
}

/// Launch an enclave with the specified arguments and provide the launch status through the given connection.
pub fn run_enclaves(
    args: &RunEnclavesArgs,
    connection: Option<&Connection>,
) -> NitroCliResult<RunEnclaveResult> {
    debug!("run_enclaves");

    let eif_file = File::open(&args.eif_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to open the EIF file: {:?}", e),
            NitroCliErrorEnum::FileOperationFailure
        )
        .add_info(vec![&args.eif_path, "Open"])
    })?;

    let cpu_ids = CpuInfo::new()
        .map_err(|e| e.add_subaction("Failed to construct CPU information".to_string()))?
        .get_cpu_config(args)
        .map_err(|e| e.add_subaction("Failed to get CPU configuration".to_string()))?;

    let enclave_name = match &args.enclave_name {
        Some(enclave_name) => enclave_name,
        None => {
            return Err(new_nitro_cli_failure!(
                "Failed to set enclave name in the manager".to_string(),
                NitroCliErrorEnum::FileOperationFailure
            ))
        }
    };

    let mut enclave_manager = EnclaveManager::new(
        args.enclave_cid,
        args.memory_mib,
        cpu_ids,
        eif_file,
        args.debug_mode.unwrap_or(false),
        enclave_name.to_string(),
    )
    .map_err(|e| {
        e.add_subaction("Failed to construct EnclaveManager with given arguments".to_string())
    })?;

    let mut signature_checker = PcrSignatureChecker::from_eif(&args.eif_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create EIF signature checker: {:?}", e),
            NitroCliErrorEnum::EIFSignatureCheckerError
        )
    })?;

    // Verify the certificate only if signature section exists
    if !signature_checker.is_empty() {
        signature_checker.verify().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Invalid signing certificate: {:?}", e),
                NitroCliErrorEnum::EIFSignatureCheckerError
            )
        })?;
    }

    // Launch parallel computing of PCRs
    let path = args.eif_path.clone();
    let handle = std::thread::spawn(move || {
        let mut eif_reader = EifReader::from_eif(path).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed initialize EIF reader: {:?}", e),
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
                &format!("Failed to calculate PCRs: {:?}", e),
                NitroCliErrorEnum::EifParsingError
            )
        })?;
        Ok((measurements, eif_reader.metadata))
    });
    enclave_manager
        .run_enclave(connection)
        .map_err(|e| e.add_subaction("Failed to run enclave".to_string()))?;
    enclave_manager
        .update_state(EnclaveState::Running)
        .map_err(|e| e.add_subaction("Failed to update enclave state".to_string()))?;

    Ok(RunEnclaveResult {
        enclave_manager,
        pcr_thread: Some(handle),
    })
}

/// Terminate an enclave and provide the termination status through the given connection.
pub fn terminate_enclaves(
    enclave_manager: &mut EnclaveManager,
    connection: Option<&Connection>,
) -> NitroCliResult<()> {
    let enclave_id = enclave_manager.enclave_id.clone();
    let enclave_name = Some(enclave_manager.enclave_name.clone());

    debug!("terminate_enclaves");
    enclave_manager
        .update_state(EnclaveState::Terminating)
        .map_err(|e| e.add_subaction("Failed to update enclave state".to_string()))?;
    if let Err(error_info) = enclave_manager.terminate_enclave() {
        safe_conn_eprintln(
            connection,
            format!(
                "Warning: Failed to stop enclave {}\nError message: {:?}",
                enclave_manager.enclave_id,
                construct_error_message(&error_info).as_str()
            )
            .as_str(),
        )?;
        return Err(error_info);
    }

    enclave_manager.update_state(EnclaveState::Empty)?;
    safe_conn_eprintln(
        connection,
        format!(
            "Successfully terminated enclave {}.",
            enclave_manager.enclave_id
        )
        .as_str(),
    )?;

    // We notify the CLI of the termination's status.
    safe_conn_println(
        connection,
        serde_json::to_string_pretty(&EnclaveTerminateInfo::new(enclave_name, enclave_id, true))
            .map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to display enclave termination data: {:?}", err),
                    NitroCliErrorEnum::SerdeError
                )
            })?
            .as_str(),
    )
}

/// Obtain an enclave's description and provide it through the given connection.
pub fn describe_enclaves(
    enclave_manager: &EnclaveManager,
    connection: &Connection,
    add_info: InfoLevel,
) -> NitroCliResult<()> {
    debug!("describe_enclaves");

    let mut info = get_enclave_describe_info(enclave_manager)
        .map_err(|e| e.add_subaction(String::from("Execute Describe Enclave command")))?;
    // Check if the run_enclave command version calculated the measurements
    let mut build_info: Option<EnclaveBuildInfo> = None;
    let mut name: Option<String> = None;
    let mut metadata: Option<DescribeMetadata> = None;
    let mut img_name: Option<Value> = None;
    let mut img_version: Option<Value> = None;

    match add_info {
        InfoLevel::Basic => {}
        InfoLevel::Measured => {
            build_info = Some(enclave_manager.get_measurements()?);
            name = Some(enclave_manager.enclave_name.clone());
        }
        InfoLevel::Metadata => {
            build_info = Some(enclave_manager.get_measurements()?);
            name = Some(enclave_manager.enclave_name.clone());
            let raw_metadata = enclave_manager.get_metadata()?;
            if !raw_metadata.is_null() {
                img_name = raw_metadata.get("ImageName").cloned();
                img_version = raw_metadata.get("ImageVersion").cloned();
                let describe_meta = DescribeMetadata::new(
                    match raw_metadata.get("GeneratedMetadata") {
                        Some(meta) => meta.clone(),
                        None => {
                            return Err(new_nitro_cli_failure!(
                                &"Missing generated metadata.".to_string(),
                                NitroCliErrorEnum::SerdeError
                            ))
                        }
                    },
                    match raw_metadata.get("DockerInfo") {
                        Some(meta) => meta.clone(),
                        None => {
                            return Err(new_nitro_cli_failure!(
                                &"Missing docker information.".to_string(),
                                NitroCliErrorEnum::SerdeError
                            ))
                        }
                    },
                    raw_metadata.get("CustomMetadata").cloned(),
                )
                .map_err(|err| {
                    new_nitro_cli_failure!(
                        &format!("Failed to construct enclave metadata: {:?}", err),
                        NitroCliErrorEnum::SerdeError
                    )
                })?;
                metadata = Some(describe_meta);
            }
        }
    }

    info.enclave_name = name;
    info.img_name = img_name;
    info.img_version = img_version;
    info.build_info = build_info;
    info.metadata = metadata;

    connection.println(
        serde_json::to_string_pretty(&info)
            .map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("Failed to display enclave describe data: {:?}", err),
                    NitroCliErrorEnum::SerdeError
                )
            })?
            .as_str(),
    )
}
