// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

//! This crate provides the functionality for managing nitro enclaves.

/// The common module (shared between the CLI and enclave process).
pub mod common;
/// The enclave process module.
pub mod enclave_proc;
/// The module covering the communication between a CLI instance and enclave processes.
pub mod enclave_proc_comm;

use bitflags::*;
use common::commands_parser::{EmptyArgs, RunEnclavesArgs};
use common::json_output::{EnclaveDescribeInfo, EnclaveRunInfo, EnclaveTerminateInfo};
use common::{
    enclave_proc_command_send_single, get_sockets_dir_path, logger, read_u64_le,
    EnclaveProcessCommandType, NitroCliErrorEnum, NitroCliFailure, MSG_ENCLAVE_CONFIRM,
};
use enclave_proc::resource_manager::EnclaveState;
use enclave_proc::utils::generate_enclave_id;
use enclave_proc_comm::{
    enclave_proc_connect_to_single, enclave_proc_handle_output, enclave_proc_spawn,
};

use std::fs;
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;

/// The result returned by almost all operations.
pub type EnclaveResult<T> = Result<T, NitroCliFailure>;

bitflags! {
    /// Structure for describing enclave flags.
    pub struct EnclaveFlags: u32 {
        /// No flag
        const NONE = 0b0000_0000;
        /// Debug flag
        const DEBUG_MODE = 0b0000_0001;
    }
}

impl Into<String> for EnclaveFlags {
    fn into(self) -> String {
        match self {
            EnclaveFlags::DEBUG_MODE => "DEBUG_MODE".to_string(),
            _ => "NONE".to_string(),
        }
    }
}

/// Enclave configuration structure
#[derive(Clone)]
pub struct EnclaveConf {
    /// Path to enclave image file
    pub eif_path: String,
    /// Requested memory by the user
    pub mem_size: u64,
    /// User's cpu configuration
    pub cpu_conf: EnclaveCpuConfig,
    /// Enclave cid
    pub cid: Option<u64>,
    /// Enclave flags
    pub flags: EnclaveFlags,
}

/// Enclave CPU configuration
#[derive(Clone)]
pub enum EnclaveCpuConfig {
    /// List of CPUs
    List(Vec<u32>),
    /// Number of CPUs
    Count(u32),
}

/// Enclave structure
#[derive(Clone)]
pub struct Enclave {
    /// Enclave's id
    enclave_id: String,
    /// Enclave process id
    process_id: u32,
    /// Enclave cid
    enclave_cid: u64,
    /// Enclave number of CPUs
    cpu_count: u64,
    /// CPUs used by the enclave
    cpu_ids: Vec<u32>,
    /// Memory used by the enclave (in MiB)
    memory_size: u64,
    /// Enclave's state
    state: EnclaveState,
    /// Enclave's flags
    flags: EnclaveFlags,
}

impl From<EnclaveDescribeInfo> for Enclave {
    fn from(info: EnclaveDescribeInfo) -> Self {
        let flags = if info.flags == "DEBUG_MODE" {
            EnclaveFlags::DEBUG_MODE
        } else {
            EnclaveFlags::NONE
        };

        let state = match info.state.as_str() {
            "RUNNING" => EnclaveState::Running,
            "TERMINATING" => EnclaveState::Terminating,
            _ => EnclaveState::Empty,
        };

        Enclave {
            enclave_id: info.enclave_id,
            process_id: info.process_id,
            enclave_cid: info.enclave_cid,
            cpu_count: info.cpu_count,
            cpu_ids: info.cpu_ids,
            memory_size: info.memory_mib,
            state,
            flags,
        }
    }
}

impl Into<EnclaveRunInfo> for Enclave {
    fn into(self) -> EnclaveRunInfo {
        EnclaveRunInfo {
            enclave_id: self.enclave_id,
            process_id: self.process_id,
            enclave_cid: self.enclave_cid,
            cpu_count: self.cpu_count as usize,
            cpu_ids: self.cpu_ids,
            memory_mib: self.memory_size,
        }
    }
}

impl Into<EnclaveDescribeInfo> for Enclave {
    fn into(self) -> EnclaveDescribeInfo {
        EnclaveDescribeInfo {
            enclave_id: self.enclave_id,
            process_id: self.process_id,
            enclave_cid: self.enclave_cid,
            cpu_count: self.cpu_count,
            cpu_ids: self.cpu_ids,
            memory_mib: self.memory_size,
            state: self.state.into(),
            flags: self.flags.into(),
        }
    }
}

impl Enclave {
    fn from_run_info(info: EnclaveRunInfo, state: EnclaveState, flags: EnclaveFlags) -> Self {
        Enclave {
            enclave_id: info.enclave_id,
            process_id: info.process_id,
            enclave_cid: info.enclave_cid,
            cpu_count: info.cpu_count as u64,
            cpu_ids: info.cpu_ids,
            memory_size: info.memory_mib,
            state,
            flags,
        }
    }

    /// Returns the enclave id
    pub fn get_enclave_id(&self) -> String {
        self.enclave_id.clone()
    }

    /// Returns the process id
    pub fn get_process_id(&self) -> u32 {
        self.process_id
    }

    /// Returns the enclave cid
    pub fn get_enclave_cid(&self) -> u64 {
        self.enclave_cid
    }

    /// Returns the number of CPUs used
    pub fn get_cpu_count(&self) -> u64 {
        self.cpu_count
    }

    /// Returns which CPUs are used
    pub fn get_cpu_ids(&self) -> Vec<u32> {
        self.cpu_ids.clone()
    }

    /// Returns memory allocated for the enclave
    pub fn get_memory_size(&self) -> u64 {
        self.memory_size
    }

    /// Returns the state of the enclave
    pub fn get_state(&self) -> EnclaveState {
        self.state.clone()
    }

    /// Returns enclave's flags
    pub fn get_flags(&self) -> EnclaveFlags {
        self.flags
    }

    /// Describes an enclave (provides more info about an enclave)
    pub fn describe(enclave_id: String) -> EnclaveResult<Self> {
        let mut comm = enclave_proc_connect_to_single(&enclave_id)
            .map_err(|e| format!("Failed to connect to enclave process: {:?}", e))
            .unwrap();

        enclave_proc_command_send_single::<EmptyArgs>(
            EnclaveProcessCommandType::Describe,
            None,
            &mut comm,
        )
        .map_err(|e| {
            e.add_subaction("Failed to send describe enclave command".to_string())
                .set_action("Send describe command".to_string())
        })?;

        let mut input_stream = unsafe { UnixStream::from_raw_fd(comm.as_raw_fd()) };
        let reply = read_u64_le(&mut input_stream).map_err(|e| {
            e.add_subaction("Failed to send describe enclave command".to_string())
                .set_action("Send describe command".to_string())
        })?;

        if reply != MSG_ENCLAVE_CONFIRM {
            return Err(new_nitro_cli_failure!(
                "Failed to communicate with enclave procces.".to_string(),
                NitroCliErrorEnum::UnusableConnectionError
            ));
        }

        let describe_info =
            enclave_proc_handle_output::<EnclaveDescribeInfo>(&mut comm).map_err(|e| {
                e.add_subaction("Failed to handle response of describe enclave command".to_string())
                    .set_action("Send describe command".to_string())
            })?;

        Ok(Enclave::from(describe_info))
    }

    /// Runs a new enclave given a configuration
    pub fn run(conf: EnclaveConf) -> EnclaveResult<Self> {
        let logger =
            logger::init_logger().map_err(|e| e.set_action("Logger initialization".to_string()))?;
        logger
            .update_logger_id(format!("enclave-api:{}", std::process::id()).as_str())
            .map_err(|e| e.set_action("Update Enclave Process Logger ID".to_string()))?;

        let mut comm = enclave_proc_spawn(&logger).map_err(|err| {
            err.add_subaction("Failed to spawn enclave process".to_string())
                .set_action("Run enclave".to_string())
        })?;

        let mut cpu_ids = None;
        let mut cpu_count = None;
        match conf.cpu_conf {
            EnclaveCpuConfig::Count(n) => cpu_count = Some(n),
            EnclaveCpuConfig::List(v) => cpu_ids = Some(v),
        };

        let run_args = RunEnclavesArgs {
            eif_path: conf.eif_path,
            enclave_cid: conf.cid,
            memory_mib: conf.mem_size,
            cpu_ids,
            debug_mode: Some(conf.flags.bits() != 0),
            cpu_count,
        };

        enclave_proc_command_send_single(
            EnclaveProcessCommandType::Run,
            Some(&run_args),
            &mut comm,
        )
        .map_err(|e| {
            e.add_subaction("Failed to send run enclave command".to_string())
                .set_action("Send run command".to_string())
        })?;

        let run_info = enclave_proc_handle_output::<EnclaveRunInfo>(&mut comm).map_err(|e| {
            e.add_subaction("Failed to handle response of run enclave command".to_string())
                .set_action("Send run command".to_string())
        })?;
        Ok(Enclave::from_run_info(
            run_info,
            EnclaveState::Running,
            conf.flags,
        ))
    }

    /// Terminate a running enclave given an enclave id
    pub fn terminate_id(enclave_id: &str) -> EnclaveResult<()> {
        let mut comm = enclave_proc_connect_to_single(&enclave_id).map_err(|e| {
            e.add_subaction("Failed to connect to enclave process".to_string())
                .set_action("Termiante enclave".to_string())
        })?;

        enclave_proc_command_send_single::<EmptyArgs>(
            EnclaveProcessCommandType::Terminate,
            None,
            &mut comm,
        )
        .map_err(|e| {
            e.add_subaction("Failed to send terminate enclave command".to_string())
                .set_action("Send terminate command".to_string())
        })?;

        let _terminate_info = enclave_proc_handle_output::<EnclaveTerminateInfo>(&mut comm)
            .map_err(|e| {
                e.add_subaction(
                    "Failed to handle response of terminate enclave command".to_string(),
                )
                .set_action("Send terminate command".to_string())
            })?;

        Ok(())
    }

    /// Terminate a running enclave given an enclave object
    pub fn terminate(&mut self) -> EnclaveResult<()> {
        Enclave::terminate_id(&self.enclave_id)
    }

    /// List all running enclaves
    pub fn list() -> EnclaveResult<Vec<String>> {
        let paths = fs::read_dir(get_sockets_dir_path()).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to access sockets directory: {:?}", e),
                NitroCliErrorEnum::ReadFromDiskFailure
            )
        })?;

        Ok(paths
            .filter_map(|path| path.ok())
            .map(|path| path.path())
            .filter(|path| !path.is_dir())
            .filter_map(|path| {
                if let Some(path_str) = path.to_str() {
                    // Enclave process sockets are named "<enclave_id>.sock".
                    if !path_str.ends_with(".sock") {
                        return None;
                    }

                    // At this point we have found a potential socket.
                    match UnixStream::connect(path_str) {
                        Ok(_) => {
                            // Successfully connected to an enclave process.
                            let filename = path.file_name()?.to_str()?;
                            // Get slot uid from file name
                            if let Ok(slot_uid) = u64::from_str_radix(
                                &filename.trim_end_matches(".sock").to_string(),
                                16,
                            ) {
                                // Get enclave id from slot id
                                if let Ok(enclave_id) = generate_enclave_id(slot_uid) {
                                    return Some(enclave_id);
                                }
                            }
                        }
                        Err(e) => {
                            if e.kind() != ErrorKind::PermissionDenied {
                                // Delete only stale sockets.
                                let _ = fs::remove_file(path_str).map_err(|e| {
                                    new_nitro_cli_failure!(
                                        &format!("Failed to delete socket: {:?}", e),
                                        NitroCliErrorEnum::FileOperationFailure
                                    )
                                });
                            }
                        }
                    }
                }

                None
            })
            .collect())
    }
}
