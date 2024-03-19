// Copyright 2020-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

/// The module which parses command parameters from command-line arguments.
pub mod commands_parser;
/// The module which provides mappings between NitroCliErrors and their corresponding code.
pub mod document_errors;
/// The module which provides JSON-ready information structures.
pub mod json_output;
/// The module which provides the per-process logger.
pub mod logger;
/// The module which provides signal handling.
pub mod signal_handler;

use chrono::offset::Utc;
use log::error;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{Read, Write};

#[cfg(test)]
use std::os::raw::c_char;

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use document_errors::ERROR_CODES;
use logger::get_log_file_base_path;

/// The most common result type provided by Nitro CLI operations.
pub type NitroCliResult<T> = Result<T, NitroCliFailure>;

/// The CID for the vsock device of the parent VM.
pub const VMADDR_CID_PARENT: u32 = 3;

/// The vsock port used to confirm that the enclave has booted.
pub const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;

/// The amount of time in milliseconds an enclave process will wait for certain operations.
pub const ENCLAVE_PROC_WAIT_TIMEOUT_MSEC: isize = 3000;

/// The confirmation code sent by an enclave process to a requesting CLI instance
/// in order to signal that it is alive.
pub const MSG_ENCLAVE_CONFIRM: u64 = 0xEEC0;

/// The environment variable which holds the path to the Unix sockets directory.
pub const SOCKETS_DIR_PATH_ENV_VAR: &str = "NITRO_CLI_SOCKETS_PATH";

/// The default path to the Unix sockets directory.
const SOCKETS_DIR_PATH: &str = "/run/nitro_enclaves";

/// Constant used for identifying the backtrace environment variable.
const BACKTRACE_VAR: &str = "BACKTRACE";

/// All possible errors which may occur.
#[derive(Debug, Default, Clone, Copy, Hash, PartialEq)]
pub enum NitroCliErrorEnum {
    #[default]
    /// Unspecified error (should avoid using it thoughout the code).
    UnspecifiedError = 0,
    /// Error for handling missing arguments.
    MissingArgument,
    /// Error for handling conflicting arguments.
    ConflictingArgument,
    /// Invalid type argument.
    InvalidArgument,
    /// Failed to create socket pair.
    SocketPairCreationFailure,
    /// Failed to spawn a child process.
    ProcessSpawnFailure,
    /// Failed to daemonize current process.
    DaemonizeProcessFailure,
    /// Failed to read requested content from disk.
    ReadFromDiskFailure,
    /// Unusable connection error.
    UnusableConnectionError,
    /// Socket close error.
    SocketCloseError,
    /// Socket connect timeout error.
    SocketConnectTimeoutError,
    /// General error for handling socket-related errors.
    SocketError,
    /// General error for handling epoll-related errors.
    EpollError,
    /// General error for handling inotify-related errors.
    InotifyError,
    /// Invalid command format.
    InvalidCommand,
    /// Lock acquire failure.
    LockAcquireFailure,
    /// Thread join failure.
    ThreadJoinFailure,
    /// General error for handling serde-related errors.
    SerdeError,
    /// File permissions error.
    FilePermissionsError,
    /// File operation failure.
    FileOperationFailure,
    /// Invalid CPU list configuration.
    InvalidCpuConfiguration,
    /// Requested CPU not available in the pool.
    NoSuchCpuAvailableInPool,
    /// Not enough CPUs available in the pool.
    InsufficientCpus,
    /// Malformed CPU ID error.
    MalformedCpuId,
    /// General error to catch all other CPU-related errors.
    CpuError,
    /// No such hugepage map flag.
    NoSuchHugepageFlag,
    /// Insufficient memory requested.
    InsufficientMemoryRequested,
    /// Insufficient memory available.
    InsufficientMemoryAvailable,
    /// Invalid enclave file descriptor.
    InvalidEnclaveFd,
    /// General ioctl failure.
    IoctlFailure,
    /// Image load info ioctl failure.
    IoctlImageLoadInfoFailure,
    /// Enclave set memory region ioctl failure.
    IoctlSetMemoryRegionFailure,
    /// VCPU add ioctl failure.
    IoctlAddVcpuFailure,
    /// Enclave start ioctl failure.
    IoctlEnclaveStartFailure,
    /// Memory overflow.
    MemoryOverflow,
    /// General EIF parsing related error.
    EifParsingError,
    /// Error specific to enclave booting issues.
    EnclaveBootFailure,
    /// Enclave event wait error.
    EnclaveEventWaitError,
    /// Enclave process command was not executed.
    EnclaveProcessCommandNotExecuted,
    /// Could not connect to an enclave process.
    EnclaveProcessConnectionFailure,
    /// Socket path not found.
    SocketPathNotFound,
    /// Enclave process failed to send back reply.
    EnclaveProcessSendReplyFailure,
    /// Error when trying to allocate enclave memory regions.
    EnclaveMmapError,
    /// Error when trying to release enclave memory regions.
    EnclaveMunmapError,
    /// Enclave connection to console failed.
    EnclaveConsoleConnectionFailure,
    /// Error when reading from the console.
    EnclaveConsoleReadError,
    /// Error when writing console output to stream.
    EnclaveConsoleWriteOutputError,
    /// Integer parsing error.
    IntegerParsingError,
    /// Could not build EIF file.
    EifBuildingError,
    /// Could not build Docker image.
    DockerImageBuildError,
    /// Could not pull Docker image.
    DockerImagePullError,
    /// Artifacts path environment variable not set.
    ArtifactsPathNotSet,
    /// Blobs path environment variable not set.
    BlobsPathNotSet,
    /// Clock skew error.
    ClockSkewError,
    /// Signal masking error.
    SignalMaskingError,
    /// Signal unmasking error.
    SignalUnmaskingError,
    /// General error for handling logger-related errors.
    LoggerError,
    /// Hasher operation error
    HasherError,
    /// Enclave naming error
    EnclaveNamingError,
    /// Signature checker error
    EIFSignatureCheckerError,
}

impl Eq for NitroCliErrorEnum {}

/// The type of commands that can be sent to an enclave process.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnclaveProcessCommandType {
    /// Launch (run) an enclave (sent by the CLI).
    Run = 0,
    /// Terminate an enclave (sent by the CLI).
    Terminate,
    /// Notify that the enclave has terminated (sent by the enclave process to itself).
    TerminateComplete,
    /// Describe an enclave (broadcast by the CLI).
    Describe,
    /// Request an enclave's CID (sent by the CLI).
    GetEnclaveCID,
    /// Request an enclave's flags (sent by the CLI).
    GetEnclaveFlags,
    /// Request an enclave's name (sent by the CLI).
    GetEnclaveName,
    /// Request the ID of an enclave only if the name matches (sent by the CLI).
    GetIDbyName,
    /// Notify the socket connection listener to shut down (sent by the enclave process to itself).
    ConnectionListenerStop,
    /// Do not execute a command due to insufficient privileges (sent by the CLI, modified by the enclave process).
    NotPermitted,
}

/// The type of replies that an enclave process can send to a CLI instance.
#[derive(Debug, Serialize, Deserialize)]
pub enum EnclaveProcessReply {
    /// A message which must be printed to the CLI's standard output.
    StdOutMessage(String),
    /// A messge which must be printed to the CLI's standard error.
    StdErrMessage(String),
    /// The status of the operation that the enclave process has performed.
    Status(i32),
}

/// Struct that is passed along the backtrace and accumulates error messages.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NitroCliFailure {
    /// Main action which was attempted and failed.
    pub action: String,
    /// (Possibly) more subactions which lead to the root cause of the failure.
    pub subactions: Vec<String>,
    /// Computer-readable error code.
    pub error_code: NitroCliErrorEnum,
    /// File in which the root error occurred.
    pub file: String,
    /// Line at which the root error occurred.
    pub line: u32,
    /// Additional info regarding the error, passed as individual components (for easier parsing).
    pub additional_info: Vec<String>,
}

impl NitroCliFailure {
    /// Returns an empty `NitroCliFailure` object.
    pub fn new() -> Self {
        NitroCliFailure {
            action: String::new(),
            subactions: vec![],
            error_code: NitroCliErrorEnum::default(),
            file: String::new(),
            line: 0,
            additional_info: vec![],
        }
    }

    /// Sets the main action which failed (i.e. RUN_ENCLAVE).
    pub fn set_action(mut self, action: String) -> Self {
        self.action = action;
        self
    }

    /// Adds a new layer into the backtrace, corresponding to a failing subaction (i.e. NOT_ENOUGH_MEM).
    pub fn add_subaction(mut self, subaction: String) -> Self {
        self.subactions.push(subaction);
        self
    }

    /// Sets the error code.
    pub fn set_error_code(mut self, error_code: NitroCliErrorEnum) -> Self {
        self.error_code = error_code;
        self
    }

    /// Sets the name of the file the error occurred in.
    pub fn set_file(mut self, file: &str) -> Self {
        self.file = file.to_string();
        self
    }

    /// Sets the number of the line the error occurred on.
    pub fn set_line(mut self, line: u32) -> Self {
        self.line = line;
        self
    }

    /// Sets both error file and error line.
    pub fn set_file_and_line(mut self, file: &str, line: u32) -> Self {
        self.file = file.to_string();
        self.line = line;
        self
    }

    /// Include additional error information.
    pub fn add_info(mut self, info: Vec<&str>) -> Self {
        for info_ in info {
            self.additional_info.push(info_.to_string());
        }
        self
    }
}

/// Macro used for constructing a NitroCliFailure in a more convenient manner.
#[macro_export]
macro_rules! new_nitro_cli_failure {
    ($subaction:expr, $error_code:expr) => {
        NitroCliFailure::new()
            .add_subaction(($subaction).to_string())
            .set_error_code($error_code)
            .set_file_and_line(file!(), line!())
    };
}

/// Logs the given backtrace string to a separate, backtrace-specific file.
/// Returns a string denoting the path to the corresponding log file.
fn log_backtrace(backtrace: String) -> Result<String, &'static str> {
    let log_path_base = get_log_file_base_path();

    // Check if backtrace logs location exists and create it if necessary.
    if !Path::new(&log_path_base).exists() {
        let create_logs_dir = std::fs::create_dir_all(&log_path_base);
        if create_logs_dir.is_err() {
            return Err("Could not create backtrace logs directory");
        }
    }

    let utc_time_now = Utc::now().to_rfc3339();
    let log_path_str = format!("{}/err{}.log", &log_path_base, utc_time_now);
    let log_path = Path::new(&log_path_str);
    let log_file = std::fs::File::create(log_path);
    if log_file.is_err() {
        return Err("Could not create backtrace log file");
    }

    let write_result = log_file.unwrap().write_all(backtrace.as_bytes());
    if write_result.is_err() {
        return Err("Could not write to backtrace log file");
    }

    match log_path.to_str() {
        Some(log_path) => Ok(log_path.to_string()),
        None => Err("Could not return log file path"),
    }
}

/// Assembles the error message which gets displayed to the user.
pub fn construct_error_message(failure: &NitroCliFailure) -> String {
    // Suggestive error description comes first.
    let error_info: String = document_errors::get_detailed_info(
        (*ERROR_CODES.get(&failure.error_code).unwrap_or(&"E00")).to_string(),
        &failure.additional_info,
    );

    // Include a link to the documentation page.
    let help_link: String = document_errors::construct_help_link(
        (*ERROR_CODES.get(&failure.error_code).unwrap_or(&"E00")).to_string(),
    );
    let backtrace: String = document_errors::construct_backtrace(failure);

    // Write backtrace to a log file.
    let log_path = log_backtrace(backtrace.clone());

    // Return final output, depending on whether the user requested the backtrace or not.
    match std::env::var(BACKTRACE_VAR) {
        Ok(display_backtrace) => match display_backtrace.as_str() {
            "1" => {
                if let Ok(log_path) = log_path {
                    format!(
                        "{}\n\nFor more details, please visit {}\n\nBacktrace:\n{}\n\nIf you open a support ticket, please provide the error log found at \"{}\"",
                        error_info, help_link, backtrace, log_path
                    )
                } else {
                    format!(
                        "{}\n\nFor more details, please visit {}\n\nBacktrace:\n{}",
                        error_info, help_link, backtrace
                    )
                }
            }
            _ => {
                if let Ok(log_path) = log_path {
                    format!(
                        "{}\n\nFor more details, please visit {}\n\nIf you open a support ticket, please provide the error log found at \"{}\"",
                        error_info, help_link, log_path
                    )
                } else {
                    format!(
                        "{}\n\nFor more details, please visit {}",
                        error_info, help_link
                    )
                }
            }
        },
        _ => {
            if let Ok(log_path) = log_path {
                format!(
                    "{}\n\nFor more details, please visit {}\n\nIf you open a support ticket, please provide the error log found at \"{}\"",
                    error_info, help_link, log_path
                )
            } else {
                format!(
                    "{}\n\nFor more details, please visit {}",
                    error_info, help_link
                )
            }
        }
    }
}

/// A trait which allows a more graceful program exit instead of the standard `panic`.
/// Provides a custom exit code.
pub trait ExitGracefully<T> {
    /// Provide the inner value of a `Result` or exit gracefully with a message and custom errno.
    fn ok_or_exit_with_errno(self, additional_info: Option<&str>) -> T;
}

impl<T> ExitGracefully<T> for NitroCliResult<T> {
    /// Provide the inner value of a `Result` or exit gracefully with a message and custom errno.
    fn ok_or_exit_with_errno(self, additional_info: Option<&str>) -> T {
        match self {
            Ok(val) => val,
            Err(err) => {
                let err_str = construct_error_message(&err);
                if let Some(additional_info_str) = additional_info {
                    notify_error(&format!("{} | {}", additional_info_str, err_str));
                } else {
                    notify_error(&err_str);
                }
                std::process::exit(err.error_code as i32);
            }
        }
    }
}

/// Notify both the user and the logger of an error.
pub fn notify_error(err_msg: &str) {
    eprintln!("{}", err_msg);
    error!("{}", err_msg);
}

/// Read a LE-encoded 64-bit unsigned value from a socket.
pub fn read_u64_le(socket: &mut dyn Read) -> NitroCliResult<u64> {
    let mut bytes = [0u8; std::mem::size_of::<u64>()];
    socket.read_exact(&mut bytes).map_err(|e| {
        new_nitro_cli_failure!(
            &format!(
                "Failed to read {} bytes from the given socket: {:?}",
                std::mem::size_of::<u64>(),
                e
            ),
            NitroCliErrorEnum::SocketError
        )
    })?;

    Ok(u64::from_le_bytes(bytes))
}

/// Write a LE-encoded 64-bit unsigned value to a socket.
pub fn write_u64_le(socket: &mut dyn Write, value: u64) -> NitroCliResult<()> {
    let bytes = value.to_le_bytes();
    socket.write_all(&bytes).map_err(|e| {
        new_nitro_cli_failure!(
            &format!(
                "Failed to write {} bytes to the given socket: {:?}",
                std::mem::size_of::<u64>(),
                e
            ),
            NitroCliErrorEnum::SocketError
        )
    })
}

/// Send a command to a single socket.
pub fn enclave_proc_command_send_single<T>(
    cmd: EnclaveProcessCommandType,
    args: Option<&T>,
    mut socket: &mut UnixStream,
) -> NitroCliResult<()>
where
    T: Serialize,
{
    // Serialize the command type.
    let cmd_bytes = serde_cbor::to_vec(&cmd).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Invalid command format: {:?}", e),
            NitroCliErrorEnum::InvalidCommand
        )
    })?;

    // The command is written twice. The first read is done by the connection listener to check if this is
    // a shut-down command. The second read is done by the enclave process for all non-shut-down commands.
    for _ in 0..2 {
        write_u64_le(&mut socket, cmd_bytes.len() as u64)
            .map_err(|e| e.add_subaction("Failed to send single command size".to_string()))?;
        socket.write_all(&cmd_bytes[..]).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to send single command: {:?}", e),
                NitroCliErrorEnum::SocketError
            )
        })?;
    }

    // Serialize the command arguments.
    if let Some(args) = args {
        let arg_bytes = serde_cbor::to_vec(args).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Invalid single command arguments: {:?}", e),
                NitroCliErrorEnum::InvalidCommand
            )
        })?;

        // Write the serialized command arguments.
        write_u64_le(&mut socket, arg_bytes.len() as u64)
            .map_err(|e| e.add_subaction("Failed to send arguments size".to_string()))?;
        socket.write_all(&arg_bytes).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to send arguments: {:?}", e),
                NitroCliErrorEnum::SocketError
            )
        })?;
    }

    Ok(())
}

/// Receive an object of a specified type from an input stream.
pub fn receive_from_stream<T>(input_stream: &mut dyn Read) -> NitroCliResult<T>
where
    T: DeserializeOwned,
{
    let size = read_u64_le(input_stream)
        .map_err(|e| e.add_subaction("Failed to receive data size".to_string()))?
        as usize;
    let mut raw_data: Vec<u8> = vec![0; size];
    input_stream.read_exact(&mut raw_data[..]).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to receive data: {:?}", e),
            NitroCliErrorEnum::SocketError
        )
    })?;
    let data: T = serde_cbor::from_slice(&raw_data[..]).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to decode received data: {:?}", e),
            NitroCliErrorEnum::SerdeError
        )
    })?;
    Ok(data)
}

/// Get the path to the directory containing the Unix sockets owned by all enclave processes.
pub fn get_sockets_dir_path() -> PathBuf {
    let log_path = match env::var(SOCKETS_DIR_PATH_ENV_VAR) {
        Ok(env_path) => env_path,
        Err(_) => SOCKETS_DIR_PATH.to_string(),
    };
    Path::new(&log_path).to_path_buf()
}

/// Get the path to the Unix socket owned by an enclave process which also owns the enclave with the given ID.
pub fn get_socket_path(enclave_id: &str) -> NitroCliResult<PathBuf> {
    // The full enclave ID is "i-(...)-enc<enc_id>" and we want to extract only <enc_id>.
    let tokens: Vec<_> = enclave_id.rsplit("-enc").collect();
    let sockets_path = get_sockets_dir_path();
    Ok(sockets_path.join(tokens[0]).with_extension("sock"))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    use crate::common::commands_parser::EmptyArgs;

    const TMP_DIR_STR: &str = "./tmp_sock_dir";

    fn unset_envvar(varname: &str) {
        unsafe {
            libc::unsetenv(varname.as_ptr() as *const c_char);
        };
    }

    /// Tests that a value wrote by `write_u64_le()` is read
    /// correctly by `read_u64_le()`.
    #[test]
    fn test_read_write_u64() {
        let (mut sock0, mut sock1) = UnixStream::pair().unwrap();

        let _ = write_u64_le(&mut sock0, 127);
        let result = read_u64_le(&mut sock1);

        if let Ok(result) = result {
            assert_eq!(result, 127);
        }
    }

    /// Tests that a command sent though a socket by `enclave_proc_command_send_single()`
    /// is received correctly at the other end, by `receive_command_type()`.
    #[test]
    fn test_enclave_proc_command_send_single() {
        let (mut sock0, mut sock1) = UnixStream::pair().unwrap();
        let cmd = EnclaveProcessCommandType::Describe;
        let args: std::option::Option<&EmptyArgs> = None;

        let result0 = enclave_proc_command_send_single::<EmptyArgs>(cmd, args, &mut sock0);
        assert!(result0.is_ok());

        let result1 = receive_from_stream::<EnclaveProcessCommandType>(&mut sock1);
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), EnclaveProcessCommandType::Describe);
    }

    /// Tests that the returned sockets_dir_path matches the expected path,
    /// as retrieved from the corresponding environment variable.
    #[test]
    fn test_get_sockets_dir_path_default() {
        let sockets_dir = env::var(SOCKETS_DIR_PATH_ENV_VAR);
        let sockets_dir_path_f = get_sockets_dir_path();

        if let Ok(sockets_dir) = sockets_dir {
            assert_eq!(sockets_dir, sockets_dir_path_f.as_path().to_str().unwrap());
        } else {
            assert_eq!(
                SOCKETS_DIR_PATH,
                sockets_dir_path_f.as_path().to_str().unwrap()
            );
        }
    }

    /// Tests that altering the content of the sockets_dir_path environment variable
    /// changes the sockets_dir_path string returned by `get_sockets_dir_path()`.
    #[test]
    fn test_get_sockets_dir_path_custom_envvar() {
        let old_sockets_dir = env::var(SOCKETS_DIR_PATH_ENV_VAR);
        env::set_var(SOCKETS_DIR_PATH_ENV_VAR, TMP_DIR_STR);

        let sockets_dir_path_f = get_sockets_dir_path();

        assert_eq!(TMP_DIR_STR, sockets_dir_path_f.as_path().to_str().unwrap());

        // Restore previous environment variable value
        if let Ok(old_sockets_dir) = old_sockets_dir {
            env::set_var(SOCKETS_DIR_PATH_ENV_VAR, old_sockets_dir);
        } else {
            env::set_var(SOCKETS_DIR_PATH_ENV_VAR, "");
            unset_envvar(&String::from(SOCKETS_DIR_PATH_ENV_VAR));
        }
    }

    /// Tests that `get_socket_path()` returns the expected socket path,
    /// given a specific enclave id.
    #[test]
    fn test_get_socket_path_valid_id() {
        let enclave_id = "i-0000000000000000-enc0123456789012345";
        let tokens: Vec<_> = enclave_id.rsplit("-enc").collect();
        let sockets_path = get_sockets_dir_path();
        let result = get_socket_path(enclave_id);

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().as_path().to_str().unwrap(),
            format!(
                "{}/{}.sock",
                sockets_path.as_path().to_str().unwrap(),
                tokens[0]
            )
        );
    }

    /// Tests that `get_socket_path()` returns an invalid socket path,
    /// given a malformed enclave id.
    #[test]
    fn test_get_socket_path_invalid_id() {
        let enclave_id = "i-0000000000000000_enc0123456789012345";
        let sockets_path = get_sockets_dir_path();
        let result = get_socket_path(enclave_id);

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().as_path().to_str().unwrap(),
            format!(
                "{}/{}.sock",
                sockets_path.as_path().to_str().unwrap(),
                enclave_id
            )
        );
    }
}
