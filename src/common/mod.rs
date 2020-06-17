// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

/// The module which parses command parameters from command-line arguments.
pub mod commands_parser;
/// The module which provides JSON-ready information structures.
pub mod json_output;
/// The module which provides the per-process logger.
pub mod logger;
/// The module which provides signal handling.
pub mod signal_handler;

use log::error;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// The most common result type provided by Nitro CLI operations.
pub type NitroCliResult<T> = Result<T, String>;

/// The amount of time in milliseconds an enclave process will wait for certain operations.
pub const ENCLAVE_PROC_WAIT_TIMEOUT_MSEC: isize = 3000;

/// The confirmation code sent by an enclave process to a requesting CLI instance
/// in order to signal that it is alive.
pub const MSG_ENCLAVE_CONFIRM: u64 = 0xEEC0;

/// The environment variable which holds the path to the Unix sockets directory.
pub const SOCKETS_DIR_PATH_ENV_VAR: &str = "NITRO_CLI_SOCKETS_PATH";

/// The default path to the Unix sockets directory.
const SOCKETS_DIR_PATH: &str = "/var/run/nitro_enclaves";

/// The type of commands that can be sent to an enclave process.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
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

/// A trait which allows a more graceful program exit instead of the standard `panic`.
pub trait ExitGracefully<T, E> {
    /// Provide the inner value of a `Result` or exit gracefully with a message.
    fn ok_or_exit(self, message: &str) -> T;
}

impl<T, E: std::fmt::Debug> ExitGracefully<T, E> for Result<T, E> {
    /// Provide the inner value of a `Result` or exit gracefully with a message.
    fn ok_or_exit(self, message: &str) -> T {
        match self {
            Ok(val) => val,
            Err(err) => {
                notify_error(&format!("{}: {:?}", message, err));
                std::process::exit(1);
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
        format!(
            "Failed to read {} bytes from given socket: {:?}",
            std::mem::size_of::<u64>(),
            e
        )
    })?;
    Ok(u64::from_le_bytes(bytes))
}

/// Write a LE-encoded 64-bit unsigned value to a socket.
pub fn write_u64_le(socket: &mut dyn Write, value: u64) -> NitroCliResult<()> {
    let bytes = value.to_le_bytes();
    socket.write_all(&bytes).map_err(|e| {
        format!(
            "Failed to write {} bytes to given socket: {:?}",
            std::mem::size_of::<u64>(),
            e
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
    let cmd_bytes =
        serde_cbor::to_vec(&cmd).map_err(|e| format!("Invalid single command format: {:?}", e))?;

    // The command is written twice. The first read is done by the connection listener to check if this is
    // a shut-down command. The second read is done by the enclave process for all non-shut-down commands.
    for _ in 0..2 {
        write_u64_le(&mut socket, cmd_bytes.len() as u64)
            .map_err(|e| format!("Failed to send single command size: {:?}", e))?;
        socket
            .write_all(&cmd_bytes[..])
            .map_err(|e| format!("Failed to send single command: {:?}", e))?;
    }

    // Serialize the command arguments.
    if let Some(args) = args {
        let arg_bytes = serde_cbor::to_vec(args)
            .map_err(|e| format!("Invalid single command arguments: {:?}", e))?;

        // Write the serialized command arguments.
        write_u64_le(&mut socket, arg_bytes.len() as u64)
            .map_err(|e| format!("Failed to send arguments size: {:?}", e))?;
        socket
            .write_all(&arg_bytes)
            .map_err(|e| format!("Failed to send arguments: {:?}", e))?;
    }

    Ok(())
}

/// Receive an object of a specified type from an input stream.
pub fn receive_from_stream<T>(input_stream: &mut dyn Read) -> NitroCliResult<T>
where
    T: DeserializeOwned,
{
    let size = read_u64_le(input_stream)
        .map_err(|e| format!("Failed to receive data size: {:?}", e))? as usize;
    let mut raw_data: Vec<u8> = vec![0; size];
    input_stream
        .read_exact(&mut raw_data[..])
        .map_err(|e| format!("Failed to receive data: {:?}", e))?;
    let data: T = serde_cbor::from_slice(&raw_data[..])
        .map_err(|e| format!("Failed to decode received data: {:?}", e))?;
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

    fn unset_envvar(varname: &String) {
        let _ = unsafe {
            libc::unsetenv(varname.as_ptr() as *const i8);
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
