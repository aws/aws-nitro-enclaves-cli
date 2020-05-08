// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

pub mod commands_parser;
pub mod logger;
pub mod signal_handler;

use log::error;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub type NitroCliResult<T> = Result<T, String>;

pub const ENCLAVE_PROC_WAIT_TIMEOUT_MSEC: isize = 3000;
pub const MSG_ENCLAVE_CONFIRM: u64 = 0xEEC0;

pub const SOCKETS_DIR_PATH_ENV_VAR: &str = "NITRO_CLI_SOCKETS_PATH";
const SOCKETS_DIR_PATH: &str = "/var/run/nitro_enclaves";

/// The type of commands that can be sent to an enclave process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnclaveProcessCommandType {
    Run = 0,
    Terminate,
    TerminateComplete,
    Describe,
    GetEnclaveCID,
    ConnectionListenerStop,
}

/// The type of replies that the enclave process can send to a CLI.
#[derive(Debug, Serialize, Deserialize)]
pub enum EnclaveProcessReplyType {
    StdOutMessage(String),
    StdErrMessage(String),
    Status(i32),
}

pub trait ExitGracefully<T, E> {
    fn ok_or_exit(self, message: &str) -> T;
}

impl<T, E: std::fmt::Debug> ExitGracefully<T, E> for Result<T, E> {
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
pub fn notify_error(err_msg: &String) {
    eprintln!("{}", err_msg);
    error!("{}", err_msg);
}

/// Read a LE-encoded number from a socket.
pub fn read_u64_le(socket: &mut dyn Read) -> io::Result<u64> {
    let mut bytes = [0u8; std::mem::size_of::<u64>()];
    socket.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Write a LE-encoded number to a socket.
pub fn write_u64_le(socket: &mut dyn Write, value: u64) -> io::Result<()> {
    let bytes = value.to_le_bytes();
    socket.write_all(&bytes)
}

/// Send a command to a single socket.
pub fn enclave_proc_command_send_single<T>(
    cmd: &EnclaveProcessCommandType,
    args: Option<&T>,
    mut socket: &mut UnixStream,
) -> io::Result<()>
where
    T: Serialize,
{
    // Serialize the command type.
    let cmd_bytes =
        serde_cbor::to_vec(cmd).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // The command is written twice. The first read is done by the connection listener to check if this is
    // a shut-down command. The second read is done by the enclave process for all non-shut-down commands.
    for _ in 0..2 {
        write_u64_le(&mut socket, cmd_bytes.len() as u64)?;
        socket.write_all(&cmd_bytes[..])?;
    }

    // Serialize the command arguments.
    if let Some(args) = args {
        let arg_bytes =
            serde_cbor::to_vec(args).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Write the serialized command arguments.
        write_u64_le(&mut socket, arg_bytes.len() as u64)?;
        socket.write_all(&arg_bytes)?;
    }

    Ok(())
}

/// Read the arguments of the CLI command.
pub fn receive_from_stream<T>(input_stream: &mut dyn Read) -> io::Result<T>
where
    T: DeserializeOwned,
{
    let size = read_u64_le(input_stream)? as usize;
    let mut raw_data: Vec<u8> = vec![0; size];
    input_stream.read_exact(&mut raw_data[..])?;
    let data: T = serde_cbor::from_slice(&raw_data[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(data)
}

/// Get the path to the sockets directory.
pub fn get_sockets_dir_path() -> PathBuf {
    let log_path = match env::var(SOCKETS_DIR_PATH_ENV_VAR) {
        Ok(env_path) => env_path,
        Err(_) => SOCKETS_DIR_PATH.to_string(),
    };
    Path::new(&log_path).to_path_buf()
}

/// Get the path to our Unix socket.
pub fn get_socket_path(enclave_id: &str) -> io::Result<PathBuf> {
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

        let result0 = enclave_proc_command_send_single::<EmptyArgs>(&cmd, args, &mut sock0);
        assert!(result0.is_ok());

        let result1 = receive_command_type(&mut sock1);
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
            assert_eq!(SOCKETS_DIR_PATH, sockets_dir_path_f.as_path().to_str().unwrap());
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
        assert_eq!(result.unwrap().as_path().to_str().unwrap(), format!("{}/{}.sock", sockets_path.as_path().to_str().unwrap(), tokens[0]));
    }

    /// Tests that `get_socket_path()` returns an invalid socket path,
    /// given a malformed enclave id.
    #[test]
    fn test_get_socket_path_invalid_id() {
        let enclave_id = "i-0000000000000000_enc0123456789012345";
        let sockets_path = get_sockets_dir_path();
        let result = get_socket_path(enclave_id);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_path().to_str().unwrap(), format!("{}/{}.sock", sockets_path.as_path().to_str().unwrap(), enclave_id));
    }

}
