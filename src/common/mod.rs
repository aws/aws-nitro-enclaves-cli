// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

pub mod commands_parser;
pub mod logger;
pub mod signal_handler;

use log::error;
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

/// Read the type of the CLI command.
pub fn receive_command_type(input_stream: &mut dyn Read) -> io::Result<EnclaveProcessCommandType> {
    let cmd_size = read_u64_le(input_stream)? as usize;
    let mut cmd_data: Vec<u8> = vec![0; cmd_size];
    input_stream.read_exact(&mut cmd_data[..])?;
    let cmd_type = serde_cbor::from_slice(&cmd_data[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(cmd_type)
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
