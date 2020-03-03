// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::commands_parser::EnclaveProcessCommandType;
use common::{read_u64_from_socket, write_u64_to_socket};
use common::{ENCLAVE_PROC_BINARY, ENCLAVE_PROC_DIR_VAR, ENCLAVE_PROC_SOCKET_DIR};
use log::{debug, error, info};
use serde::Serialize;
use serde_cbor;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::io::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

/// Check if the file at a given path is an executable.
fn can_execute(binary: &str) -> bool {
    let file_data = fs::metadata(binary);
    if file_data.is_err() {
        return false;
    }

    if !file_data.unwrap().is_file() {
        return false;
    }

    // TODO: Check permission bits.

    return true;
}

/// Get the actual path to the enclave process binary.
fn enclaved_get_path() -> io::Result<String> {
    // First, check if the binary is in the user-defined path.
    let path_env = env::var(ENCLAVE_PROC_DIR_VAR);

    if path_env.is_ok() {
        let enclaved_path = format!("{}/{}", path_env.unwrap(), ENCLAVE_PROC_BINARY);
        if can_execute(&enclaved_path) {
            return Ok(enclaved_path);
        }
    }

    // Next, check the current directory.
    let enclaved_path = format!("./{}", ENCLAVE_PROC_BINARY);
    if can_execute(&enclaved_path) {
        return Ok(enclaved_path);
    }

    // Finally, check in PATH.
    if can_execute(&ENCLAVE_PROC_BINARY.to_string()) {
        return Ok(ENCLAVE_PROC_BINARY.to_string());
    }

    // The binary was not found.
    error!("Enclaved binary not found.");
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Enclaved binary not found.",
    ))
}

/// Spawn an enclave process and wait until it has detached and has
/// taken ownership of its communication socket.
pub fn enclaved_spawn() -> io::Result<UnixStream> {
    let binary_path = enclaved_get_path()?;

    info!("Spawning enclave process from: {}", binary_path);
    let (mut cli_socket, enclaved_socket) = UnixStream::pair()?;

    // Prevent the descriptor from being closed when calling exec().
    let enclaved_fd = enclaved_socket.into_raw_fd();
    unsafe {
        let flags = libc::fcntl(enclaved_fd, libc::F_GETFD);
        libc::fcntl(enclaved_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }

    // Spawn the child process (equivalent to fork() + exec()). The child process
    // will then fork() again to create the detached enclave process.
    Command::new(binary_path)
        .arg(enclaved_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // We don't yet know the PID of the detached process, so we use the socket
    // pair as an initial communication channel to learn it. This is needed since
    // the detached process's PID differs from the PID of the child spawned above.
    let enclaved_pid = read_u64_from_socket(&mut cli_socket)?;
    cli_socket.shutdown(std::net::Shutdown::Both)?;
    info!("Got PID {:?} from socket {:?}.", enclaved_pid, cli_socket);

    // The daemon will send its PID after it has taken ownership of its Unix socket.
    // It is therefore safe to attempt to connect to that socket now.
    let socket_path = format!("{}/{}.sock", ENCLAVE_PROC_SOCKET_DIR, enclaved_pid);
    UnixStream::connect(socket_path)
}

/// Connect to all existing enclave processes, returning a connection to each.
pub fn enclaved_connect_to_all() -> io::Result<Vec<UnixStream>> {
    let paths = fs::read_dir(ENCLAVE_PROC_SOCKET_DIR)?;
    let mut conn_list: Vec<UnixStream> = vec![];

    for path in paths {
        if let Ok(path) = path {
            if let Ok(file_type) = path.file_type() {
                if !file_type.is_dir() {
                    if let Some(path_str) = path.path().to_str() {
                        if path_str.ends_with(".sock") {
                            if let Ok(conn) = UnixStream::connect(path_str) {
                                debug!("Connected to: {}", path_str);
                                conn_list.push(conn);
                            } else {
                                // Can't connect to the enclave process; delete socket.
                                info!("Deleting stale socket: {}", path_str);
                                fs::remove_file(path_str).expect("Failed to delete socket.");
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(conn_list)
}

/// Send a command to a single socket.
pub fn enclaved_command_send_single<T>(
    cmd: &EnclaveProcessCommandType,
    args: &T,
    mut socket: &mut UnixStream,
) -> io::Result<()>
where
    T: Serialize,
{
    let cmd_bytes =
        serde_cbor::to_vec(cmd).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let arg_bytes =
        serde_cbor::to_vec(args).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Write the serialized command.
    write_u64_to_socket(&mut socket, cmd_bytes.len() as u64)?;
    socket.write_all(&cmd_bytes[..])?;

    // Write the serialized command arguments.
    write_u64_to_socket(&mut socket, arg_bytes.len() as u64)?;
    socket.write_all(&arg_bytes)?;

    Ok(())
}

pub fn enclaved_command_send_all<T>(cmd: &EnclaveProcessCommandType, args: &T) -> io::Result<()>
where
    T: Serialize,
{
    let mut conns = enclaved_connect_to_all()?;
    let mut results: Vec<io::Result<()>> = Vec::with_capacity(conns.len());

    for socket in conns.iter_mut() {
        results.push(enclaved_command_send_single(cmd, args, socket));
    }

    let errors = results.iter().any(|result| result.is_err());

    if errors {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Communication with at least one process failed.",
        ));
    }

    Ok(())
}
