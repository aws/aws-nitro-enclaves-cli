// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::info;
use nix::unistd::*;
use serde::Serialize;
use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process;

use crate::common::enclave_proc_command_send_single;
use crate::common::logger::EnclaveProcLogWriter;
use crate::common::ENCLAVE_PROC_RESOURCES_DIR;
use crate::common::{EnclaveProcessCommandType, ExitGracefully};
use crate::enclave_proc::enclave_process_run;

/// Spawn an enclave process and wait until it has detached and has
/// taken ownership of its communication socket.
pub fn enclave_proc_spawn(logger: &EnclaveProcLogWriter) -> io::Result<UnixStream> {
    let (cli_socket, enclave_proc_socket) = UnixStream::pair()?;

    // Prevent the descriptor from being closed when calling exec().
    let enclave_proc_fd = enclave_proc_socket.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(enclave_proc_fd, libc::F_GETFD);
        libc::fcntl(enclave_proc_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }

    // Spawn an intermediate child process. This will fork again in order to
    // create the detached enclave process.
    match fork() {
        Ok(ForkResult::Parent { child }) => {
            info!("Parent = {} with child = {:?}", process::id(), child);
        }
        Ok(ForkResult::Child) => {
            // This is our intermediate child process.
            process::exit(enclave_process_run(enclave_proc_socket, logger));
        }
        Err(e) => panic!("Failed to create child: {}", e),
    }

    // The enclave process will open a socket named "<enclave_id>.sock", but this
    // will only become available after the enclave has been successfully launched.
    // Until then, we can only use the pre-initialized socket pair to communicate
    // with the new process.
    Ok(cli_socket)
}

/// Connect to all existing enclave processes, returning a connection to each.
pub fn enclave_proc_connect_to_all() -> io::Result<Vec<UnixStream>> {
    let paths = fs::read_dir(ENCLAVE_PROC_RESOURCES_DIR)?;
    Ok(paths
        .filter_map(|path| path.ok())
        .map(|path| path.path())
        .filter(|path| !path.is_dir())
        .filter_map(|path| {
            // Get the file path string.
            if let Some(path_str) = path.to_str() {
                // Enclave process sockets are named "<enclave_id>.sock".
                if !path_str.ends_with(".sock") {
                    return None;
                }

                // At this point we have found a potential socket.
                if let Ok(conn) = UnixStream::connect(path_str) {
                    // We have connected to an enclave process
                    info!("Connected to: {}", path_str);
                    return Some(conn);
                }

                // Can't connect to the enclave process, so delete the socket.
                info!("Deleting stale socket: {}", path_str);
                fs::remove_file(path_str).ok_or_exit("Failed to delete socket.");
            }

            None
        })
        .collect())
}

/// Broadcast a command to all available enclave processes.
pub fn enclave_proc_command_send_all<T>(
    cmd: &EnclaveProcessCommandType,
    args: Option<&T>,
) -> io::Result<()>
where
    T: Serialize,
{
    let mut conns = enclave_proc_connect_to_all()?;
    let mut results: Vec<io::Result<()>> = Vec::with_capacity(conns.len());

    for socket in conns.iter_mut() {
        results.push(enclave_proc_command_send_single(cmd, args, socket));
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
