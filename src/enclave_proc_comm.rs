// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::{debug, info};
use nix::sys::epoll;
use nix::sys::epoll::{EpollEvent, EpollFlags, EpollOp};
use nix::unistd::*;
use serde::Serialize;
use std::fs;
use std::io::{self, Error, ErrorKind, Read};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::common::commands_parser::EmptyArgs;
use crate::common::logger::EnclaveProcLogWriter;
use crate::common::{
    enclave_proc_command_send_single, get_socket_path, get_sockets_dir_path, read_u64_le,
};
use crate::common::{EnclaveProcessCommandType, ExitGracefully};
use crate::common::{ENCLAVE_PROC_WAIT_TIMEOUT_MSEC, MSG_ENCLAVE_CONFIRM};
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
    let fork_status = fork();

    if let Ok(ForkResult::Child) = fork_status {
        // This is our intermediate child process.
        enclave_process_run(enclave_proc_socket, logger);
    } else {
        fork_status.ok_or_exit("Failed to create intermediate process");
    }

    // The enclave process will open a socket named "<enclave_id>.sock", but this
    // will only become available after the enclave has been successfully launched.
    // Until then, we can only use the pre-initialized socket pair to communicate
    // with the new process.
    Ok(cli_socket)
}

/// Connect to all existing enclave processes, returning a connection to each.
pub fn enclave_proc_connect_to_all() -> io::Result<Vec<UnixStream>> {
    let paths = fs::read_dir(get_sockets_dir_path())?;
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

/// Open a connection to an enclave-specific socket.
pub fn enclave_proc_connect_to_single(enclave_id: &String) -> io::Result<UnixStream> {
    let socket_path = get_socket_path(enclave_id)?;
    UnixStream::connect(socket_path)
}

/// Broadcast a command to all available enclave processes.
pub fn enclave_proc_command_send_all<T>(
    cmd: &EnclaveProcessCommandType,
    args: Option<&T>,
) -> io::Result<(Vec<UnixStream>, usize)>
where
    T: Serialize,
{
    // Open a connection to each valid socket.
    let mut replies: Vec<UnixStream> = vec![];
    let epoll_fd = epoll::epoll_create().map_err(|e| Error::new(ErrorKind::Other, e))?;
    let comms: Vec<io::Result<()>> = enclave_proc_connect_to_all()?
        .iter_mut()
        .map(|socket| {
            // Add each valid connection to epoll.
            let socket_clone = socket.try_clone()?;
            let mut process_evt =
                EpollEvent::new(EpollFlags::EPOLLIN, socket_clone.into_raw_fd() as u64);
            epoll::epoll_ctl(
                epoll_fd,
                EpollOp::EpollCtlAdd,
                socket.as_raw_fd(),
                &mut process_evt,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            // Send the command.
            enclave_proc_command_send_single(cmd, args, socket)
        })
        .collect();

    // Don't proceed unless at least one connection has been established.
    if comms.len() == 0 {
        return Ok((vec![], 0));
    }

    // Get the number of transmission errors.
    let mut num_errors = comms
        .iter()
        .filter(|result| result.is_err())
        .collect::<Vec<_>>()
        .len();

    // Get the number of expected replies.
    let mut num_replies_expected = comms.len() - num_errors;
    let mut events = vec![EpollEvent::empty(); 1];

    while num_replies_expected > 0 {
        let num_events = loop {
            match epoll::epoll_wait(epoll_fd, &mut events[..], ENCLAVE_PROC_WAIT_TIMEOUT_MSEC) {
                Ok(num_events) => break num_events,
                Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => continue,
                // TODO: Handle bad descriptors (closed remote connections).
                Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            }
        };

        // We will handle this reply, irrespective of its status (successful or failed).
        num_replies_expected -= 1;

        // Check if a time-out has occurred.
        if num_events == 0 {
            continue;
        }

        // Handle the reply we received.
        let mut input_stream = unsafe { UnixStream::from_raw_fd(events[0].data() as RawFd) };
        if let Ok(reply) = read_u64_le(&mut input_stream) {
            if reply == MSG_ENCLAVE_CONFIRM {
                debug!("Got confirmation from {:?}", input_stream);
                replies.push(input_stream);
            }
        }
    }

    // Update the number of connections that have yielded errors.
    num_errors = comms.len() - replies.len();

    Ok((replies, num_errors))
}

/// Print a stream's output. Returns the number of streams with no output.
pub fn enclave_proc_fetch_output(conns: &[UnixStream]) -> usize {
    let mut empty_conns = 0;

    for conn in conns.iter() {
        let mut bytes_read = 0u32;

        // Fetch all stream contents.
        for byte in conn.bytes() {
            match byte {
                Ok(data) => print!("{}", data as char),
                Err(_) => break,
            }

            bytes_read = bytes_read + 1;
        }

        // Shut the stream down.
        conn.shutdown(std::net::Shutdown::Both)
            .ok_or_exit("Failed to shut down connection.");

        if bytes_read == 0 {
            empty_conns = empty_conns + 1;
        }
    }

    empty_conns
}

/// Output a message for the connections that have failed.
pub fn enclave_proc_output_failed_conns(failed_conns: usize) {
    // Don't print anything if there were no failed connections.
    if failed_conns == 0 {
        return;
    }

    // Print a JSON object with the number of failed connections.
    eprintln!(
        "{}",
        serde_json::json!({ "FailedConnections": failed_conns })
    );
}

/// Obtain an enclave's CID given its full ID.
pub fn enclave_proc_get_cid(enclave_id: &String) -> io::Result<u64> {
    let mut comm = enclave_proc_connect_to_single(enclave_id)?;
    // TODO: Replicate output of old CLI on invalid enclave IDs.
    enclave_proc_command_send_single::<EmptyArgs>(
        &EnclaveProcessCommandType::GetEnclaveCID,
        None,
        &mut comm,
    )?;

    info!("Sent command: GetEnclaveCID");
    let enclave_cid = read_u64_le(&mut comm)?;

    // We got the CID, so shut the connection down.
    comm.shutdown(std::net::Shutdown::Both)?;

    Ok(enclave_cid)
}
