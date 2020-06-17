// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::{debug, info};
use nix::sys::epoll;
use nix::sys::epoll::{EpollEvent, EpollFlags, EpollOp};
use nix::unistd::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::common::commands_parser::EmptyArgs;
use crate::common::logger::EnclaveProcLogWriter;
use crate::common::{
    enclave_proc_command_send_single, get_socket_path, get_sockets_dir_path, notify_error,
    read_u64_le, receive_from_stream,
};
use crate::common::{EnclaveProcessCommandType, EnclaveProcessReply, ExitGracefully};
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
                match UnixStream::connect(path_str) {
                    Ok(conn) => {
                        // We have connected to an enclave process
                        info!("Connected to: {}", path_str);
                        return Some(conn);
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::PermissionDenied {
                            // Don't touch the socket if connection failed due to insufficient permissions.
                            info!("Connection to '{}' failed: {}", path_str, e);
                        } else {
                            // For all other connection errors, assume the socket is stale and delete it.
                            info!("Deleting stale socket: {}", path_str);
                            fs::remove_file(path_str).ok_or_exit("Failed to delete socket.");
                        }
                    }
                }
            }

            None
        })
        .collect())
}

/// Open a connection to an enclave-specific socket.
pub fn enclave_proc_connect_to_single(enclave_id: &str) -> io::Result<UnixStream> {
    let socket_path = get_socket_path(enclave_id)?;
    UnixStream::connect(socket_path)
}

/// Broadcast a command to all available enclave processes.
pub fn enclave_proc_command_send_all<T>(
    cmd: EnclaveProcessCommandType,
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
    if comms.is_empty() {
        return Ok((vec![], 0));
    }

    // Get the number of transmission errors.
    let mut num_errors = comms.iter().filter(|result| result.is_err()).count();

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

/// Print the output from a single enclave process.
fn enclave_proc_handle_output<T>(conn: &mut UnixStream) -> (Option<T>, Option<i32>)
where
    T: DeserializeOwned,
{
    let mut stdout_str = String::new();
    let mut status: Option<i32> = None;

    // The contents received on STDOUT must always form a valid JSON object.
    while let Ok(reply) = receive_from_stream::<EnclaveProcessReply>(conn) {
        match reply {
            EnclaveProcessReply::StdOutMessage(msg) => stdout_str.push_str(&msg),
            EnclaveProcessReply::StdErrMessage(msg) => eprint!("{}", msg),
            EnclaveProcessReply::Status(status_code) => status = Some(status_code),
        }
    }

    // Shut the connection down.
    match conn.shutdown(std::net::Shutdown::Both) {
        Ok(()) => (),
        Err(e) => {
            notify_error(&format!("Failed to shut connection down: {}", e));
            status = Some(-1);
        }
    }

    // Decode the JSON object.
    let json_obj = serde_json::from_str::<T>(&stdout_str).ok();
    (json_obj, status)
}

/// Fetch JSON objects and statuses from all connected enclave processes.
pub fn enclave_proc_handle_outputs<T>(conns: &mut [UnixStream]) -> Vec<(T, i32)>
where
    T: DeserializeOwned,
{
    let mut objects: Vec<(T, i32)> = Vec::new();

    for conn in conns.iter_mut() {
        // We only count connections that have yielded a valid JSON object and a status
        let (object, status) = enclave_proc_handle_output::<T>(conn);
        if let Some(object) = object {
            if let Some(status) = status {
                objects.push((object, status));
            }
        }
    }

    objects
}

/// Process reply messages from all connected enclave processes.
pub fn enclave_process_handle_all_replies<T>(
    replies: &mut [UnixStream],
    prev_failed_conns: usize,
    print_as_vec: bool,
) -> io::Result<()>
where
    T: Clone + DeserializeOwned + Serialize,
{
    let objects = enclave_proc_handle_outputs::<T>(replies);
    let failed_conns = prev_failed_conns + replies.len() - objects.len();

    // Print a message if we have any connections that have failed.
    if failed_conns > 0 {
        eprintln!("Failed connections: {}", failed_conns);
    }

    // Output the received objects either individually or as an array.
    if print_as_vec {
        let obj_vec: Vec<T> = objects.iter().map(|v| v.0.clone()).collect();
        println!("{}", serde_json::to_string_pretty(&obj_vec)?);
    } else {
        for object in objects.iter().map(|v| v.0.clone()) {
            println!("{}", serde_json::to_string_pretty(&object)?);
        }
    }

    // We fail on any error codes or failed connections.
    if objects.iter().filter(|v| v.1 != 0).count() > 0 || failed_conns > 0 {
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to handle enclave process replies.",
        ));
    }

    Ok(())
}

/// Obtain an enclave's CID given its full ID.
pub fn enclave_proc_get_cid(enclave_id: &str) -> io::Result<u64> {
    let mut comm = enclave_proc_connect_to_single(enclave_id)?;
    // TODO: Replicate output of old CLI on invalid enclave IDs.
    enclave_proc_command_send_single::<EmptyArgs>(
        EnclaveProcessCommandType::GetEnclaveCID,
        None,
        &mut comm,
    )?;

    info!("Sent command: GetEnclaveCID");
    let enclave_cid = read_u64_le(&mut comm)?;

    // We got the CID, so shut the connection down.
    comm.shutdown(std::net::Shutdown::Both)?;

    Ok(enclave_cid)
}
