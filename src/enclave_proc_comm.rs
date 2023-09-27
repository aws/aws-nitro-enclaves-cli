// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use log::{debug, info};
use nix::sys::epoll;
use nix::sys::epoll::{EpollEvent, EpollFlags, EpollOp};
use nix::unistd::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::borrow::BorrowMut;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::common::commands_parser::EmptyArgs;
use crate::common::logger::EnclaveProcLogWriter;
use crate::common::{
    enclave_proc_command_send_single, get_socket_path, get_sockets_dir_path, notify_error,
    read_u64_le, receive_from_stream,
};
use crate::common::{
    EnclaveProcessCommandType, EnclaveProcessReply, NitroCliErrorEnum, NitroCliFailure,
    NitroCliResult,
};
use crate::common::{ENCLAVE_PROC_WAIT_TIMEOUT_MSEC, MSG_ENCLAVE_CONFIRM};
use crate::enclave_proc::enclave_process_run;
use crate::new_nitro_cli_failure;

/// Spawn an enclave process and wait until it has detached and has
/// taken ownership of its communication socket.
pub fn enclave_proc_spawn(logger: &EnclaveProcLogWriter) -> NitroCliResult<UnixStream> {
    let (cli_socket, enclave_proc_socket) = UnixStream::pair().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Could not create a socket pair: {:?}", e),
            NitroCliErrorEnum::SocketPairCreationFailure
        )
    })?;

    // Prevent the descriptor from being closed when calling exec().
    let enclave_proc_fd = enclave_proc_socket.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(enclave_proc_fd, libc::F_GETFD);
        libc::fcntl(enclave_proc_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }

    // Spawn an intermediate child process. This will fork again in order to
    // create the detached enclave process.
    // Safety: enclave_proc_spawn is called early on and nitro-cli is not that this point
    // multi-threaded, which should prevent the issues around forking. However,
    // the safe way to do this would be to use a safe alternative such as Command to
    // re-execute this same process with another set of parameters.
    let fork_status = unsafe { fork() };

    if let Ok(ForkResult::Child) = fork_status {
        // This is our intermediate child process.
        enclave_process_run(enclave_proc_socket, logger);
    } else {
        fork_status.map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to create intermediate process: {:?}", e),
                NitroCliErrorEnum::ProcessSpawnFailure
            )
        })?;
    }

    // The enclave process will open a socket named "<enclave_id>.sock", but this
    // will only become available after the enclave has been successfully launched.
    // Until then, we can only use the pre-initialized socket pair to communicate
    // with the new process.
    Ok(cli_socket)
}

/// Connect to all existing enclave processes, returning a connection to each.
pub fn enclave_proc_connect_to_all() -> NitroCliResult<Vec<UnixStream>> {
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
            // Get the file path string.
            if let Some(path_str) = path.to_str() {
                // Enclave process sockets are named "<enclave_id>.sock".
                if !path_str.ends_with(".sock") {
                    return None;
                }

                // At this point we have found a potential socket.
                match UnixStream::connect(path_str) {
                    Ok(conn) => {
                        // We have connected to an enclave process.
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
                            let _ = fs::remove_file(path_str).map_err(|e| {
                                new_nitro_cli_failure!(
                                    &format!("Failed to delete socket: {:?}", e),
                                    NitroCliErrorEnum::FileOperationFailure
                                )
                                .add_info(vec![path_str, "Remove"])
                            });
                        }
                    }
                }
            }

            None
        })
        .collect())
}

/// Open a connection to an enclave-specific socket.
pub fn enclave_proc_connect_to_single(enclave_id: &str) -> NitroCliResult<UnixStream> {
    let socket_path = get_socket_path(enclave_id).map_err(|e| {
        e.add_subaction("Connect to specific enclave process".to_string())
            .set_error_code(NitroCliErrorEnum::SocketError)
    })?;
    UnixStream::connect(socket_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to connect to specific enclave process: {:?}", e),
            NitroCliErrorEnum::SocketError
        )
    })
}

/// Broadcast a command to all available enclave processes.
pub fn enclave_proc_command_send_all<T>(
    cmd: EnclaveProcessCommandType,
    args: Option<&T>,
) -> NitroCliResult<(Vec<UnixStream>, usize)>
where
    T: Serialize,
{
    // Open a connection to each valid socket.
    let mut replies: Vec<UnixStream> = vec![];
    let epoll_fd = epoll::epoll_create().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create epoll: {:?}", e),
            NitroCliErrorEnum::EpollError
        )
    })?;
    let comms: Vec<NitroCliResult<()>> = enclave_proc_connect_to_all()
        .map_err(|e| {
            e.add_subaction("Failed to send command to all enclave processes".to_string())
        })?
        .into_iter()
        .map(|mut socket| {
            // Send the command.
            enclave_proc_command_send_single(cmd, args, socket.borrow_mut())?;

            let raw_fd = socket.into_raw_fd();
            let mut process_evt = EpollEvent::new(EpollFlags::EPOLLIN, raw_fd as u64);

            // Add each valid connection to epoll.
            epoll::epoll_ctl(epoll_fd, EpollOp::EpollCtlAdd, raw_fd, &mut process_evt).map_err(
                |e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to register socket with epoll: {:?}", e),
                        NitroCliErrorEnum::EpollError
                    )
                },
            )?;

            Ok(())
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
    let mut events = [EpollEvent::empty(); 1];

    while num_replies_expected > 0 {
        let num_events = loop {
            match epoll::epoll_wait(epoll_fd, &mut events[..], ENCLAVE_PROC_WAIT_TIMEOUT_MSEC) {
                Ok(num_events) => break num_events,
                Err(nix::errno::Errno::EINTR) => continue,
                // TODO: Handle bad descriptors (closed remote connections).
                Err(e) => {
                    return Err(new_nitro_cli_failure!(
                        &format!("Failed to wait on epoll: {:?}", e),
                        NitroCliErrorEnum::EpollError
                    ))
                }
            }
        };

        // We will handle this reply, irrespective of its status (successful or failed).
        num_replies_expected -= 1;

        // Check if a time-out has occurred.
        if num_events == 0 {
            continue;
        }

        let input_stream_raw_fd = events[0].data() as RawFd;
        let mut input_stream = unsafe { UnixStream::from_raw_fd(input_stream_raw_fd) };

        // Handle the reply we received.
        if let Ok(reply) = read_u64_le(&mut input_stream) {
            if reply == MSG_ENCLAVE_CONFIRM {
                debug!("Got confirmation from {:?}", input_stream);
                replies.push(input_stream);
            }
        }

        epoll::epoll_ctl(
            epoll_fd,
            EpollOp::EpollCtlDel,
            input_stream_raw_fd,
            Option::None,
        )
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to remove socket from epoll: {:?}", e),
                NitroCliErrorEnum::EpollError
            )
        })?;
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

    // The contents meant for standard output must always form a valid JSON object.
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
    allowed_return_codes: Vec<i32>,
) -> NitroCliResult<Vec<T>>
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
        println!(
            "{}",
            serde_json::to_string_pretty(&obj_vec).map_err(|e| new_nitro_cli_failure!(
                &format!("Failed to print JSON vector: {:?}", e),
                NitroCliErrorEnum::SerdeError
            ))?
        );
    } else {
        for object in objects.iter().map(|v| v.0.clone()) {
            println!(
                "{}",
                serde_json::to_string_pretty(&object).map_err(|e| new_nitro_cli_failure!(
                    &format!("Failed to print JSON object: {:?}", e),
                    NitroCliErrorEnum::SerdeError
                ))?
            );
        }
    }

    // We fail on any error codes or failed connections.
    if objects
        .iter()
        .filter(|v| !allowed_return_codes.contains(&v.1))
        .count()
        > 0
    {
        return Err(new_nitro_cli_failure!(
            &format!(
                "Failed to execute {} enclave process commands",
                objects
                    .iter()
                    .filter(|v| !allowed_return_codes.contains(&v.1))
                    .count()
            ),
            NitroCliErrorEnum::EnclaveProcessCommandNotExecuted
        ));
    } else if failed_conns > 0 {
        return Err(new_nitro_cli_failure!(
            &format!("Failed to connect to {} enclave processes", failed_conns),
            NitroCliErrorEnum::EnclaveProcessConnectionFailure
        ));
    }

    Ok(objects.into_iter().map(|(o, _)| o).collect())
}

/// Obtain an enclave's CID given its full ID.
pub fn enclave_proc_get_cid(enclave_id: &str) -> NitroCliResult<u64> {
    let mut comm = enclave_proc_connect_to_single(enclave_id)
        .map_err(|e| e.add_subaction("Failed to connect to enclave process".to_string()))?;
    // TODO: Replicate output of old CLI on invalid enclave IDs.
    enclave_proc_command_send_single::<EmptyArgs>(
        EnclaveProcessCommandType::GetEnclaveCID,
        None,
        &mut comm,
    )
    .map_err(|e| e.add_subaction("Failed to send CID request to enclave process".to_string()))?;

    info!("Sent command: GetEnclaveCID");
    let enclave_cid = read_u64_le(&mut comm)
        .map_err(|e| e.add_subaction(String::from("Failed to read CID from enclave process")))?;

    // We got the CID, so shut the connection down.
    comm.shutdown(std::net::Shutdown::Both).map_err(|e| {
        new_nitro_cli_failure!(
            &format!(
                "Failed to shut down connection after obtaining enclave CID: {:?}",
                e
            ),
            NitroCliErrorEnum::SocketError
        )
    })?;

    Ok(enclave_cid)
}

/// Obtain an enclave's flags given its full ID.
pub fn enclave_proc_get_flags(enclave_id: &str) -> NitroCliResult<u64> {
    let mut comm = enclave_proc_connect_to_single(enclave_id)
        .map_err(|e| e.add_subaction("Failed to connect to enclave process".to_string()))?;
    // TODO: Replicate output of old CLI on invalid enclave IDs.
    enclave_proc_command_send_single::<EmptyArgs>(
        EnclaveProcessCommandType::GetEnclaveFlags,
        None,
        &mut comm,
    )
    .map_err(|e| e.add_subaction("Failed to send flags request to enclave process".to_string()))?;

    info!("Sent command: GetEnclaveFlags");
    let enclave_flags = read_u64_le(&mut comm)
        .map_err(|e| e.add_subaction(String::from("Failed to read flags from enclave process")))?;

    // We got the flags, so shut the connection down.
    comm.shutdown(std::net::Shutdown::Both).map_err(|e| {
        new_nitro_cli_failure!(
            &format!(
                "Failed to shut down connection after obtaining enclave flags: {:?}",
                e
            ),
            NitroCliErrorEnum::SocketError
        )
    })?;

    Ok(enclave_flags)
}
