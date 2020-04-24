// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::{debug, info};
use nix::sys::epoll;
use nix::sys::epoll::{EpollEvent, EpollFlags, EpollOp};
use nix::unistd::*;
use serde::Serialize;
use std::fs;
use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process;

use crate::common::commands_parser::EmptyArgs;
use crate::common::logger::EnclaveProcLogWriter;
use crate::common::{
    enclave_proc_command_send_single, get_resources_dir, get_socket_path, read_u64_le,
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
    let resources_dir = get_resources_dir()?;
    let paths = fs::read_dir(resources_dir)?;
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
) -> io::Result<Vec<UnixStream>>
where
    T: Serialize,
{
    // Open a connection to each valid socket.
    let epoll_fd = epoll::epoll_create().ok_or_exit("Could not create epoll_fd.");
    let mut replies: Vec<UnixStream> = vec![];
    let mut sockets = enclave_proc_connect_to_all()?;
    let comms: Vec<io::Result<()>> = sockets
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
        return Ok(vec![]);
    }

    // Get the number of transmission errors.
    let num_errors = comms
        .iter()
        .filter(|result| result.is_err())
        .collect::<Vec<_>>()
        .len();

    // Get the number of expected replies.
    let mut num_replies_expected = comms.len() - num_errors;
    let mut events = vec![EpollEvent::empty(); num_replies_expected as usize];
    let ret: io::Result<()> = loop {
        let num_events = loop {
            match epoll::epoll_wait(epoll_fd, &mut events[..], ENCLAVE_PROC_WAIT_TIMEOUT_MSEC) {
                Ok(num_events) => break num_events,
                Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => continue,
                // TODO: Handle bad descriptors (closed remote connections).
                Err(x) => panic!("epoll_wait failed: {:?}", x),
            }
        };

        if num_events == 0 {
            // Timeout occurred
            break Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Timed out waiting for replies.",
            ));
        }

        assert!(num_events <= num_replies_expected, "Got too many replies!");

        // Handle all replies.
        for event in events.iter() {
            let mut input_stream = unsafe { UnixStream::from_raw_fd(event.data() as RawFd) };
            if let Ok(reply) = read_u64_le(&mut input_stream) {
                if reply == MSG_ENCLAVE_CONFIRM {
                    num_replies_expected -= 1;
                    debug!("Got confirmation from {:?}", input_stream);
                    replies.push(input_stream);
                }
            }
        }

        if num_replies_expected == 0 {
            info!("Got all expected replies.");
            break Ok(());
        }
    };

    if (num_errors > 0) || ret.is_err() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Communication with at least one process failed.",
        ));
    }

    Ok(replies)
}

/// Print a stream's output.
pub fn enclave_proc_fetch_output(conns: &Vec<UnixStream>) {
    for conn in conns.iter() {
        for byte in conn.bytes() {
            match byte {
                Ok(data) => print!("{}", data as char),
                Err(_) => break,
            }
        }
    }
}

/// Close all active connections.
pub fn enclave_proc_connection_close(conns: &Vec<UnixStream>) {
    for conn in conns.iter() {
        conn.shutdown(std::net::Shutdown::Both)
            .ok_or_exit("Failed to shut down connection.");
    }
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
