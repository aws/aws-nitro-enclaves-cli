// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

pub mod connection;
pub mod connection_listener;

use log::{info, warn};
use nix::sys::signal::{signal, SigHandler, Signal};
use nix::unistd::*;
use procinfo::pid;
use serde::de::DeserializeOwned;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::io::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::process;
use std::thread;

use super::common::commands_parser::RunEnclavesArgs;
use super::common::{read_u64_le, receive_command_type};
use super::common::{EnclaveProcessCommandType, ExitGracefully};
use crate::common::logger::EnclaveProcLogWriter;

use connection::Connection;
use connection_listener::ConnectionListener;

/// Read the arguments of the CLI command.
fn receive_command_args<T>(input_stream: &mut dyn Read) -> io::Result<T>
where
    T: DeserializeOwned,
{
    let arg_size = read_u64_le(input_stream)? as usize;
    let mut arg_data: Vec<u8> = vec![0; arg_size];
    input_stream.read_exact(&mut arg_data[..])?;
    let args: T = serde_cbor::from_slice(&arg_data[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(args)
}

/// The main event loop of the enclave process.
fn process_event_loop(comm_stream: UnixStream) {
    let mut conn_listener = ConnectionListener::new();

    // Add the CLI communication channel to epoll.
    conn_listener.handle_new_connection(comm_stream);

    loop {
        let mut connection = Connection::new(conn_listener.get_epoll_fd());
        let cmd =
            receive_command_type(connection.as_reader()).ok_or_exit("Failed to receive command.");
        info!("Received command: {:?}", cmd);

        match cmd {
            EnclaveProcessCommandType::Run => {
                let run_args = receive_command_args::<RunEnclavesArgs>(connection.as_reader());
                info!("Run args = {:?}", run_args);
                // TODO: Launch an enclave from here.
                // TODO: The exposed socket's name will be "<enclave_id>.sock".
                conn_listener
                    .start("0".to_string())
                    .ok_or_exit("Failed to start connection listener.");
            }

            EnclaveProcessCommandType::Terminate => {
                info!("Stopping enclave process.");
                // TODO: Terminate the enclave.
                break;
            }

            _ => warn!("Command not supported."),
        };
    }

    info!("Enclave process {} exited event loop.", process::id());
    conn_listener.stop();
}

/// Ignore a list of signals.
fn ignore_signal_handlers(ign_signals: &[Signal]) -> Vec<(Signal, SigHandler)> {
    let mut handlers: Vec<(Signal, SigHandler)> = vec![];
    for &ign_signal in ign_signals.iter() {
        let handler =
            unsafe { signal(ign_signal, SigHandler::SigIgn) }.ok_or_exit("Failed to set signal.");
        handlers.push((ign_signal, handler));
    }

    handlers
}

/// Restore the signal handlers that were previously ignored.
fn restore_signal_handlers(handlers: &[(Signal, SigHandler)]) {
    for &(ign_signal, old_handler) in handlers.iter() {
        unsafe { signal(ign_signal, old_handler) }.ok_or_exit("Failed to restore signal handler.");
    }
}

/// Redirect STDIN, STDOUT and STDERR to "/dev/null"
fn hide_standard_descriptors() {
    let null_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .open("/dev/null")
        .ok_or_exit("Failed to open '/dev/null'")
        .into_raw_fd();
    unsafe { libc::dup2(null_fd, libc::STDIN_FILENO) };
    unsafe { libc::dup2(null_fd, libc::STDOUT_FILENO) };
    unsafe { libc::dup2(null_fd, libc::STDERR_FILENO) };
}

/// Create the enclave process.
fn create_enclave_process() {
    // To get a detached process, we first:
    // (1) Temporarily ignore specific signals (SIGHUP).
    // (2) Fork a child process.
    // (3) Terminate the parent (at which point the child becomes orphaned).
    // (4) Restore signal handlers.
    let old_sig_handlers = ignore_signal_handlers(&[Signal::SIGHUP]);

    // We need to redirect the standard descriptors to "/dev/null" in the
    // intermediate process since we want its child (the detached enclave
    // process) to not have terminal access.
    hide_standard_descriptors();

    // The current process must first become session leader.
    setsid().ok_or_exit("setsid() failed.");

    match fork() {
        Ok(ForkResult::Parent { child }) => {
            info!("Parent = {} with child = {:?}", process::id(), child);
            process::exit(0);
        }
        Ok(ForkResult::Child) => {
            // This is our detached process.
            info!("Enclave process PID: {}", process::id());
        }
        Err(e) => panic!("Failed to create child: {}", e),
    }

    // The detached process is not a session leader and thus cannot attach
    // to a terminal. Next, we must wait until we're 100% orphaned.
    loop {
        let stat = pid::stat_self().ok_or_exit("Failed to get process stat.");
        if stat.ppid == 1 {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }

    // Restore signal handlers.
    restore_signal_handlers(&old_sig_handlers);
}

pub fn enclave_process_run(comm_stream: UnixStream, logger: &EnclaveProcLogWriter) -> i32 {
    // TODO: The enclave ID will be shared by both the logger and the event loop.
    logger.update_logger_id("enc-xxxxxxxxxxxx");
    create_enclave_process();
    process_event_loop(comm_stream);

    0
}
