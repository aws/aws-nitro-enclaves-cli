// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

pub mod commands;
pub mod connection;
pub mod connection_listener;
pub mod cpu_info;
pub mod resource_manager;
pub mod socket;
pub mod utils;

use log::{info, warn};
use nix::sys::epoll::EpollFlags;
use nix::sys::signal::{Signal, SIGHUP};
use nix::unistd::{daemon, getpid, getppid};
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process;
use std::thread::{self, JoinHandle};

use super::common::MSG_ENCLAVE_CONFIRM;
use super::common::{enclave_proc_command_send_single, notify_error};
use super::common::{EnclaveProcessCommandType, ExitGracefully, NitroCliResult};
use crate::common::commands_parser::{EmptyArgs, RunEnclavesArgs};
use crate::common::logger::EnclaveProcLogWriter;
use crate::common::signal_handler::SignalHandler;

use commands::{describe_enclaves, run_enclaves, terminate_enclaves};
use connection::Connection;
use connection_listener::ConnectionListener;
use resource_manager::EnclaveManager;

/// The type of enclave event that has been handled.
enum HandledEnclaveEvent {
    /// A hang-up event.
    HangUp,
    /// An unexpected but non-critical event.
    Unexpected,
    /// There was no event that needed handling.
    None,
}

/// Obtain the logger ID from the full enclave ID.
fn get_logger_id(enclave_id: &str) -> String {
    // The full enclave ID is "i-(...)-enc<enc_id>" and we want to extract only <enc_id>.
    let tokens: Vec<_> = enclave_id.rsplit("-enc").collect();
    format!("enc-{}", tokens[0])
}

fn send_command_and_close(cmd: EnclaveProcessCommandType, stream: &mut UnixStream) {
    enclave_proc_command_send_single::<EmptyArgs>(cmd, None, stream)
        .ok_or_exit("Failed to send command.");
    stream
        .shutdown(std::net::Shutdown::Both)
        .ok_or_exit("Failed to shut down stream.");
}

/// Notify that an error has occurred, also forwarding the error message to a connection.
fn notify_error_with_conn(err_msg: &str, conn: &Connection) {
    notify_error(err_msg);
    conn.eprintln(err_msg)
        .ok_or_exit("Failed to forward error message to connection.");
}

/// Perform enclave termination.
fn run_terminate(
    connection: Connection,
    mut thread_stream: UnixStream,
    mut enclave_manager: EnclaveManager,
) {
    terminate_enclaves(&mut enclave_manager, &connection).unwrap_or_else(|e| {
        notify_error_with_conn(&format!("Failed to terminate enclave: {}", e), &connection);
    });

    // Notify the main thread that enclave termination has completed.
    send_command_and_close(
        EnclaveProcessCommandType::TerminateComplete,
        &mut thread_stream,
    );
}

/// Start enclave termination.
fn notify_terminate(
    connection: Connection,
    conn_listener: &ConnectionListener,
    enclave_manager: EnclaveManager,
) -> NitroCliResult<JoinHandle<()>> {
    let (local_stream, thread_stream) =
        UnixStream::pair().map_err(|e| format!("Failed to create stream pair: {}", e))?;

    conn_listener.add_stream_to_epoll(local_stream);
    Ok(thread::spawn(move || {
        run_terminate(connection, thread_stream, enclave_manager)
    }))
}

fn enclave_proc_configure_signal_handler(conn_listener: &ConnectionListener) {
    let mut signal_handler = SignalHandler::new_with_defaults().mask_all();
    let (local_stream, thread_stream) =
        UnixStream::pair().ok_or_exit("Failed to create stream pair.");

    conn_listener.add_stream_to_epoll(local_stream);
    signal_handler.start_handler(thread_stream.into_raw_fd(), enclave_proc_handle_signals);
}

fn enclave_proc_handle_signals(comm_fd: RawFd, signal: Signal) -> bool {
    let mut stream = unsafe { UnixStream::from_raw_fd(comm_fd) };

    warn!(
        "Received signal {:?}. The enclave process will now close.",
        signal
    );
    send_command_and_close(
        EnclaveProcessCommandType::ConnectionListenerStop,
        &mut stream,
    );

    true
}

/// Handle an event coming from an enclave.
fn try_handle_enclave_event(connection: &Connection) -> HandledEnclaveEvent {
    // Check if this is an enclave connection.
    if let Some(mut enc_events) = connection.get_enclave_event_flags() {
        let enc_hup = enc_events.contains(EpollFlags::EPOLLHUP);

        // Check if non-hang-up events have occurred.
        enc_events.remove(EpollFlags::EPOLLHUP);
        if !enc_events.is_empty() {
            warn!("Received unexpected enclave event(s): {:?}", enc_events);
        }

        // If we received the hang-up event we need to terminate cleanly.
        if enc_hup {
            warn!("Received hang-up event from the enclave. Enclave process will shut down.");
            return HandledEnclaveEvent::HangUp;
        }

        // Non-hang-up enclave events are not fatal.
        return HandledEnclaveEvent::Unexpected;
    }

    HandledEnclaveEvent::None
}

/// Handle a single command, returning whenever an error occurs.
fn handle_command(
    cmd: EnclaveProcessCommandType,
    logger: &EnclaveProcLogWriter,
    connection: &Connection,
    conn_listener: &mut ConnectionListener,
    enclave_manager: &mut EnclaveManager,
    terminate_thread: &mut Option<std::thread::JoinHandle<()>>,
) -> NitroCliResult<bool> {
    match cmd {
        EnclaveProcessCommandType::Run => {
            let run_args = connection
                .read::<RunEnclavesArgs>()
                .map_err(|e| format!("Failed to get run arguments: {}", e))?;
            info!("Run args = {:?}", run_args);

            *enclave_manager = run_enclaves(&run_args, connection)
                .map_err(|e| format!("Failed to run enclave: {}", e))?;

            info!("Enclave ID = {}", enclave_manager.enclave_id);
            logger.update_logger_id(&get_logger_id(&enclave_manager.enclave_id));
            conn_listener
                .start(&enclave_manager.enclave_id)
                .map_err(|e| format!("Failed to start connection listener: {}", e))?;

            // Add the enclave descriptor to epoll to listen for enclave events.
            let enc_fd = enclave_manager
                .get_enclave_descriptor()
                .map_err(|e| format!("Failed to get enclave descriptor: {}", e))?;
            conn_listener.register_enclave_descriptor(enc_fd);
        }

        EnclaveProcessCommandType::Terminate => {
            *terminate_thread = Some(notify_terminate(
                connection.clone(),
                conn_listener,
                enclave_manager.clone(),
            )?);
        }

        EnclaveProcessCommandType::TerminateComplete => {
            info!("Enclave has completed termination.");
            return Ok(true);
        }

        EnclaveProcessCommandType::GetEnclaveCID => {
            let enclave_cid = enclave_manager
                .get_console_resources()
                .map_err(|e| format!("Failed to get enclave CID: {}", e))?;
            connection
                .write_u64(enclave_cid)
                .map_err(|e| format!("Failed to send enclave CID: {}", e))?;
        }

        EnclaveProcessCommandType::Describe => {
            connection
                .write_u64(MSG_ENCLAVE_CONFIRM)
                .map_err(|e| format!("Failed to write confirmation: {}", e))?;

            describe_enclaves(&enclave_manager, connection)
                .map_err(|e| format!("Failed to describe enclave: {}", e))?;
        }

        EnclaveProcessCommandType::ConnectionListenerStop => return Ok(true),
    };

    Ok(false)
}

/// The main event loop of the enclave process.
fn process_event_loop(comm_stream: UnixStream, logger: &EnclaveProcLogWriter) {
    let mut conn_listener = ConnectionListener::new();
    let mut enclave_manager = EnclaveManager::default();
    let mut terminate_thread: Option<std::thread::JoinHandle<()>> = None;
    let mut done = false;

    // Start the signal handler before spawning any other threads. This is done since the
    // handler will mask all relevant signals from the current thread and this setting will
    // be automatically inherited by all threads spawned from this point on; we want this
    // because only the dedicated thread spawned by the handler should listen for signals.
    enclave_proc_configure_signal_handler(&conn_listener);

    // Add the CLI communication channel to epoll.
    conn_listener.handle_new_connection(comm_stream);

    while !done {
        // We can get connections to CLI instances, to the enclave or to ourselves.
        let connection =
            conn_listener.get_next_connection(enclave_manager.get_enclave_descriptor().ok());

        // If this is an enclave event, handle it.
        match try_handle_enclave_event(&connection) {
            HandledEnclaveEvent::HangUp => break,
            HandledEnclaveEvent::Unexpected => continue,
            HandledEnclaveEvent::None => (),
        }

        // At this point we have a connection that is not coming from an enclave.
        // Read the command that should be executed.
        let cmd = match connection.read::<EnclaveProcessCommandType>() {
            Ok(value) => value,
            Err(e) => {
                notify_error_with_conn(&format!("Failed to read command type: {}", e), &connection);
                break;
            }
        };

        info!("Received command: {:?}", cmd);
        let status = handle_command(
            cmd,
            logger,
            &connection,
            &mut conn_listener,
            &mut enclave_manager,
            &mut terminate_thread,
        );

        // Obtain the status code and whether the event loop must be exited.
        let (status_code, do_break) = match status {
            Ok(value) => (0, value),
            Err(e) => {
                // Any encountered error is both logged and send to the other side of the connection.
                notify_error_with_conn(&format!("Error: {}", e), &connection);
                (1, true)
            }
        };

        done = do_break;

        // Only the commands comming from the CLI must be replied to with the status code.
        match cmd {
            EnclaveProcessCommandType::Run
            | EnclaveProcessCommandType::Terminate
            | EnclaveProcessCommandType::Describe => connection
                .write_status(status_code)
                .ok_or_exit("Failed to send status reply."),
            _ => (),
        }
    }

    // Wait for the termination thread, if any.
    if let Some(handle) = terminate_thread {
        handle
            .join()
            .ok_or_exit("Failed to retrieve termination thread.");
    };

    info!("Enclave process {} exited event loop.", process::id());
    conn_listener.stop();
}

/// Create the enclave process.
fn create_enclave_process() {
    // To get a detached process, we first:
    // (1) Temporarily ignore specific signals (SIGHUP).
    // (2) Daemonize the current process.
    // (3) Wait until the detached process is orphaned.
    // (4) Restore signal handlers.
    let signal_handler = SignalHandler::new(&[SIGHUP]).mask_all();
    let ppid = getpid();

    // Daemonize the current process. The working directory remains
    // unchanged and the standard descriptors are routed to '/dev/null'.
    daemon(true, false).ok_or_exit("Failed to create enclave process");

    // This is our detached process.
    info!("Enclave process PID: {}", process::id());

    // We must wait until we're 100% orphaned. That is, our parent must
    // no longer be the pre-fork process.
    while getppid() == ppid {
        thread::sleep(std::time::Duration::from_millis(10));
    }

    // Restore signal handlers.
    signal_handler.unmask_all();
}

/// Launch the enclave process.
///
/// * `comm_fd` - A descriptor used for initial communication with the parent Nitro CLI instance.
/// * `logger` - The current log writer, whose ID gets updated when an enclave is launched.
pub fn enclave_process_run(comm_stream: UnixStream, logger: &EnclaveProcLogWriter) {
    logger.update_logger_id("enc-xxxxxxxxxxxx");
    create_enclave_process();
    process_event_loop(comm_stream, logger);
    process::exit(0);
}
