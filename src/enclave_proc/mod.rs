// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]
#![allow(clippy::too_many_arguments)]

/// The module which provides top-level enclave commands.
pub mod commands;
/// The module which provides a connection to the enclave process.
pub mod connection;
/// The module which provides an enclave socket monitor that listens for incoming connections.
pub mod connection_listener;
/// The module which provides CPU information utilities.
pub mod cpu_info;
/// The module which provides the enclave manager and its utilities.
pub mod resource_manager;
/// The module which provides the managed Unix socket needed to communicate with the enclave process.
pub mod socket;
/// The module which provides additional enclave process utilities.
pub mod utils;

use log::{info, warn};
use nix::sys::epoll::EpollFlags;
use nix::sys::signal::{Signal, SIGHUP};
use nix::unistd::{daemon, getpid, getppid};
use std::collections::BTreeMap;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process;
use std::thread::{self, JoinHandle};

use super::common::MSG_ENCLAVE_CONFIRM;
use super::common::{construct_error_message, enclave_proc_command_send_single, notify_error};
use super::common::{
    EnclaveProcessCommandType, ExitGracefully, NitroCliErrorEnum, NitroCliFailure, NitroCliResult,
};
use crate::common::commands_parser::{EmptyArgs, RunEnclavesArgs};
use crate::common::logger::EnclaveProcLogWriter;
use crate::common::signal_handler::SignalHandler;
use crate::enclave_proc::connection::safe_conn_println;
use crate::new_nitro_cli_failure;

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
    format!("enc-{}:{}", tokens[0], std::process::id())
}

/// Get the action associated with `cmd` as a String.
fn get_command_action(cmd: EnclaveProcessCommandType) -> String {
    match cmd {
        EnclaveProcessCommandType::Run => "Run Enclave".to_string(),
        EnclaveProcessCommandType::Terminate | EnclaveProcessCommandType::TerminateComplete => {
            "Terminate Enclave".to_string()
        }
        EnclaveProcessCommandType::Describe => "Describe Enclaves".to_string(),
        EnclaveProcessCommandType::GetEnclaveCID => "Get Enclave CID".to_string(),
        EnclaveProcessCommandType::GetEnclaveFlags => "Get Enclave Flags".to_string(),
        EnclaveProcessCommandType::ConnectionListenerStop => "Stop Connection Listener".to_string(),
        _ => "Unknown Command".to_string(),
    }
}

/// Send the given command, then close the channel that was used for sending it.
fn send_command_and_close(cmd: EnclaveProcessCommandType, stream: &mut UnixStream) {
    let action_str = &get_command_action(cmd);

    enclave_proc_command_send_single::<EmptyArgs>(cmd, None, stream)
        .ok_or_exit_with_errno(Some("Failed to send command"));
    stream
        .shutdown(std::net::Shutdown::Both)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to close stream after sending command: {:?}", e),
                NitroCliErrorEnum::SocketCloseError
            )
            .set_action(action_str.to_string())
        })
        .ok_or_exit_with_errno(Some("Failed to shut down stream"));
}

/// Notify that an error has occurred, also forwarding the error message to a connection.
fn notify_error_with_conn(err_msg: &str, conn: &Connection, action: EnclaveProcessCommandType) {
    let action_str = &get_command_action(action);

    notify_error(err_msg);
    conn.eprintln(err_msg)
        .map_err(|e| e.set_action(action_str.to_string()))
        .ok_or_exit_with_errno(Some("Failed to forward error message to connection"));
}

/// Perform enclave termination.
fn run_terminate(
    connection: Connection,
    mut thread_stream: UnixStream,
    mut enclave_manager: EnclaveManager,
) {
    terminate_enclaves(&mut enclave_manager, Some(&connection)).unwrap_or_else(|e| {
        notify_error_with_conn(
            construct_error_message(&e).as_str(),
            &connection,
            EnclaveProcessCommandType::Terminate,
        );
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
    let (local_stream, thread_stream) = UnixStream::pair().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Could not create stream pair: {:?}", e),
            NitroCliErrorEnum::SocketPairCreationFailure
        )
    })?;

    conn_listener.add_stream_to_epoll(local_stream)?;
    Ok(thread::spawn(move || {
        run_terminate(connection, thread_stream, enclave_manager)
    }))
}

/// Launch the POSIX signal handler on a dedicated thread and ensure its events are accessible.
fn enclave_proc_configure_signal_handler(conn_listener: &ConnectionListener) -> NitroCliResult<()> {
    let mut signal_handler = SignalHandler::new_with_defaults()
        .mask_all()
        .map_err(|e| e.add_subaction("Failed to configure signal handler".to_string()))?;
    let (local_stream, thread_stream) = UnixStream::pair()
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to create stream pair: {:?}", e),
                NitroCliErrorEnum::SocketPairCreationFailure
            )
            .set_action("Run Enclave".to_string())
        })
        .ok_or_exit_with_errno(Some("Failed to create stream pair"));

    conn_listener
        .add_stream_to_epoll(local_stream)
        .map_err(|e| {
            e.add_subaction(
                "Failed to add stream to epoll when configuring signal handler".to_string(),
            )
        })?;
    signal_handler.start_handler(thread_stream.into_raw_fd(), enclave_proc_handle_signals);

    Ok(())
}

/// The default POSIX signal handling function, which notifies the enclave process to shut down gracefully.
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
fn try_handle_enclave_event(connection: &Connection) -> NitroCliResult<HandledEnclaveEvent> {
    // Check if this is an enclave connection.
    if let Some(mut enc_events) = connection
        .get_enclave_event_flags()
        .map_err(|e| e.add_subaction("Failed to get enclave events flag".to_string()))?
    {
        let enc_hup = enc_events.contains(EpollFlags::EPOLLHUP);

        // Check if non-hang-up events have occurred.
        enc_events.remove(EpollFlags::EPOLLHUP);
        if !enc_events.is_empty() {
            warn!("Received unexpected enclave event(s): {:?}", enc_events);
        }

        // If we received the hang-up event we need to terminate cleanly.
        if enc_hup {
            warn!("Received hang-up event from the enclave. Enclave process will shut down.");
            return Ok(HandledEnclaveEvent::HangUp);
        }

        // Non-hang-up enclave events are not fatal.
        return Ok(HandledEnclaveEvent::Unexpected);
    }

    Ok(HandledEnclaveEvent::None)
}

/// Handle a single command, returning whenever an error occurs.
fn handle_command(
    cmd: EnclaveProcessCommandType,
    logger: &EnclaveProcLogWriter,
    connection: &Connection,
    conn_listener: &mut ConnectionListener,
    enclave_manager: &mut EnclaveManager,
    terminate_thread: &mut Option<std::thread::JoinHandle<()>>,
    pcr_thread: &mut Option<JoinHandle<NitroCliResult<BTreeMap<String, String>>>>,
    add_info: &mut bool,
) -> NitroCliResult<(i32, bool)> {
    Ok(match cmd {
        EnclaveProcessCommandType::Run => {
            // We should never receive a Run command if we are already running.
            if !enclave_manager.enclave_id.is_empty() {
                (libc::EEXIST, false)
            } else {
                let run_args = connection.read::<RunEnclavesArgs>().map_err(|e| {
                    e.add_subaction("Failed to get run arguments".to_string())
                        .set_action("Run Enclave".to_string())
                })?;
                info!("Run args = {:?}", run_args);

                let run_result = run_enclaves(&run_args, Some(connection)).map_err(|e| {
                    e.add_subaction("Failed to trigger enclave run".to_string())
                        .set_action("Run Enclave".to_string())
                })?;
                *enclave_manager = run_result.enclave_manager;
                *pcr_thread = run_result.pcr_thread;
                *add_info = true;

                info!("Enclave ID = {}", enclave_manager.enclave_id);
                logger
                    .update_logger_id(&get_logger_id(&enclave_manager.enclave_id))
                    .map_err(|e| e.set_action("Failed to update logger ID".to_string()))?;
                conn_listener
                    .start(&enclave_manager.enclave_id)
                    .map_err(|e| {
                        e.set_action("Failed to start connection listener thread".to_string())
                    })?;

                // Add the enclave descriptor to epoll to listen for enclave events.
                let enc_fd = enclave_manager
                    .get_enclave_descriptor()
                    .map_err(|e| e.set_action("Failed to get enclave descriptor".to_string()))?;
                conn_listener
                    .register_enclave_descriptor(enc_fd)
                    .map_err(|e| {
                        e.set_action("Failed to register enclave descriptor".to_string())
                    })?;
                (0, false)
            }
        }

        EnclaveProcessCommandType::Terminate => {
            *terminate_thread = Some(
                notify_terminate(connection.clone(), conn_listener, enclave_manager.clone())
                    .map_err(|e| {
                        e.set_action("Failed to send enclave termination request".to_string())
                    })?,
            );
            (0, false)
        }

        EnclaveProcessCommandType::TerminateComplete => {
            info!("Enclave has completed termination.");
            (0, true)
        }

        EnclaveProcessCommandType::GetEnclaveCID => {
            let enclave_cid = enclave_manager
                .get_console_resources_enclave_cid()
                .map_err(|e| {
                    e.set_action("Failed to get console resources (enclave CID)".to_string())
                })?;
            connection.write_u64(enclave_cid).map_err(|e| {
                e.add_subaction("Failed to write enclave CID to connection".to_string())
                    .set_action("Get Enclave CID".to_string())
            })?;
            (0, false)
        }

        EnclaveProcessCommandType::GetEnclaveFlags => {
            let enclave_flags = enclave_manager
                .get_console_resources_enclave_flags()
                .map_err(|e| {
                    e.set_action("Failed to get console resources (enclave flags)".to_string())
                })?;
            connection.write_u64(enclave_flags).map_err(|e| {
                e.add_subaction("Failed to write enclave flags to connection".to_string())
                    .set_action("Get Enclave Flags".to_string())
            })?;
            (0, false)
        }

        EnclaveProcessCommandType::GetEnclaveName => {
            connection.write_u64(MSG_ENCLAVE_CONFIRM).map_err(|e| {
                e.add_subaction("Failed to write confirmation".to_string())
                    .set_action("Get Enclave Name".to_string())
            })?;
            safe_conn_println(
                Some(connection),
                serde_json::to_string_pretty(&enclave_manager.enclave_name)
                    .map_err(|err| {
                        new_nitro_cli_failure!(
                            &format!("Failed to write enclave name to connection: {:?}", err),
                            NitroCliErrorEnum::SerdeError
                        )
                    })?
                    .as_str(),
            )?;
            (0, false)
        }

        EnclaveProcessCommandType::Describe => {
            connection.write_u64(MSG_ENCLAVE_CONFIRM).map_err(|e| {
                e.add_subaction("Failed to write confirmation".to_string())
                    .set_action("Describe Enclaves".to_string())
            })?;

            // Evaluate thread result at first describe, then set thread to None.
            if pcr_thread.is_some() {
                enclave_manager
                    .set_measurements(match pcr_thread.take() {
                        Some(thread) => thread
                            .join()
                            .map_err(|e| {
                                new_nitro_cli_failure!(
                                    &format!("Termination thread join failed: {:?}", e),
                                    NitroCliErrorEnum::ThreadJoinFailure
                                )
                            })?
                            .map_err(|e| {
                                e.add_subaction("Failed to save PCR values".to_string())
                            })?,
                        None => {
                            return Err(new_nitro_cli_failure!(
                                "Thread handle not found",
                                NitroCliErrorEnum::ThreadJoinFailure
                            ));
                        }
                    })
                    .map_err(|e| {
                        e.add_subaction(
                            "Failed to set measurements inside enclave handle.".to_string(),
                        )
                    })?;
                *pcr_thread = None;
            }

            describe_enclaves(&enclave_manager, connection, *add_info).map_err(|e| {
                e.add_subaction("Failed to describe enclave".to_string())
                    .set_action("Describe Enclaves".to_string())
            })?;
            (0, false)
        }

        EnclaveProcessCommandType::ConnectionListenerStop => (0, true),

        EnclaveProcessCommandType::NotPermitted => (libc::EACCES, false),
    })
}

/// The main event loop of the enclave process.
fn process_event_loop(
    comm_stream: UnixStream,
    logger: &EnclaveProcLogWriter,
) -> NitroCliResult<()> {
    let mut conn_listener = ConnectionListener::new()?;
    let mut enclave_manager = EnclaveManager::default();
    let mut terminate_thread: Option<std::thread::JoinHandle<()>> = None;
    let mut pcr_thread: Option<std::thread::JoinHandle<NitroCliResult<BTreeMap<String, String>>>> =
        None;
    let mut done = false;
    let mut ret_value = Ok(());
    let mut add_info = false;

    // Start the signal handler before spawning any other threads. This is done since the
    // handler will mask all relevant signals from the current thread and this setting will
    // be automatically inherited by all threads spawned from this point on; we want this
    // because only the dedicated thread spawned by the handler should listen for signals.
    enclave_proc_configure_signal_handler(&conn_listener)
        .map_err(|e| e.add_subaction("Failed to configure signal handler".to_string()))?;

    // Add the CLI communication channel to epoll.
    conn_listener
        .handle_new_connection(comm_stream)
        .map_err(|e| {
            e.add_subaction("Failed to add CLI communication channel to epoll".to_string())
        })?;

    while !done {
        // We can get connections to CLI instances, to the enclave or to ourselves.
        let connection =
            conn_listener.get_next_connection(enclave_manager.get_enclave_descriptor().ok())?;

        // If this is an enclave event, handle it.
        match try_handle_enclave_event(&connection) {
            Ok(HandledEnclaveEvent::HangUp) => break,
            Ok(HandledEnclaveEvent::Unexpected) => continue,
            Ok(HandledEnclaveEvent::None) => (),
            Err(error_info) => {
                ret_value = Err(error_info
                    .add_subaction("Error while trying to handle enclave event".to_string()));
                break;
            }
        }

        // At this point we have a connection that is not coming from an enclave.
        // Read the command that should be executed.
        let cmd = match connection.read_command() {
            Ok(value) => value,
            Err(mut error_info) => {
                error_info = error_info
                    .add_subaction("Failed to read command".to_string())
                    .set_action("Run Enclave".to_string());
                notify_error_with_conn(
                    &construct_error_message(&error_info),
                    &connection,
                    EnclaveProcessCommandType::NotPermitted,
                );
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
            &mut pcr_thread,
            &mut add_info,
        );

        // Obtain the status code and whether the event loop must be exited.
        let (status_code, do_break) = match status {
            Ok(value) => value,
            Err(mut error_info) => {
                // Any encountered error is both logged and send to the other side of the connection.
                error_info = error_info
                    .add_subaction(format!("Failed to execute command `{:?}`", cmd))
                    .set_action("Run Enclave".to_string());
                notify_error_with_conn(&construct_error_message(&error_info), &connection, cmd);
                (libc::EINVAL, true)
            }
        };

        done = do_break;

        // Perform clean-up and stop the connection listener before returning the status to the CLI.
        // This is done to avoid race conditions where the enclave process has not yet removed the
        // socket and another CLI issues a command on that very-soon-to-be-removed socket.
        if done {
            // Stop the connection listener.
            conn_listener.stop()?;

            // Wait for the termination thread, if any.
            if terminate_thread.is_some() {
                terminate_thread.take().unwrap().join().map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Termination thread join failed: {:?}", e),
                        NitroCliErrorEnum::ThreadJoinFailure
                    )
                })?;
            };
        }

        // Only the commands coming from the CLI must be replied to with the status code.
        match cmd {
            EnclaveProcessCommandType::Run
            | EnclaveProcessCommandType::Terminate
            | EnclaveProcessCommandType::Describe
            | EnclaveProcessCommandType::GetEnclaveName => {
                connection.write_status(status_code).map_err(|_| {
                    new_nitro_cli_failure!(
                        "Process event loop failed",
                        NitroCliErrorEnum::EnclaveProcessSendReplyFailure
                    )
                })?
            }
            _ => (),
        }
    }

    info!("Enclave process {} exited event loop.", process::id());

    ret_value
}

/// Create the enclave process.
fn create_enclave_process(logger: &EnclaveProcLogWriter) -> NitroCliResult<()> {
    // To get a detached process, we first:
    // (1) Temporarily ignore specific signals (SIGHUP).
    // (2) Daemonize the current process.
    // (3) Wait until the detached process is orphaned.
    // (4) Restore signal handlers.
    let signal_handler = SignalHandler::new(&[SIGHUP])
        .mask_all()
        .map_err(|e| e.add_subaction("Failed to mask signals".to_string()))?;
    let ppid = getpid();

    // Daemonize the current process. The working directory remains
    // unchanged and the standard descriptors are routed to '/dev/null'.
    daemon(true, false).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to daemonize enclave process: {:?}", e),
            NitroCliErrorEnum::DaemonizeProcessFailure
        )
    })?;

    // This is our detached process.
    logger
        .update_logger_id(format!("enc-xxxxxxx:{}", std::process::id()).as_str())
        .map_err(|e| e.add_subaction("Failed to update logger id".to_string()))?;
    info!("Enclave process PID: {}", process::id());

    // We must wait until we're 100% orphaned. That is, our parent must
    // no longer be the pre-fork process.
    while getppid() == ppid {
        thread::sleep(std::time::Duration::from_millis(10));
    }

    // Restore signal handlers.
    signal_handler
        .unmask_all()
        .map_err(|e| e.add_subaction("Failed to restore signal handlers".to_string()))?;

    Ok(())
}

/// Launch the enclave process.
///
/// * `comm_fd` - A descriptor used for initial communication with the parent Nitro CLI instance.
/// * `logger` - The current log writer, whose ID gets updated when an enclave is launched.
pub fn enclave_process_run(comm_stream: UnixStream, logger: &EnclaveProcLogWriter) {
    create_enclave_process(logger)
        .map_err(|e| e.set_action("Run Enclave".to_string()))
        .ok_or_exit_with_errno(None);
    let res = process_event_loop(comm_stream, logger);
    if let Err(mut error_info) = res {
        error_info = error_info.set_action("Run Enclave".to_string());
        notify_error(construct_error_message(&error_info).as_str());
        process::exit(error_info.error_code as i32);
    }
    process::exit(0);
}
