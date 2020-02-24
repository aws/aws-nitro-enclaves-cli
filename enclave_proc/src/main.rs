// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use env_logger;
use libc;
use log::{info, warn};
use std::env;
use std::format;
use std::fs::OpenOptions;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;
use std::thread;
use std::thread::JoinHandle;

use procinfo::pid;

use nix::sys::signal::{signal, SigHandler, Signal};
use nix::unistd::*;

use serde::de::DeserializeOwned;

use common::commands_parser::{EnclaveProcessCommandType, RunEnclavesArgs};
use common::ENCLAVE_PROC_SOCKET_DIR;
use common::{read_u64_from_socket, write_u64_to_socket};

// TODO: We should have includes & implementations for both Linux and Windows.
use nix::sys::epoll;
use nix::sys::epoll::{EpollEvent, EpollFlags, EpollOp};

/// Handle a new connection.
fn handle_client(stream: UnixStream, epoll_fd: RawFd) {
    info!("New connection: {:?}", stream);
    let mut cli_evt = EpollEvent::new(EpollFlags::EPOLLIN, stream.as_raw_fd() as u64);
    epoll::epoll_ctl(
        epoll_fd,
        EpollOp::EpollCtlAdd,
        stream.into_raw_fd(),
        &mut cli_evt,
    )
    .expect("Could not add SM descriptor to epoll.");
}

/// Wait for and handle new connections.
fn connection_listener_run(listener: UnixListener, epoll_fd: RawFd) {
    info!("Connections listener: {:?}", listener);

    // Accept connections and process them (this is a blocking call).
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Received a new connection.
                handle_client(stream, epoll_fd);
            }
            Err(err) => {
                // Connection failed.
                warn!("Connection error: {:?}", err);
                break;
            }
        }
    }
}

/// Read the type of the CLI command.
fn receive_command_type(input_stream: &mut UnixStream) -> io::Result<EnclaveProcessCommandType> {
    let cmd_size = read_u64_from_socket(input_stream)? as usize;
    let mut cmd_data: Vec<u8> = vec![0; cmd_size];
    input_stream.read_exact(&mut cmd_data[..])?;
    let cmd_type = serde_cbor::from_slice(&cmd_data[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(cmd_type)
}

/// Read the arguments of the CLI command.
fn receive_command_args<T>(input_stream: &mut UnixStream) -> io::Result<T>
where
    T: DeserializeOwned,
{
    let arg_size = read_u64_from_socket(input_stream)? as usize;
    let mut arg_data: Vec<u8> = vec![0; arg_size];
    input_stream.read_exact(&mut arg_data[..])?;
    let args: T = serde_cbor::from_slice(&arg_data[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(args)
}

/// The main event loop of the enclave process.
fn process_event_loop(epoll_fd: RawFd) {
    loop {
        // We can get an event from either a CLI instance or the resource driver
        let mut events = [EpollEvent::empty(); 2];
        let num_events = epoll::epoll_wait(epoll_fd, &mut events, -1).expect("epoll wait failed");
        if num_events == 0 {
            continue;
        }

        info!("Received event(s): {}", num_events);
        let mut input_stream = unsafe { UnixStream::from_raw_fd(events[0].data() as RawFd) };
        let cmd = receive_command_type(&mut input_stream).expect("Failed to receive command.");
        info!("Received command: {:?}", cmd);

        match cmd {
            EnclaveProcessCommandType::Start => {
                let run_args = receive_command_args::<RunEnclavesArgs>(&mut input_stream);
                info!("Run args = {:?}", run_args);
                // TODO: Launch an enclave from here.
            }

            EnclaveProcessCommandType::Stop => {
                info!("Stopping enclave process.");
                // TODO: Terminate the enclave.
                break;
            }

            _ => warn!("Command not supported."),
        };
    }

    info!("Enclave process {} exited event loop.", process::id());
}

/// Initialize the connection listener.
fn connection_listener_init() -> io::Result<(JoinHandle<()>, RawFd)> {
    // Obtain the path of the socket to listen on.
    let proc_dir_path = Path::new(ENCLAVE_PROC_SOCKET_DIR);
    if !proc_dir_path.exists() {
        std::fs::create_dir_all(ENCLAVE_PROC_SOCKET_DIR)
            .expect("Failed to create enclave process socket directory.");
    }

    let socket_path = format!("{}/{}.sock", ENCLAVE_PROC_SOCKET_DIR, process::id());
    info!("Will listen on socket: {}", socket_path);

    // Bind the listener to the socket and spawn the listener thread.
    let listener = UnixListener::bind(socket_path).expect("Error binding.");
    let epoll_fd = epoll::epoll_create().expect("Could not create epoll_fd.");
    let listener_thread = thread::spawn(move || connection_listener_run(listener, epoll_fd));
    Ok((listener_thread, epoll_fd))
}

/// Ignore a list of signals.
fn ignore_signal_handlers(ign_signals: &[Signal]) -> Vec<(Signal, SigHandler)> {
    let mut handlers: Vec<(Signal, SigHandler)> = vec![];
    for &ign_signal in ign_signals.iter() {
        let handler =
            unsafe { signal(ign_signal, SigHandler::SigIgn) }.expect("Failed to set signal.");
        handlers.push((ign_signal, handler));
    }

    handlers
}

/// Restore the signal handlers that were previously ignored.
fn restore_signal_handlers(handlers: &[(Signal, SigHandler)]) {
    for &(ign_signal, old_handler) in handlers.iter() {
        unsafe { signal(ign_signal, old_handler) }.expect("Failed to restore signal handler.");
    }
}

/// Create the enclave process.
fn create_enclave_process() {
    // To get a detached process, we first:
    // (1) Temporarily ignore specific signals (SIGHUP).
    // (2) Fork a child process.
    // (3) Terminate the parent (at which point the child becomes orphaned).
    // (4) Restore signal handlers.
    let old_sig_handlers = ignore_signal_handlers(&[Signal::SIGHUP]);

    // The current process must first become session leader.
    setsid().expect("setsid() failed.");

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
        let stat = pid::stat_self().expect("Failed to get process stat.");
        if stat.ppid == 1 {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }

    // Restore signal handlers.
    restore_signal_handlers(&old_sig_handlers);
}

/// Get a stream to the CLI.
fn get_stream_from_cli() -> UnixStream {
    let args: Vec<String> = env::args().collect();
    let fd = args[1].parse::<RawFd>().unwrap();
    unsafe { UnixStream::from_raw_fd(fd) }
}

/// Initialize logging.
fn init_logger() {
    // All logging shall be directed to a centralized file.
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(false)
        .open("/tmp/enclave-proc.log")
        .expect("Failed to open log file.");

    // STDOUT and STDERR are both redirected to that file.
    unsafe { libc::dup2(log_file.as_raw_fd(), libc::STDOUT_FILENO) };
    unsafe { libc::dup2(log_file.as_raw_fd(), libc::STDERR_FILENO) };

    env_logger::builder()
        .format(|buf, record| {
            // TODO: Update format to include enclave id
            writeln!(buf, "{}: {}", record.level(), record.args())
        })
        .target(env_logger::Target::Stdout)
        .init();
}

fn main() {
    init_logger();
    create_enclave_process();

    let (conn_thread, epoll_fd) = connection_listener_init().unwrap();
    let mut stream = get_stream_from_cli();
    info!("Stream = {:?}", stream);

    // At this point, process:id() returns the daemon's PID.
    write_u64_to_socket(&mut stream, process::id() as u64).expect("Failed to write PID to socket.");
    stream
        .shutdown(std::net::Shutdown::Both)
        .expect("Failed to shut down.");

    process_event_loop(epoll_fd);
    conn_thread.join().expect("Failed to join.");
}
