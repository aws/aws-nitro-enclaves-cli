// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::{debug, info, warn};
use nix::sys::epoll::{self, EpollEvent, EpollFlags, EpollOp};
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread::{self, JoinHandle};

use super::connection::Connection;
use super::socket::EnclaveProcSock;
use crate::common::commands_parser::EmptyArgs;
use crate::common::{enclave_proc_command_send_single, receive_command_type};
use crate::common::{EnclaveProcessCommandType, ExitGracefully};

/// A listener which waits for external connections.
pub struct ConnectionListener {
    /// The epoll descriptor used to register new connections.
    epoll_fd: RawFd,
    /// The thread which actually listens for new connections
    listener_thread: Option<JoinHandle<()>>,
    /// The Unix socket that the listener binds to.
    socket: EnclaveProcSock,
}

/// The listener must be cloned when launching the listening thread.
impl Clone for ConnectionListener {
    fn clone(&self) -> Self {
        // Actually clone only what's relevant for the listening thread.
        ConnectionListener {
            epoll_fd: self.epoll_fd,
            listener_thread: None,
            socket: self.socket.clone(),
        }
    }
}

impl ConnectionListener {
    /// Create a new connection listener.
    pub fn new() -> Self {
        ConnectionListener {
            epoll_fd: epoll::epoll_create().ok_or_exit("Could not create epoll_fd."),
            listener_thread: None,
            socket: EnclaveProcSock::default(),
        }
    }

    /// Expose the epoll descriptor.
    pub fn get_epoll_fd(&self) -> RawFd {
        self.epoll_fd
    }

    /// Initialize the connection listener.
    pub fn start(&mut self, enclave_id: &String) -> io::Result<()> {
        // Obtain the socket to listen on.
        self.socket = EnclaveProcSock::new(enclave_id)?;

        let self_clone = self.clone();
        self.listener_thread = Some(thread::spawn(move || self_clone.connection_listener_run()));

        Ok(())
    }

    /// Add a stream to epoll.
    pub fn add_stream_to_epoll(&self, stream: UnixStream) {
        let stream_fd = stream.as_raw_fd();
        let mut cli_evt = EpollEvent::new(EpollFlags::EPOLLIN, stream.into_raw_fd() as u64);
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlAdd, stream_fd, &mut cli_evt)
            .ok_or_exit("Could not add new connection descriptor to epoll.");
    }

    /// Add the enclave descriptor to epoll.
    pub fn register_enclave_descriptor(&mut self, enc_fd: RawFd) {
        let mut enc_event = EpollEvent::new(
            EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
            enc_fd as u64,
        );
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlAdd, enc_fd, &mut enc_event)
            .ok_or_exit("Could not add enclave descriptor to epoll.");
    }

    /// Handle a new connection.
    pub fn handle_new_connection(&self, mut stream: UnixStream) -> EnclaveProcessCommandType {
        let cmd_type = receive_command_type(&mut stream).ok_or_exit("Failed to read command type.");

        // All connections must be registered with epoll, with the exception of the shutdown one.
        if cmd_type != EnclaveProcessCommandType::ConnectionListenerStop {
            self.add_stream_to_epoll(stream);
        }

        cmd_type
    }

    /// Wait for and handle new connections.
    fn connection_listener_run(mut self) {
        // Bind the listener to the socket and spawn the listener thread.
        let listener = UnixListener::bind(self.socket.get_path()).ok_or_exit("Error binding.");
        self.socket
            .start_monitoring()
            .ok_or_exit("Error monitoring socket.");
        debug!(
            "Connection listener started on socket {:?}.",
            self.socket.get_path()
        );

        // Accept connections and process them (this is a blocking call).
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // Received a new connection. Shut down if required.
                    if self.handle_new_connection(stream)
                        == EnclaveProcessCommandType::ConnectionListenerStop
                    {
                        break;
                    }
                }
                Err(err) => {
                    // Connection failed.
                    warn!("Connection error: {:?}", err);
                    break;
                }
            }
        }

        // Remove the listener's socket.
        self.socket.close();
        debug!("Connection listener has finished.");
    }

    /// Terminate the connection listener.
    pub fn stop(self) {
        // Nothing to do if the connection listener thread has not been started.
        if self.listener_thread.is_none() {
            return;
        }

        // Send termination notification to the listener thread.
        let mut self_conn = UnixStream::connect(self.socket.get_path())
            .ok_or_exit("Failed to connect to our own socket.");
        enclave_proc_command_send_single::<EmptyArgs>(
            &EnclaveProcessCommandType::ConnectionListenerStop,
            None,
            &mut self_conn,
        )
        .ok_or_exit("Failed to notify listener thread of shutdown.");

        // Shut the connection down.
        self_conn
            .shutdown(std::net::Shutdown::Both)
            .ok_or_exit("Failed to shut down.");

        // Ensure that the listener thread has terminated.
        self.listener_thread
            .unwrap()
            .join()
            .ok_or_exit("Failed to join listener thread.");
        info!("The connection listener has been stopped.");
    }

    /// Fetch the next available connection.
    pub fn get_next_connection(&self, enc_fd: Option<RawFd>) -> Connection {
        // Wait on epoll until a valid event is received.
        let mut events = [EpollEvent::empty(); 1];

        loop {
            let num_events = epoll::epoll_wait(self.epoll_fd, &mut events, -1)
                .ok_or_exit("Waiting on epoll failed.");
            if num_events > 0 {
                break;
            }
        }

        let fd = events[0].data() as RawFd;
        let input_stream = match enc_fd {
            // This is a connection to an enclave.
            Some(enc_fd) if enc_fd == fd => None,
            // This is a connection to a CLI instance or to ourselves.
            _ => Some(unsafe { UnixStream::from_raw_fd(fd) }),
        };

        // Remove the fetched descriptor from epoll. We are doing this here since
        // otherwise the Connection would have to do it when dropped and we prefer
        // the Connection not touch epoll directly.
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlDel, fd, None)
            .ok_or_exit("Failed to remove fd from epoll.");

        Connection::new(events[0].events(), input_stream)
    }
}
