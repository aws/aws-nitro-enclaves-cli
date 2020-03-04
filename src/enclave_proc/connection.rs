// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use nix::sys::epoll::{self, EpollEvent, EpollOp};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::common::ExitGracefully;

/// An enclave process connection to a CLI instance or itself.
pub struct Connection {
    epoll_fd: RawFd,
    input_stream: UnixStream,
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Close the stream.
        self.input_stream
            .shutdown(std::net::Shutdown::Both)
            .ok_or_exit("Failed to shut down.");

        // Remove the descriptor from epoll.
        epoll::epoll_ctl(
            self.epoll_fd,
            EpollOp::EpollCtlDel,
            self.input_stream.as_raw_fd(),
            None,
        )
        .ok_or_exit("Failed to remove fd from epoll.");
    }
}

impl AsRawFd for Connection {
    fn as_raw_fd(&self) -> RawFd {
        self.input_stream.as_raw_fd()
    }
}

impl Connection {
    /// Create a new connection instance.
    pub fn new(epoll_fd: RawFd) -> Self {
        // Wait on epoll until a valid event is received.
        let mut events = [EpollEvent::empty(); 1];

        loop {
            let num_events =
                epoll::epoll_wait(epoll_fd, &mut events, -1).ok_or_exit("Waiting on epoll failed.");
            if num_events > 0 {
                break;
            }
        }

        // Obtain a unix stream for reading and writing data.
        let input_stream = unsafe { UnixStream::from_raw_fd(events[0].data() as RawFd) };
        Connection {
            epoll_fd,
            input_stream,
        }
    }

    /// Expose the connection for reading.
    pub fn as_reader(&mut self) -> &mut dyn Read {
        &mut self.input_stream
    }

    /// Expose the connection for writing.
    pub fn as_writer(&mut self) -> &mut dyn Write {
        &mut self.input_stream
    }
}
