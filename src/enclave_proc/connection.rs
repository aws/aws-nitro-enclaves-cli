// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use nix::sys::epoll::EpollFlags;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::common::ExitGracefully;

/// An enclave process connection to a CLI instance, an enclave or itself.
pub struct Connection {
    epoll_flags: EpollFlags,
    input_stream: Option<UnixStream>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(input_stream) = &self.input_stream {
            // Close the stream.
            input_stream
                .shutdown(std::net::Shutdown::Both)
                .ok_or_exit("Failed to shut down.");
        }
    }
}

impl AsRawFd for Connection {
    fn as_raw_fd(&self) -> RawFd {
        self.input_stream.as_ref().unwrap().as_raw_fd()
    }
}

impl Connection {
    /// Create a new connection.
    pub fn new(epoll_flags: EpollFlags, input_stream: Option<UnixStream>) -> Self {
        Connection {
            epoll_flags,
            input_stream,
        }
    }

    /// Expose the connection for reading.
    pub fn as_reader(&mut self) -> &mut dyn Read {
        self.input_stream.as_mut().unwrap()
    }

    /// Expose the connection for writing.
    pub fn as_writer(&mut self) -> &mut dyn Write {
        self.input_stream.as_mut().unwrap()
    }

    // Get the enclave event flags.
    pub fn get_enclave_event_flags(&self) -> Option<EpollFlags> {
        match self.input_stream {
            None => Some(self.epoll_flags),
            _ => None,
        }
    }
}
