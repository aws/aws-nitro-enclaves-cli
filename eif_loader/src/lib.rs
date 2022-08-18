// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use libc::c_int;
use nix::poll::poll;
use nix::poll::{PollFd, PollFlags};
use std::io::Read;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use vsock::VsockListener;

/// Timeout of 1 second in milliseconds
pub const TIMEOUT_SECOND_MS: i32 = 1000;

/// Timeout of 1 minute 30 seconds in milliseconds
pub const TIMEOUT_MINUTE_MS: i32 = 90 * TIMEOUT_SECOND_MS;

const HEART_BEAT: u8 = 0xB7;

#[derive(Debug, PartialEq, Eq)]
/// Internal errors while sending an Eif file
pub enum EifLoaderError {
    SocketPollingError,
    VsockAcceptingError,
    VsockBindingError,
    VsockReceivingError,
    VsockTimeoutError,
}

pub fn enclave_ready(
    listener: VsockListener,
    poll_timeout_ms: c_int,
) -> Result<(), EifLoaderError> {
    let mut poll_fds = [PollFd::new(listener.as_raw_fd(), PollFlags::POLLIN)];
    let result = poll(&mut poll_fds, poll_timeout_ms);
    if result == Ok(0) {
        return Err(EifLoaderError::VsockTimeoutError);
    } else if result != Ok(1) {
        return Err(EifLoaderError::SocketPollingError);
    }

    let mut stream = listener
        .accept()
        .map_err(|_err| EifLoaderError::VsockAcceptingError)?;

    // Wait until the other end is closed
    let mut buf = [0u8];
    let bytes = stream
        .0
        .read(&mut buf)
        .map_err(|_err| EifLoaderError::VsockReceivingError)?;

    if bytes != 1 || buf[0] != HEART_BEAT {
        return Err(EifLoaderError::VsockReceivingError);
    }

    stream
        .0
        .write_all(&buf)
        .map_err(|_err| EifLoaderError::VsockReceivingError)?;

    Ok(())
}
