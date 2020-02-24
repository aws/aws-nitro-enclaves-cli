// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod commands_parser;

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

pub const ENCLAVE_PROC_SOCKET_DIR: &str = "/root/.npe";
pub const ENCLAVE_PROC_DIR_VAR: &str = "ENCLAVE_PROC_DIR";
pub const ENCLAVE_PROC_BINARY: &str = "enclave-proc";

/// Read a LE-encoded number from a socket.
pub fn read_u64_from_socket(socket: &mut UnixStream) -> io::Result<u64> {
    let mut bytes = [0u8; std::mem::size_of::<u64>()];
    socket.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Write a LE-encoded number to a socket.
pub fn write_u64_to_socket(socket: &mut UnixStream, value: u64) -> io::Result<()> {
    let bytes = value.to_le_bytes();
    socket.write_all(&bytes)
}
