// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod commands_parser;

use log::error;
use signal_hook::iterator::Signals;
use signal_hook::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::thread::spawn;

pub type NitroCliResult<T> = Result<T, String>;

pub const ENCLAVE_PROC_SOCKET_DIR: &str = "/root/.npe";
pub const ENCLAVE_PROC_DIR_VAR: &str = "ENCLAVE_PROC_DIR";
pub const ENCLAVE_PROC_BINARY: &str = "enclave-proc";

pub trait ExitGracefully<T, E> {
    fn ok_or_exit(self, message: &str) -> T;
}

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

impl<T, E: std::fmt::Debug> ExitGracefully<T, E> for Result<T, E> {
    fn ok_or_exit(self, message: &str) -> T {
        match self {
            Ok(val) => val,
            Err(err) => {
                error!("{:?}: {}", err, message);
                std::process::exit(1);
            }
        }
    }
}

pub fn handle_signals() {
    let signals =
        Signals::new(&[SIGINT, SIGQUIT, SIGTERM, SIGHUP]).ok_or_exit("Could not handle signals");
    spawn(move || {
        for sig in signals.forever() {
            if sig != SIGHUP {
                eprintln!("Warning! Trying to stop a command could leave the enclave in an unsafe state. If you think something is wrong please use SIGKILL to terminate the command.");
            }
        }
    });
}
