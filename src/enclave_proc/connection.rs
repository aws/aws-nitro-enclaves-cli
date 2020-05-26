// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use nix::sys::epoll::EpollFlags;
use serde::de::DeserializeOwned;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::string::ToString;
use std::sync::{Arc, Mutex};

use crate::common::{receive_from_stream, write_u64_le};
use crate::common::{EnclaveProcessReply, ExitGracefully, NitroCliResult};

struct ConnectionData {
    epoll_flags: EpollFlags,
    input_stream: Option<UnixStream>,
}

/// An enclave process connection to a CLI instance, an enclave or itself.
#[derive(Clone)]
pub struct Connection {
    data: Arc<Mutex<ConnectionData>>,
}

impl Drop for ConnectionData {
    fn drop(&mut self) {
        if let Some(input_stream) = &self.input_stream {
            // Close the stream.
            input_stream
                .shutdown(std::net::Shutdown::Both)
                .ok_or_exit("Failed to shut down.");
        }
    }
}

impl Connection {
    /// Create a new connection instance.
    pub fn new(epoll_flags: EpollFlags, input_stream: Option<UnixStream>) -> Self {
        let conn_data = ConnectionData {
            epoll_flags,
            input_stream,
        };

        Connection {
            data: Arc::new(Mutex::new(conn_data)),
        }
    }

    /// Read an object from this connection.
    pub fn read<T>(&self) -> NitroCliResult<T>
    where
        T: DeserializeOwned,
    {
        let mut lock = self.data.lock().map_err(|e| e.to_string())?;
        if lock.input_stream.is_none() {
            return Err("Cannot read from this connection.".to_string());
        }

        receive_from_stream::<T>(lock.input_stream.as_mut().unwrap()).map_err(|e| e.to_string())
    }

    /// Write a u64 value on this connection.
    pub fn write_u64(&self, value: u64) -> NitroCliResult<()> {
        let mut lock = self.data.lock().map_err(|e| e.to_string())?;
        if lock.input_stream.is_none() {
            return Err("Cannot write a 64-bit value to this connection.".to_string());
        }

        write_u64_le(lock.input_stream.as_mut().unwrap(), value).map_err(|e| e.to_string())
    }

    /// Write a message to the standard output of the connection's other end.
    pub fn println(&self, msg: &str) -> NitroCliResult<()> {
        let mut msg_str = msg.to_string();

        // Append a new-line at the end of the string.
        msg_str.push('\n');

        let reply = EnclaveProcessReply::StdOutMessage(msg_str);
        self.write_reply(&reply)
    }

    /// Write a message to the standard error of the connection's other end.
    pub fn eprintln(&self, msg: &str) -> NitroCliResult<()> {
        let mut msg_str = msg.to_string();

        // Append a new-line at the end of the string.
        msg_str.push('\n');

        let reply = EnclaveProcessReply::StdErrMessage(msg_str);
        self.write_reply(&reply)
    }

    /// Write an operation's status to the connection's other end.
    pub fn write_status(&self, status: i32) -> NitroCliResult<()> {
        let reply = EnclaveProcessReply::Status(status);
        self.write_reply(&reply)
    }

    // Get the enclave event flags.
    pub fn get_enclave_event_flags(&self) -> Option<EpollFlags> {
        let lock = self
            .data
            .lock()
            .ok_or_exit("Failed to get connection lock.");
        match lock.input_stream {
            None => Some(lock.epoll_flags),
            _ => None,
        }
    }

    /// Write a string and its corresponding destination to a socket.
    fn write_reply(&self, reply: &EnclaveProcessReply) -> NitroCliResult<()> {
        let mut lock = self.data.lock().map_err(|e| e.to_string())?;
        if lock.input_stream.is_none() {
            return Err("Cannot write a message to this connection.".to_string());
        }

        let mut stream = lock.input_stream.as_mut().unwrap();
        let reply_bytes = serde_cbor::to_vec(reply).map_err(|e| e.to_string())?;

        write_u64_le(&mut stream, reply_bytes.len() as u64).map_err(|e| e.to_string())?;
        stream.write_all(&reply_bytes).map_err(|e| e.to_string())
    }
}

/// Print a STDOUT message to a connection. Do nothing if the connection is missing.
pub fn safe_conn_println(conn: Option<&Connection>, msg: &str) -> NitroCliResult<()> {
    if conn.is_none() {
        return Ok(());
    }

    conn.unwrap().println(msg)
}

/// Print a STDERR message to a connection. Do nothing if the connection is missing.
pub fn safe_conn_eprintln(conn: Option<&Connection>, msg: &str) -> NitroCliResult<()> {
    if conn.is_none() {
        return Ok(());
    }

    conn.unwrap().eprintln(msg)
}
