// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use log::{debug, warn};
use nix::sys::epoll::EpollFlags;
use nix::sys::socket::sockopt::PeerCredentials;
use nix::sys::socket::UnixCredentials;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use crate::common::{receive_from_stream, write_u64_le};
use crate::common::{
    EnclaveProcessCommandType, EnclaveProcessReply, ExitGracefully, NitroCliErrorEnum,
    NitroCliFailure, NitroCliResult,
};
use crate::new_nitro_cli_failure;

/// The types of requesters which may send commands to the enclave process.
#[derive(PartialEq, Eq, Hash)]
enum CommandRequesterType {
    /// The requester is the user with the given UID.
    User(libc::uid_t),
    /// The requester is the group with the given GID.
    Group(libc::gid_t),
    /// The requester is any other user.
    Others,
}

/// The policy used to filter received commands based on the requester's type.
struct CommandRequesterPolicy {
    /// A mapping between a requester's type and all of its allowed commands.
    policy: HashMap<CommandRequesterType, Vec<EnclaveProcessCommandType>>,
}

/// Data held by a connection.
struct ConnectionData {
    /// Flags received from `epoll` if this was an event-triggered connection.
    epoll_flags: EpollFlags,
    /// A communication stream with the peer, if this was a socket-triggered connection.
    input_stream: Option<UnixStream>,
}

/// An enclave process connection to a CLI instance, an enclave or itself.
#[derive(Clone)]
pub struct Connection {
    /// The thread-safe data used internally by the connection.
    data: Arc<Mutex<ConnectionData>>,
}

impl Drop for ConnectionData {
    fn drop(&mut self) {
        if let Some(input_stream) = &self.input_stream {
            // Close the stream.
            input_stream
                .shutdown(std::net::Shutdown::Both)
                .map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Stream shutdown error: {:?}", e),
                        NitroCliErrorEnum::SocketCloseError
                    )
                })
                .ok_or_exit_with_errno(Some("Failed to shut down"));
        }
    }
}

impl CommandRequesterPolicy {
    /// Create a new `CommandRequesterPolicy` with the default rules. These rules allow
    /// the user which spawned the enclave, together with `root`, to make any request,
    /// whereas all other users are only allowed to make read-only requests (namely,
    /// to describe an enclave or to read its CID).
    fn new_with_defaults() -> Self {
        let cmds_read_write = vec![
            EnclaveProcessCommandType::Run,
            EnclaveProcessCommandType::Terminate,
            EnclaveProcessCommandType::TerminateComplete,
            EnclaveProcessCommandType::Describe,
            EnclaveProcessCommandType::GetEnclaveCID,
            EnclaveProcessCommandType::GetEnclaveFlags,
            EnclaveProcessCommandType::GetEnclaveName,
            EnclaveProcessCommandType::GetIDbyName,
            EnclaveProcessCommandType::ConnectionListenerStop,
        ];
        let cmds_read_only = vec![
            EnclaveProcessCommandType::Describe,
            EnclaveProcessCommandType::GetEnclaveCID,
            EnclaveProcessCommandType::GetEnclaveFlags,
            EnclaveProcessCommandType::GetEnclaveName,
            EnclaveProcessCommandType::GetIDbyName,
        ];
        let mut policy = HashMap::new();

        // The user which owns this enclave process may issue any command.
        policy.insert(
            CommandRequesterType::User(unsafe { libc::getuid() }),
            cmds_read_write.clone(),
        );

        // The root user may issue any command.
        policy.insert(CommandRequesterType::User(0_u32), cmds_read_write);

        // All other users may only issue read-only commands.
        policy.insert(CommandRequesterType::Others, cmds_read_only);

        CommandRequesterPolicy { policy }
    }

    /// Find the policy rule which applies to the given requester and command.
    fn find_policy_rule(
        &self,
        cmd: EnclaveProcessCommandType,
        requester: &CommandRequesterType,
    ) -> bool {
        match self.policy.get(requester) {
            None => false,
            Some(allowed_cmds) => allowed_cmds.contains(&cmd),
        }
    }

    /// Check if the user with the specified credentials has permission to run the specified command.
    fn can_execute_command(&self, cmd: EnclaveProcessCommandType, creds: &UnixCredentials) -> bool {
        // Search for a policy rule on the provided user ID.
        if self.find_policy_rule(cmd, &CommandRequesterType::User(creds.uid())) {
            return true;
        }

        // Search for a policy rule on the provided group ID.
        if self.find_policy_rule(cmd, &CommandRequesterType::Group(creds.gid())) {
            return true;
        }

        // Search for a policy rule on all other users.
        if self.find_policy_rule(cmd, &CommandRequesterType::Others) {
            return true;
        }

        // If we haven't found any applicable policy rule we can't allow the command to be executed.
        false
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

    /// Read a command and its corresponding credentials.
    pub fn read_command(&self) -> NitroCliResult<EnclaveProcessCommandType> {
        let mut lock = self.data.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        if lock.input_stream.is_none() {
            return Err(new_nitro_cli_failure!(
                "Cannot read a command from this connection",
                NitroCliErrorEnum::UnusableConnectionError
            ));
        }

        // First, read the incoming command.
        let mut cmd =
            receive_from_stream::<EnclaveProcessCommandType>(lock.input_stream.as_mut().unwrap())?;

        // Next, read the credentials of the command requester.
        let conn_fd = lock.input_stream.as_ref().unwrap().as_raw_fd();
        let socket_creds = nix::sys::socket::getsockopt(conn_fd, PeerCredentials);

        // If the credentials cannot be read, the command will be skipped.
        let user_creds = match socket_creds {
            Ok(creds) => creds,
            Err(e) => {
                warn!("Failed to get user credentials: {}", e);
                return Ok(EnclaveProcessCommandType::NotPermitted);
            }
        };

        // Apply the default command access policy based on the user's credentials.
        let policy = CommandRequesterPolicy::new_with_defaults();
        if !policy.can_execute_command(cmd, &user_creds) {
            // Log the failed execution attempt.
            warn!(
                "The requester with credentials ({:?}) is not allowed to perform '{:?}'.",
                user_creds, cmd
            );

            // Force the command to be skipped by the main event loop.
            cmd = EnclaveProcessCommandType::NotPermitted;
        } else {
            // Log the successful execution attempt.
            debug!(
                "The requester with credentials ({:?}) is allowed to perform '{:?}'.",
                user_creds, cmd
            );
        }

        Ok(cmd)
    }

    /// Read an object of the specified type from this connection.
    pub fn read<T>(&self) -> NitroCliResult<T>
    where
        T: DeserializeOwned,
    {
        let mut lock = self.data.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        if lock.input_stream.is_none() {
            return Err(new_nitro_cli_failure!(
                "Cannot read from this connection",
                NitroCliErrorEnum::SocketError
            ));
        }

        receive_from_stream::<T>(lock.input_stream.as_mut().unwrap())
    }

    /// Write a 64-bit unsigned value on this connection.
    pub fn write_u64(&self, value: u64) -> NitroCliResult<()> {
        let mut lock = self.data.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        if lock.input_stream.is_none() {
            return Err(new_nitro_cli_failure!(
                "Cannot write a 64-bit value to this connection",
                NitroCliErrorEnum::SocketError
            ));
        }

        write_u64_le(lock.input_stream.as_mut().unwrap(), value)
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

    /// Get the enclave event flags.
    pub fn get_enclave_event_flags(&self) -> NitroCliResult<Option<EpollFlags>> {
        let lock = self.data.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire connection lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        match lock.input_stream {
            None => Ok(Some(lock.epoll_flags)),
            _ => Ok(None),
        }
    }

    /// Write a string and its corresponding destination to a socket.
    fn write_reply(&self, reply: &EnclaveProcessReply) -> NitroCliResult<()> {
        let mut lock = self.data.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        if lock.input_stream.is_none() {
            return Err(new_nitro_cli_failure!(
                "Cannot write message to connection",
                NitroCliErrorEnum::SocketError
            ));
        }

        let mut stream = lock.input_stream.as_mut().unwrap();
        let reply_bytes = serde_cbor::to_vec(reply).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to serialize reply: {:?}", e),
                NitroCliErrorEnum::SerdeError
            )
        })?;

        write_u64_le(&mut stream, reply_bytes.len() as u64)
            .map_err(|e| e.add_subaction("Write reply".to_string()))?;
        stream.write_all(&reply_bytes).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write to stream: {:?}", e),
                NitroCliErrorEnum::SocketError
            )
        })
    }
}

/// Print a message to a connection's standard output, if the connection is available.
pub fn safe_conn_println(conn: Option<&Connection>, msg: &str) -> NitroCliResult<()> {
    if conn.is_none() {
        return Ok(());
    }

    conn.unwrap().println(msg)
}

/// Print a message to a connection's standard error, if the connection is available.
pub fn safe_conn_eprintln(conn: Option<&Connection>, msg: &str) -> NitroCliResult<()> {
    if conn.is_none() {
        return Ok(());
    }

    conn.unwrap().eprintln(msg)
}
