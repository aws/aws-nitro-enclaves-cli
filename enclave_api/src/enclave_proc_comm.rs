// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use log::info;
use nix::unistd::*;
use serde::de::DeserializeOwned;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::u64;

use crate::common::commands_parser::EmptyArgs;
use crate::common::{
    enclave_proc_command_send_single, get_socket_path, read_u64_le, receive_from_stream,
};
use crate::common::{
    EnclaveProcessCommandType, EnclaveProcessReply, NitroCliErrorEnum, NitroCliFailure,
    NitroCliResult,
};
use crate::enclave_proc::enclave_process_run;
use crate::new_nitro_cli_failure;

/// Spawn an enclave process and wait until it has detached and has
/// taken ownership of its communication socket.
pub fn enclave_proc_spawn() -> NitroCliResult<UnixStream> {
    let (cli_socket, enclave_proc_socket) = UnixStream::pair().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Could not create a socket pair: {:?}", e),
            NitroCliErrorEnum::SocketPairCreationFailure
        )
    })?;

    // Prevent the descriptor from being closed when calling exec().
    let enclave_proc_fd = enclave_proc_socket.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(enclave_proc_fd, libc::F_GETFD);
        libc::fcntl(enclave_proc_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }

    // Spawn an intermediate child process. This will fork again in order to
    // create the detached enclave process.
    let fork_status = fork();

    if let Ok(ForkResult::Child) = fork_status {
        // This is our intermediate child process.
        enclave_process_run(enclave_proc_socket);
    } else {
        fork_status.map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to create intermediate process: {:?}", e),
                NitroCliErrorEnum::ProcessSpawnFailure
            )
        })?;
    }

    // The enclave process will open a socket named "<enclave_id>.sock", but this
    // will only become available after the enclave has been successfully launched.
    // Until then, we can only use the pre-initialized socket pair to communicate
    // with the new process.
    Ok(cli_socket)
}

/// Open a connection to an enclave-specific socket.
pub fn enclave_proc_connect_to_single(enclave_id: &str) -> NitroCliResult<UnixStream> {
    let socket_path = get_socket_path(enclave_id).map_err(|e| {
        e.add_subaction("Connect to specific enclave process".to_string())
            .set_error_code(NitroCliErrorEnum::SocketError)
    })?;
    UnixStream::connect(socket_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to connect to specific enclave process: {:?}", e),
            NitroCliErrorEnum::SocketError
        )
    })
}

/// Print the output from a single enclave process.
pub fn enclave_proc_handle_output<T>(conn: &mut UnixStream) -> NitroCliResult<T>
where
    T: DeserializeOwned,
{
    let mut stdout_str = String::new();
    let mut stderr_str = String::new();
    let mut status: Option<i32> = None;

    // The contents meant for standard output must always form a valid JSON object.
    while let Ok(reply) = receive_from_stream::<EnclaveProcessReply>(conn) {
        match reply {
            EnclaveProcessReply::StdOutMessage(msg) => stdout_str.push_str(&msg),
            EnclaveProcessReply::StdErrMessage(msg) => stderr_str.push_str(&msg),
            EnclaveProcessReply::Status(status_code) => status = Some(status_code),
        }
    }

    // Shut the connection down.
    if let Err(e) = conn.shutdown(std::net::Shutdown::Both) {
        return Err(new_nitro_cli_failure!(
            &format!("Failed to shut down connection down {}, {}", e, stderr_str),
            NitroCliErrorEnum::SocketError
        ));
    }

    // Decode the JSON object.
    let json_obj = serde_json::from_str::<T>(&stdout_str).ok();

    if let Some(status_code) = status {
        if status_code == libc::EACCES {
            return Err(new_nitro_cli_failure!(
                &format!("Operation not permitted {}", stderr_str),
                NitroCliErrorEnum::UnspecifiedError
            ));
        } else if status_code != 0 {
            return Err(new_nitro_cli_failure!(
                stderr_str,
                NitroCliErrorEnum::UnspecifiedError
            ));
        }
    }

    if json_obj.is_none() {
        return Err(new_nitro_cli_failure!(
            &format!("Failed to parse enclave proc response {}", stderr_str),
            NitroCliErrorEnum::SerdeError
        ));
    }

    Ok(json_obj.unwrap())
}

/// Obtain an enclave's CID given its full ID.
pub fn enclave_proc_get_cid(enclave_id: &str) -> NitroCliResult<u64> {
    let mut comm = enclave_proc_connect_to_single(enclave_id)
        .map_err(|e| e.add_subaction("Failed to connect to enclave process".to_string()))?;
    // TODO: Replicate output of old CLI on invalid enclave IDs.
    enclave_proc_command_send_single::<EmptyArgs>(
        EnclaveProcessCommandType::GetEnclaveCID,
        None,
        &mut comm,
    )
    .map_err(|e| e.add_subaction("Failed to send CID request to enclave process".to_string()))?;

    info!("Sent command: GetEnclaveCID");
    let enclave_cid = read_u64_le(&mut comm)
        .map_err(|e| e.add_subaction(String::from("Failed to read CID from enclave process")))?;

    // We got the CID, so shut the connection down.
    comm.shutdown(std::net::Shutdown::Both).map_err(|e| {
        new_nitro_cli_failure!(
            &format!(
                "Failed to shut down connection after obtaining CID: {:?}",
                e
            ),
            NitroCliErrorEnum::SocketError
        )
    })?;

    Ok(enclave_cid)
}
