// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use inotify::{EventMask, Inotify, WatchMask};
use log::{debug, warn};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::common::get_socket_path;
use crate::common::{ExitGracefully, NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::new_nitro_cli_failure;

/// The structure which manages the Unix socket that an enclave process listens on for commands.
#[derive(Default)]
pub struct EnclaveProcSock {
    /// The socket's file-system path.
    socket_path: PathBuf,
    /// The thread which listens for external events which delete the socket from the file-system.
    remove_listener_thread: Option<JoinHandle<()>>,
    /// A flag indicating if socket removal was requested.
    requested_remove: Arc<AtomicBool>,
}

/// The enclave process socket must allow cloning, since that is needed by the socket-listening thread.
impl Clone for EnclaveProcSock {
    fn clone(&self) -> Self {
        // Actually clone only what's relevant for the listening thread.
        EnclaveProcSock {
            socket_path: self.socket_path.clone(),
            remove_listener_thread: None,
            requested_remove: self.requested_remove.clone(),
        }
    }
}

impl Drop for EnclaveProcSock {
    fn drop(&mut self) {
        self.close_mut()
            .ok_or_exit_with_errno(Some("Failed to drop socket"));
    }
}

impl EnclaveProcSock {
    /// Create a new `EnclaveProcSock` instance from a given enclave ID.
    pub fn new(enclave_id: &str) -> NitroCliResult<Self> {
        let socket_path = get_socket_path(enclave_id).map_err(|_| {
            new_nitro_cli_failure!(
                "Failed to create enclave process socket",
                NitroCliErrorEnum::SocketPathNotFound
            )
        })?;

        Ok(EnclaveProcSock {
            socket_path,
            remove_listener_thread: None,
            requested_remove: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Get the path to the managed Unix socket.
    pub fn get_path(&self) -> &Path {
        self.socket_path.as_path()
    }

    /// Set the path of the managed Unix socket.
    pub fn set_path(&mut self, socket_path: PathBuf) {
        self.socket_path = socket_path;
    }

    /// Start monitoring the Unix socket's state using `inotify`.
    pub fn start_monitoring(&mut self, exit_on_delete: bool) -> NitroCliResult<()> {
        let path_clone = self.socket_path.clone();
        let requested_remove_clone = self.requested_remove.clone();
        let socket_inotify = Inotify::init().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to initialize socket notifications: {:?}", e),
                NitroCliErrorEnum::InotifyError
            )
        })?;

        // Relevant events to listen for are:
        // - IN_DELETE_SELF: triggered when the socket file inode gets removed.
        // - IN_ATTRIB: triggered when the reference count of the file inode changes.
        socket_inotify
            .watches()
            .add(
                self.socket_path.as_path(),
                WatchMask::ATTRIB | WatchMask::DELETE_SELF,
            )
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to add watch to inotify: {:?}", e),
                    NitroCliErrorEnum::InotifyError
                )
            })?;
        self.remove_listener_thread = Some(thread::spawn(move || {
            socket_removal_listener(
                path_clone,
                requested_remove_clone,
                socket_inotify,
                exit_on_delete,
            )
        }));
        Ok(())
    }

    /// Remove the managed Unix socket and clean up after it. This is called with a mutable self-reference.
    fn close_mut(&mut self) -> NitroCliResult<()> {
        // Delete the socket from the disk. Also mark that this operation is intended, so that the
        // socket file monitoring thread doesn't exit forcefully when notifying the deletion.
        self.requested_remove.store(true, Ordering::SeqCst);
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).map_err(|e| {
                new_nitro_cli_failure!(
                    &format!(
                        "Failed to remove socket file {:?} from disk: {:?}",
                        self.socket_path, e
                    ),
                    NitroCliErrorEnum::FileOperationFailure
                )
                .add_info(vec![
                    self.socket_path
                        .to_str()
                        .unwrap_or("Invalid unicode socket file name"),
                    "Remove",
                ])
            })?;
        }

        // Since the socket file has been deleted, we also wait for the event listener thread to finish.
        if self.remove_listener_thread.is_some() {
            self.remove_listener_thread
                .take()
                .unwrap()
                .join()
                .map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to join socket notification thread: {:?}", e),
                        NitroCliErrorEnum::ThreadJoinFailure
                    )
                })?;
        }

        Ok(())
    }

    /// Remove the managed Unix socket and clean up after it.
    pub fn close(mut self) -> NitroCliResult<()> {
        self.close_mut()
            .map_err(|e| e.add_subaction("Close socket".to_string()))
    }
}

/// Listen for an `inotify` event when the socket gets deleted from the disk.
fn socket_removal_listener(
    socket_path: PathBuf,
    requested_remove: Arc<AtomicBool>,
    mut socket_inotify: Inotify,
    exit_on_delete: bool,
) {
    let mut buffer = [0u8; 4096];
    let mut done = false;

    debug!("Socket file event listener started for {:?}.", socket_path);

    while !done {
        // Read events.
        let events = socket_inotify
            .read_events_blocking(&mut buffer)
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Socket removal listener error: {:?}", e),
                    NitroCliErrorEnum::InotifyError
                )
                .set_action("Run Enclave".to_string())
            })
            .ok_or_exit_with_errno(Some("Failed to read inotify events"));

        for event in events {
            // We monitor the DELETE_SELF event, which occurs when the inode is no longer referenced by anybody. We
            // also monitor the IN_ATTRIB event, which gets triggered whenever the inode reference count changes. To
            // make sure this is a deletion, we also verify if the socket file is still present in the file-system.
            if (event.mask.contains(EventMask::ATTRIB)
                || event.mask.contains(EventMask::DELETE_SELF))
                && !socket_path.exists()
            {
                if requested_remove.load(Ordering::SeqCst) {
                    // At this point, the socket is shutting itself down and has notified the
                    // monitoring thread, so we just exit the loop gracefully.
                    debug!("The enclave process socket has deleted itself.");
                    done = true;
                } else {
                    // At this point, the socket has been deleted by an external action, so
                    // we exit forcefully, since there is no longer any way for a CLI instance
                    // to tell the current enclave process to terminate.
                    warn!("The enclave process socket has been deleted!");
                    if exit_on_delete {
                        std::process::exit(1);
                    }
                    done = true;
                }
            }
        }
    }

    debug!("Enclave process socket monitoring is done.");
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixListener;
    use std::process::Command;

    const DUMMY_ENCLAVE_ID: &str = "i-0000000000000000-enc0123456789012345";
    const THREADS_STR: &str = "Threads:";
    const WAIT_REMOVE_MILLIS: u64 = 10;

    /// Inspects the content of /proc/<PID>/status in order to
    /// retrieve the number of threads running in the context of
    /// process <PID>.
    fn get_num_threads_from_status_output(status_str: String) -> u32 {
        let start_idx = status_str.find(THREADS_STR);
        let mut iter = status_str.chars();
        iter.by_ref().nth(start_idx.unwrap() + THREADS_STR.len()); // skip "Threads:\t"
        let slice = iter.as_str();

        let new_str = slice.to_string();
        let end_idx = new_str.find('\n'); // skip after the first '\n'
        let substr = &slice[..end_idx.unwrap()];

        substr.parse().unwrap()
    }

    /// Tests that the initial values of the EnclaveProcSock attributes match the
    /// expected ones.
    #[test]
    fn test_enclaveprocsock_init() {
        let socket = EnclaveProcSock::new(DUMMY_ENCLAVE_ID);

        assert!(socket.is_ok());

        if let Ok(socket) = socket {
            assert!(socket
                .socket_path
                .as_path()
                .to_str()
                .unwrap()
                .contains("0123456789012345"));
            assert!(socket.remove_listener_thread.is_none());
            assert!(!socket.requested_remove.load(Ordering::SeqCst));
        }
    }

    /// Tests that removing the socket file by means other than `close()` does not
    /// trigger a `socket.requested_remove` change.
    #[test]
    fn test_start_monitoring() {
        let socket = EnclaveProcSock::new(DUMMY_ENCLAVE_ID);

        assert!(socket.is_ok());

        if let Ok(mut socket) = socket {
            UnixListener::bind(socket.get_path())
                .map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to bind to socket: {:?}", e),
                        NitroCliErrorEnum::SocketError
                    )
                })
                .ok_or_exit_with_errno(Some("Error binding"));
            let result = socket.start_monitoring(false);

            assert!(result.is_ok());

            // Remove socket file and expect `socket.requested_remove` to remain False
            std::fs::remove_file(&socket.socket_path).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(WAIT_REMOVE_MILLIS));

            assert!(!socket.requested_remove.load(Ordering::SeqCst));
        }
    }

    /// Test that calling `close()` changes `socket.requested_remove` to True and
    /// that the listener thread joins.
    #[test]
    fn test_close() {
        let socket = EnclaveProcSock::new(DUMMY_ENCLAVE_ID);

        assert!(socket.is_ok());

        // Get number of running threads before spawning the socket removal listener thread
        let out_cmd0 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out0 = std::str::from_utf8(&out_cmd0.stdout).unwrap();
        let crt_num_threads0 = get_num_threads_from_status_output(out0.to_string());

        if let Ok(mut socket) = socket {
            let _ = UnixListener::bind(socket.get_path())
                .map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to bind to socket: {:?}", e),
                        NitroCliErrorEnum::SocketError
                    )
                })
                .ok_or_exit_with_errno(Some("Error binding"));
            let result = socket.start_monitoring(true);

            assert!(result.is_ok());

            // Call `close_mut()` and expect `socket.requested_remove` to change to True
            let result = socket.close_mut();

            assert!(result.is_ok());
            assert!(socket.requested_remove.load(Ordering::SeqCst));
        }

        // Get number of running threads after closing the socket removal listener thread
        let out_cmd1 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out1 = std::str::from_utf8(&out_cmd1.stdout).unwrap();
        let crt_num_threads1 = get_num_threads_from_status_output(out1.to_string());

        // Check that the number of threads remains the same before and after running the test
        assert_eq!(crt_num_threads0, crt_num_threads1);
    }
}
