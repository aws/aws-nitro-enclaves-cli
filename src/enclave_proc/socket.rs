// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use inotify::{EventMask, Inotify, WatchMask};
use log::{debug, warn};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::common::ExitGracefully;
use crate::common::{create_resources_dir, get_socket_path};

#[derive(Default)]
pub struct EnclaveProcSock {
    socket_path: String,
    remove_listener_thread: Option<JoinHandle<()>>,
    requested_remove: Arc<AtomicBool>,
}

/// The listener must be cloned when launching the listening thread.
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
        self.close_mut();
    }
}

impl EnclaveProcSock {
    pub fn new(enclave_id: &String) -> io::Result<Self> {
        create_resources_dir()?;
        let socket_path = get_socket_path(enclave_id)?;

        Ok(EnclaveProcSock {
            socket_path: socket_path.clone(),
            remove_listener_thread: None,
            requested_remove: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn get_path(&self) -> &String {
        &self.socket_path
    }

    pub fn start_monitoring(&mut self) -> io::Result<()> {
        let path_clone = self.socket_path.clone();
        let requested_remove_clone = self.requested_remove.clone();
        let mut socket_inotify = Inotify::init()?;

        // Relevant events to listen for are:
        // - IN_DELETE_SELF: triggered when the socket file inode gets removed.
        // - IN_ATTRIB: triggered when the reference count of the file inode changes.
        socket_inotify.add_watch(
            self.socket_path.as_str(),
            WatchMask::ATTRIB | WatchMask::DELETE_SELF,
        )?;
        self.remove_listener_thread = Some(thread::spawn(move || {
            socket_removal_listener(path_clone, requested_remove_clone, socket_inotify)
        }));
        Ok(())
    }

    fn close_mut(&mut self) {
        // Delete the socket from the disk. Also mark that this operation is intended, so that the
        // socket file monitoring thread doesn't exit forcefully when notifying the deletion.
        self.requested_remove.store(true, Ordering::SeqCst);
        if Path::new(self.socket_path.as_str()).exists() {
            std::fs::remove_file(&self.socket_path)
                .ok_or_exit(&format!("Failed to remove socket '{}'.", self.socket_path));
        }

        // Since the socket file has been deleted, we also wait for the event listener thread to finish.
        if self.remove_listener_thread.is_some() {
            self.remove_listener_thread
                .take()
                .unwrap()
                .join()
                .ok_or_exit("Failed to join socket notification thread.");
        }
    }

    pub fn close(mut self) {
        self.close_mut();
    }
}

/// Listen for an inotify event when the socket gets deleted from the disk.
fn socket_removal_listener(
    socket_path: String,
    requested_remove: Arc<AtomicBool>,
    mut socket_inotify: Inotify,
) {
    let mut buffer = [0u8; 4096];
    let mut done = false;

    debug!("Socket file event listener started for '{}'.", socket_path);

    while !done {
        // Read events.
        let events = socket_inotify
            .read_events_blocking(&mut buffer)
            .ok_or_exit("Failed to read inotify events.");

        for event in events {
            // We monitor the DELETE_SELF event, which occurs when the inode is no longer referenced by anybody. We
            // also monitor the IN_ATTRIB event, which gets triggered whenever the inode reference count changes. To
            // make sure this is a deletion, we also verify if the socket file is still present in the file-system.
            if (event.mask.contains(EventMask::ATTRIB)
                || event.mask.contains(EventMask::DELETE_SELF))
                && !Path::new(socket_path.as_str()).exists()
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
                    std::process::exit(1);
                }
            }
        }
    }

    debug!("Enclave process socket monitoring is done.");
}
