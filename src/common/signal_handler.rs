// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::warn;
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use std::os::unix::io::RawFd;
use std::thread;

use crate::common::ExitGracefully;

pub struct SignalHandler {
    sig_set: Option<SigSet>,
}

impl SignalHandler {
    pub fn new(signals: &[Signal]) -> Self {
        let mut sig_set = SigSet::empty();
        for signal in signals.iter() {
            sig_set.add(*signal);
        }

        SignalHandler {
            sig_set: Some(sig_set),
        }
    }

    pub fn new_with_defaults() -> Self {
        SignalHandler::new(&[SIGINT, SIGQUIT, SIGTERM, SIGHUP])
    }

    pub fn mask_all(self) -> Self {
        for set in self.sig_set.iter() {
            set.thread_block().ok_or_exit("Failed to block signal set.");
        }
        self
    }

    pub fn unmask_all(self) -> Self {
        for set in self.sig_set.iter() {
            set.thread_unblock()
                .ok_or_exit("Failed to unblock signal set.");
        }
        self
    }

    pub fn start_handler(&mut self, fd: RawFd, handler: fn(RawFd, Signal) -> bool) {
        if self.sig_set.is_none() {
            return;
        }

        let thread_sig_set = self.sig_set.take().unwrap();
        thread::spawn(move || {
            let mut stop = false;
            while !stop {
                stop = match thread_sig_set.wait() {
                    Ok(signal) => handler(fd, signal),
                    Err(e) => {
                        warn!("Error listening for signals: {}", e);
                        true
                    }
                };
            }
        });
    }
}
