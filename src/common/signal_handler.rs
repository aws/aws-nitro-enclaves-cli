// Copyright 2020-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use log::warn;
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use std::os::unix::io::RawFd;
use std::thread;

use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::new_nitro_cli_failure;

/// The custom handler of POSIX signals.
pub struct SignalHandler {
    sig_set: Option<SigSet>,
}

impl SignalHandler {
    /// Create a new `SignalHandler` instance from the given list of signals.
    pub fn new(signals: &[Signal]) -> Self {
        let mut sig_set = SigSet::empty();
        for signal in signals.iter() {
            sig_set.add(*signal);
        }

        SignalHandler {
            sig_set: Some(sig_set),
        }
    }

    /// Create a new `SignalHandler` instance from a default list of signals.
    pub fn new_with_defaults() -> Self {
        SignalHandler::new(&[SIGINT, SIGQUIT, SIGTERM, SIGHUP])
    }

    /// Mask (block) all signals covered by the handler.
    pub fn mask_all(self) -> NitroCliResult<Self> {
        if let Some(set) = self.sig_set {
            set.thread_block().map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Masking signals covered by handler failed: {:?}", e),
                    NitroCliErrorEnum::SignalMaskingError
                )
            })?;
        }

        Ok(self)
    }

    /// Unmask (unblock) all signals covered by the handler.
    pub fn unmask_all(self) -> NitroCliResult<Self> {
        if let Some(set) = self.sig_set {
            set.thread_unblock().map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Unmasking signals covered by handler failed: {:?}", e),
                    NitroCliErrorEnum::SignalUnmaskingError
                )
            })?;
        }

        Ok(self)
    }

    /// Start listening for events on a dedicated thread and handle them using the provided function.
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
