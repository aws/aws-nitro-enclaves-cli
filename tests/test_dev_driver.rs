// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use std::fs::File;
use std::os::raw::c_ulong;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;

use nitro_cli::common::NitroCliResult;
use nitro_cli::enclave_proc::resource_manager::{KVM_CREATE_VM, KVM_SET_USER_MEMORY_REGION};

pub const NE_DEVICE_PATH: &str = "/dev/nitro_enclaves";

/// Class that covers communication with the NE driver.
pub struct NitroEnclavesDeviceDriver {
    // NE device file.
    file: File,
}

impl NitroEnclavesDeviceDriver {
    /// Open the file descriptor for communicating with the NE driver.
    pub fn new() -> NitroCliResult<Self> {
        Ok(NitroEnclavesDeviceDriver {
            file: File::open(NE_DEVICE_PATH)
                .map_err(|err| format!("Could not open {}: {}", NE_DEVICE_PATH, err))?,
        })
    }

    /// Allocate an enclave slot and return an enclave fd.
    pub fn create_enclave(&mut self) -> NitroCliResult<NitroEnclave> {
        let enc_type: c_ulong = 0;
        // This is safe because we are providing valid values.
        let enc_fd = unsafe { libc::ioctl(self.file.as_raw_fd(), KVM_CREATE_VM as _, &enc_type) };
        if enc_fd < 0 {
            return Err(format!("Could not create an enclave fd: {}.", enc_fd));
        }

        Ok(NitroEnclave::new(enc_fd).unwrap())
    }
}

/// Class for managing a Nitro Enclave provided by NitroEnclavesDeviceDriver.
pub struct NitroEnclave {
    enc_fd: RawFd,
}

impl NitroEnclave {
    pub fn new(enc_fd: RawFd) -> NitroCliResult<Self> {
        Ok(NitroEnclave { enc_fd })
    }

    fn release(&mut self) {
        // Close enclave descriptor.
        let rc = unsafe { libc::close(self.enc_fd) };
        if rc < 0 {
            panic!(format!("Could not close enclave descriptor: {}.", rc))
        }
    }
}

impl Drop for NitroEnclave {
    fn drop(&mut self) {
        if self.enc_fd < 0 {
            return;
        }
        self.release();
    }
}

// Class for checking the dmesg logs.
pub struct CheckDmesg {
    recorded_line: usize,
}

impl CheckDmesg {
    pub fn new() -> NitroCliResult<Self> {
        Ok(CheckDmesg { recorded_line: 0 })
    }

    /// Obtain the log lines from dmesg.
    fn get_dmesg_lines(&mut self) -> NitroCliResult<Vec<String>> {
        let dmesg = Command::new("dmesg")
            .output()
            .expect("Failed to execute dmesg process");
        let message = String::from_utf8(dmesg.stdout).unwrap();
        let lines: Vec<String> = message.split('\n').map(|s| s.to_string()).collect();
        Ok(lines)
    }

    /// Record the current number of lines from dmesg.
    pub fn record_current_line(&mut self) -> NitroCliResult<()> {
        self.recorded_line = self.get_dmesg_lines().unwrap().len();
        Ok(())
    }

    /// Verify if dmesg number of lines changed from the last recorded line.
    pub fn expect_no_changes(&mut self) -> NitroCliResult<()> {
        let checks = vec!["WARNING", "BUG", "ERROR", "FAILURE"];
        let lines = self.get_dmesg_lines().unwrap();

        for i in self.recorded_line..lines.len() {
            // TODO: Enable when logs are modified.
            // if !lines[i].contains("nitro_enclaves") {
            //     continue;
            // }

            let upper_line = lines[i].to_uppercase();
            for word in checks.iter() {
                if upper_line.contains(word) {
                    return Err(format!("Dmesg line: {} contains: {}", lines[i], word));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test_dev_driver {
    use super::*;

    #[test]
    pub fn test_ne_dev_open() {
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");

        // Create a Nitro Enclave without providing a valid type.
        let enc_fd = unsafe { libc::ioctl(driver.file.as_raw_fd(), KVM_CREATE_VM as _, 0) };
        assert!(enc_fd < 0, "Could create enclave with invalid type");

        // Test unexpected ioctl.
        let enc_fd =
            unsafe { libc::ioctl(driver.file.as_raw_fd(), KVM_SET_USER_MEMORY_REGION as _, 0) };
        assert!(enc_fd < 0, "Could create enclave with invalid ioctl");

        let mut slot_alloc_num: u64 = 1;
        if let Ok(value) = std::env::var("NE_SLOT_ALLOC_NUM") {
            if let Ok(value) = value.parse::<u64>() {
                slot_alloc_num = value;
            }
        }

        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        for _i in 0..slot_alloc_num {
            // Allocate Nitro Enclave slot and free it.
            let _enclave = driver.create_enclave().unwrap();
        }

        check_dmesg.expect_no_changes().unwrap();
    }
}
