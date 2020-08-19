// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;

use nitro_cli::common::NitroCliResult;
use nitro_cli::enclave_proc::cpu_info::CpuInfo;
use nitro_cli::enclave_proc::resource_manager::{
    EnclaveStartInfo, MemoryRegion, NE_ADD_VCPU, NE_CREATE_VM, NE_SET_USER_MEMORY_REGION,
    NE_START_ENCLAVE,
};
use nitro_cli::enclave_proc::utils::MiB;

const ENCLAVE_MEM_CHUNKS: u64 = 40;
pub const NE_DEVICE_PATH: &str = "/dev/nitro_enclaves";

/// This is similar to `MemoryRegion`, except it doesn't implement `Drop`.
#[allow(dead_code)]
pub struct EnclaveMemoryRegion {
    /// Flags to determine the usage for the memory region.
    flags: u64,
    /// The region's size in bytes.
    mem_size: u64,
    /// The region's virtual address.
    mem_addr: u64,
}

impl EnclaveMemoryRegion {
    fn new(flags: u64, mem_addr: u64, mem_size: u64) -> Self {
        EnclaveMemoryRegion {
            flags,
            mem_size,
            mem_addr,
        }
    }

    fn new_from(region: &MemoryRegion) -> Self {
        EnclaveMemoryRegion {
            flags: 0,
            mem_size: region.mem_size(),
            mem_addr: region.mem_addr(),
        }
    }
}

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
        let mut slot_uid: u64 = 0;
        // This is safe because we are providing valid values.
        let enc_fd =
            unsafe { libc::ioctl(self.file.as_raw_fd(), NE_CREATE_VM as _, &mut slot_uid) };

        if enc_fd < 0 {
            return Err(format!("Could not create an enclave fd: {}.", enc_fd));
        }

        if slot_uid == 0 {
            return Err("Obtained invalid slot ID.".to_string());
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

    pub fn add_mem_region(&mut self, mem_region: EnclaveMemoryRegion) -> NitroCliResult<()> {
        let rc = unsafe { libc::ioctl(self.enc_fd, NE_SET_USER_MEMORY_REGION as _, &mem_region) };
        if rc < 0 {
            return Err(format!("Could not add memory region: {}.", rc));
        }

        Ok(())
    }

    pub fn add_cpu(&mut self, cpu_id: u32) -> NitroCliResult<()> {
        let mut actual_cpu_id: u32 = cpu_id;
        let rc = unsafe { libc::ioctl(self.enc_fd, NE_ADD_VCPU as _, &mut actual_cpu_id) };
        if rc < 0 {
            return Err(format!("Could not add vcpu: {}.", rc));
        }

        Ok(())
    }

    pub fn start(&mut self, start_info: EnclaveStartInfo) -> NitroCliResult<()> {
        let rc = unsafe { libc::ioctl(self.enc_fd, NE_START_ENCLAVE as _, &start_info) };
        if rc < 0 {
            return Err(format!("Could not start enclave: {}.", rc));
        }

        Ok(())
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
        let checks = vec![
            "WARNING",
            "BUG",
            "ERROR",
            "FAILURE",
            "nitro_enclaves",
            // NE PCI device identifier
            "pci 0000:00:02.0",
        ];
        let lines = self.get_dmesg_lines().unwrap();

        for i in self.recorded_line..lines.len() {
            let upper_line = lines[i].to_uppercase();
            for word in checks.iter() {
                if upper_line.contains(&word.to_uppercase()) {
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
        let enc_fd = unsafe { libc::ioctl(driver.file.as_raw_fd(), NE_CREATE_VM as _, 0) };
        assert!(
            enc_fd < 0,
            "Should not have been able to create enclave descriptor"
        );

        // Test unexpected ioctl.
        let enc_fd =
            unsafe { libc::ioctl(driver.file.as_raw_fd(), NE_SET_USER_MEMORY_REGION as _, 0) };
        assert!(
            enc_fd < 0,
            "Should not have been able to create enclave with invalid ioctl"
        );

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

    #[test]
    pub fn test_enclave_memory() {
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");
        let mut enclave = driver.create_enclave().unwrap();

        // Add invalid memory region.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(0, 0, 2 * MiB as u64));
        assert_eq!(result.is_err(), true);

        // Create a memory region using hugetlbfs.
        let region = MemoryRegion::new(2 * MiB).unwrap();

        // Add unaligned memory region.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            0,
            region.mem_addr() + 1,
            region.mem_size(),
        ));
        assert_eq!(result.is_err(), true);

        // Add wrongly sized memory region of 1 MiB.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            0,
            region.mem_addr(),
            region.mem_size() / 2,
        ));
        assert_eq!(result.is_err(), true);

        // Add wrongly sized memory region of double the memory size.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            0,
            region.mem_addr(),
            region.mem_size() * 2,
        ));
        assert_eq!(result.is_err(), true);

        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Correctly add the memory region.
        let region = MemoryRegion::new(2 * MiB).unwrap();
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(&region));
        assert_eq!(result.is_err(), false);

        check_dmesg.expect_no_changes().unwrap();

        // Add the same memory region twice.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(&region));
        assert_eq!(result.is_err(), true);

        // Add a memory region with invalid flags.
        let region = MemoryRegion::new(2 * MiB).unwrap();
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            1024,
            region.mem_addr(),
            region.mem_size(),
        ));
        assert_eq!(result.is_err(), true);

        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Correctly add a memory region of 10 MiB backed by 2 MiB huge pages.
        let region = MemoryRegion::new(10 * MiB).unwrap();
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(&region));
        assert_eq!(result.is_err(), false);

        check_dmesg.expect_no_changes().unwrap();
    }

    #[test]
    pub fn test_enclave_vcpu() {
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");
        let mut enclave = driver.create_enclave().unwrap();
        let cpu_info = CpuInfo::new().expect("Failed to obtain CpuInfo.");

        // Add an invalid cpu id.
        let result = enclave.add_cpu(u32::max_value());
        assert_eq!(result.is_err(), true);

        let mut candidates = cpu_info.get_cpu_candidates();
        // Instance does not have the appropriate number of cpus.
        if candidates.is_empty() {
            return;
        }

        let cpu_id = candidates.pop().unwrap();

        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Insert the first valid cpu id.
        let result = enclave.add_cpu(cpu_id);
        assert_eq!(result.is_err(), false);

        check_dmesg.expect_no_changes().unwrap();

        // Try inserting the cpu twice.
        let result = enclave.add_cpu(cpu_id);
        assert_eq!(result.is_err(), true);

        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Add all remaining cpus.
        for cpu in &candidates {
            let result = enclave.add_cpu(*cpu);
            assert_eq!(result.is_err(), false);
        }

        check_dmesg.expect_no_changes().unwrap();
    }

    #[test]
    pub fn test_enclave_start() {
        let mut mem_regions = Vec::new();
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");
        let mut enclave = driver.create_enclave().unwrap();

        // Start enclave without resources.
        let result = enclave.start(EnclaveStartInfo::new_empty());
        assert_eq!(result.is_err(), true);

        // Allocate memory for the enclave.
        for _i in 0..ENCLAVE_MEM_CHUNKS {
            mem_regions.push(MemoryRegion::new(2 * MiB).unwrap());
        }

        // Add memory to the enclave.
        for region in &mut mem_regions {
            let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(region));
            assert_eq!(result.is_err(), false);
        }

        // Start the enclave without cpus.
        let result = enclave.start(EnclaveStartInfo::new_empty());
        assert_eq!(result.is_err(), true);

        let cpu_info = CpuInfo::new().expect("Failed to obtain CpuInfo.");
        let candidates = cpu_info.get_cpu_candidates();
        // Instance does not have the appropriate number of cpus.
        if candidates.len() < 2 {
            return;
        }

        // Clear the enclave.
        drop(enclave);

        let mut enclave = driver.create_enclave().unwrap();

        for cpu in &candidates {
            let result = enclave.add_cpu(*cpu);
            assert_eq!(result.is_err(), false);
        }

        // Start enclave without memory.
        let result = enclave.start(EnclaveStartInfo::new_empty());
        assert_eq!(result.is_err(), true);

        drop(enclave);

        let mut enclave = driver.create_enclave().unwrap();

        // Add memory to the enclave.
        for region in &mut mem_regions {
            let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(region));
            assert_eq!(result.is_err(), false);
        }

        // Add the first available cpu.
        let result = enclave.add_cpu(candidates[0]);
        assert_eq!(result.is_err(), false);

        // Start without cpu pair.
        let result = enclave.start(EnclaveStartInfo::new_empty());
        assert_eq!(result.is_err(), true);

        // Add the first cpu pair.
        let result = enclave.add_cpu(candidates[1]);
        assert_eq!(result.is_err(), false);

        // Start with an invalid flag.
        let mut enclave_start_info = EnclaveStartInfo::new_empty();
        enclave_start_info.flags = 1234;
        let result = enclave.start(enclave_start_info);
        assert_eq!(result.is_err(), true);

        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Start the enclave.
        let result = enclave.start(EnclaveStartInfo::new_empty());
        assert_eq!(result.is_err(), false);

        check_dmesg.expect_no_changes().unwrap();

        // Try starting an already running enclave.
        let result = enclave.start(EnclaveStartInfo::new_empty());
        assert_eq!(result.is_err(), true);

        // Try adding an already added memory region
        // after the enclave start.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(&mem_regions[0]));
        assert_eq!(result.is_err(), true);

        // Try adding a new memory region after the enclave start.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(
            &MemoryRegion::new(2 * MiB).unwrap(),
        ));
        assert_eq!(result.is_err(), true);

        // Try adding an already added vcpu after enclave start.
        let result = enclave.add_cpu(candidates[0]);
        assert_eq!(result.is_err(), true);

        // Try adding a new vcpu after enclave start.
        if candidates.len() >= 3 {
            let result = enclave.add_cpu(candidates[2]);
            assert_eq!(result.is_err(), true);
        }
    }

    #[test]
    pub fn test_enclave_multiple_start() {
        let mut mem_regions = Vec::new();
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");

        // Allocate memory for the enclave.
        for _i in 0..ENCLAVE_MEM_CHUNKS {
            mem_regions.push(MemoryRegion::new(2 * MiB).unwrap());
        }

        let cpu_info = CpuInfo::new().expect("Failed to obtain CpuInfo.");
        let candidates = cpu_info.get_cpu_candidates();
        // Instance does not have the appropriate number of cpus.
        if candidates.len() < 2 {
            return;
        }

        let mut start_num: u64 = 1;
        if let Ok(value) = std::env::var("NE_MULTIPLE_START_NUM") {
            if let Ok(value) = value.parse::<u64>() {
                start_num = value;
            }
        }

        for _i in 0..start_num {
            let mut enclave = driver.create_enclave().unwrap();

            // Add memory to the enclave.
            for region in &mut mem_regions {
                let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(region));
                assert_eq!(result.is_err(), false);
            }

            // Add cpus to the enclave.
            for cpu in &candidates {
                let result = enclave.add_cpu(*cpu);
                assert_eq!(result.is_err(), false);
            }

            // Start and stop the enclave
            let result = enclave.start(EnclaveStartInfo::new_empty());
            assert_eq!(result.is_err(), false);
        }
    }
}
