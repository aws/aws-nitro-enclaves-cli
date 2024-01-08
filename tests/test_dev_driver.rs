// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use libc::{VMADDR_CID_HOST, VMADDR_CID_LOCAL};
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;

use driver_bindings::bindings::ne_enclave_start_info;
use nitro_cli::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use nitro_cli::enclave_proc::cpu_info::CpuInfo;
use nitro_cli::enclave_proc::resource_manager::{
    EnclaveStartInfo, MemoryRegion, NE_ADD_VCPU, NE_CREATE_VM, NE_SET_USER_MEMORY_REGION,
    NE_START_ENCLAVE,
};
use nitro_cli::enclave_proc::utils::MiB;

const ENCLAVE_MEM_2MB_CHUNKS: u64 = 48;
#[cfg(target_arch = "aarch64")]
const ENCLAVE_MEM_32MB_CHUNKS: u64 = 3;
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
            file: File::open(NE_DEVICE_PATH).map_err(|e| {
                NitroCliFailure::new()
                    .add_subaction(format!("Could not open {}: {}", NE_DEVICE_PATH, e))
                    .set_error_code(NitroCliErrorEnum::FileOperationFailure)
                    .set_file_and_line(file!(), line!())
                    .add_info(vec![NE_DEVICE_PATH, "Open"])
            })?,
        })
    }

    /// Allocate an enclave slot and return an enclave fd.
    pub fn create_enclave(&mut self) -> NitroCliResult<NitroEnclave> {
        let mut slot_uid: u64 = 0;
        // This is safe because we are providing valid values.
        let enc_fd =
            unsafe { libc::ioctl(self.file.as_raw_fd(), NE_CREATE_VM as _, &mut slot_uid) };

        if enc_fd < 0 {
            return Err(NitroCliFailure::new()
                .add_subaction(format!(
                    "Could not create an enclave descriptor: {}",
                    enc_fd
                ))
                .set_error_code(NitroCliErrorEnum::IoctlFailure)
                .set_file_and_line(file!(), line!()));
        }

        if slot_uid == 0 {
            return Err(NitroCliFailure::new()
                .add_subaction("Obtained invalid slot ID".to_string())
                .set_error_code(NitroCliErrorEnum::IoctlFailure)
                .set_file_and_line(file!(), line!()));
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
            panic!("Could not close enclave descriptor: {}.", rc)
        }
    }

    pub fn add_mem_region(&mut self, mem_region: EnclaveMemoryRegion) -> NitroCliResult<()> {
        let rc = unsafe { libc::ioctl(self.enc_fd, NE_SET_USER_MEMORY_REGION as _, &mem_region) };
        if rc < 0 {
            return Err(NitroCliFailure::new()
                .add_subaction(format!("Could not add memory region: {}", rc))
                .set_error_code(NitroCliErrorEnum::IoctlSetMemoryRegionFailure)
                .set_file_and_line(file!(), line!()));
        }

        Ok(())
    }

    pub fn add_cpu(&mut self, cpu_id: u32) -> NitroCliResult<()> {
        let mut actual_cpu_id: u32 = cpu_id;
        let rc = unsafe { libc::ioctl(self.enc_fd, NE_ADD_VCPU as _, &mut actual_cpu_id) };
        if rc < 0 {
            return Err(NitroCliFailure::new()
                .add_subaction(format!("Could not add vCPU: {}", rc))
                .set_error_code(NitroCliErrorEnum::IoctlAddVcpuFailure)
                .set_file_and_line(file!(), line!()));
        }

        Ok(())
    }

    pub fn start(&mut self, start_info: EnclaveStartInfo) -> NitroCliResult<()> {
        let rc = unsafe { libc::ioctl(self.enc_fd, NE_START_ENCLAVE as _, &start_info) };
        if rc < 0 {
            return Err(NitroCliFailure::new()
                .add_subaction(format!("Could not start enclave: {}", rc))
                .set_error_code(NitroCliErrorEnum::IoctlEnclaveStartFailure)
                .set_file_and_line(file!(), line!()));
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
        let checks = [
            "WARNING",
            "BUG",
            "ERROR",
            "FAILURE",
            "nitro_enclaves",
            // NE PCI device identifier
            "pci 0000:00:02.0",
        ];
        let lines = self.get_dmesg_lines().unwrap();

        for line in lines.iter().skip(self.recorded_line) {
            let upper_line = line.to_uppercase();
            for word in checks.iter() {
                if upper_line.contains(&word.to_uppercase()) {
                    return Err(NitroCliFailure::new()
                        .add_subaction(format!("Dmesg line: {} contains: {}", line, word))
                        .set_error_code(NitroCliErrorEnum::IoctlFailure)
                        .set_file_and_line(file!(), line!()));
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
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(0, 0, 2 * MiB));
        assert!(result.is_err());

        // Create a memory region using hugetlbfs.
        let region = MemoryRegion::new(libc::MAP_HUGE_2MB).unwrap();

        // Add unaligned memory region.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            0,
            region.mem_addr() + 1,
            region.mem_size(),
        ));
        assert!(result.is_err());

        // Add wrongly sized memory region of 1 MiB.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            0,
            region.mem_addr(),
            region.mem_size() / 2,
        ));
        assert!(result.is_err());

        // Add wrongly sized memory region of double the memory size.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            0,
            region.mem_addr(),
            region.mem_size() * 2,
        ));
        assert!(result.is_err());

        // Add wrongly sized memory region of max value multiple of 2 MiB.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            0,
            region.mem_addr(),
            u64::max_value() - (2 * 1024 * 1024) + 1,
        ));
        assert!(result.is_err());

        // Add wrong memory region with address out of range.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            0,
            region.mem_addr() + region.mem_size(),
            region.mem_size(),
        ));
        assert!(result.is_err());

        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Correctly add the memory region.
        let region = MemoryRegion::new(libc::MAP_HUGE_2MB).unwrap();
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(&region));
        assert!(result.is_ok());

        check_dmesg.expect_no_changes().unwrap();

        // Add the same memory region twice.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(&region));
        assert!(result.is_err());

        // Add a memory region with invalid flags.
        let region = MemoryRegion::new(libc::MAP_HUGE_2MB).unwrap();
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new(
            1024,
            region.mem_addr(),
            region.mem_size(),
        ));
        assert!(result.is_err());
    }

    #[test]
    pub fn test_enclave_vcpu() {
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");
        let mut enclave = driver.create_enclave().unwrap();
        let cpu_info = CpuInfo::new().expect("Failed to obtain CpuInfo.");

        // Add an invalid cpu id.
        let result = enclave.add_cpu(u32::max_value());
        assert!(result.is_err());

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
        assert!(result.is_ok());

        check_dmesg.expect_no_changes().unwrap();

        // Try inserting the cpu twice.
        let result = enclave.add_cpu(cpu_id);
        assert!(result.is_err());

        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Add all remaining cpus.
        for cpu in &candidates {
            let result = enclave.add_cpu(*cpu);
            assert!(result.is_ok());
        }

        check_dmesg.expect_no_changes().unwrap();

        // Clear the enclave.
        drop(enclave);

        let mut enclave = driver.create_enclave().unwrap();

        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Add an auto-chosen cpu from the pool.
        let result = enclave.add_cpu(0);
        assert!(result.is_ok());

        check_dmesg.expect_no_changes().unwrap();

        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Add all remaining auto-chosen cpus.
        for _i in 0..candidates.len() {
            let result = enclave.add_cpu(0);
            assert!(result.is_ok());
        }

        check_dmesg.expect_no_changes().unwrap();

        // Add one more cpu than the maximum available in the pool.
        let result = enclave.add_cpu(0);
        assert!(result.is_err());
    }

    #[test]
    pub fn test_enclave_start() {
        let mut mem_regions = Vec::new();
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");
        let mut enclave = driver.create_enclave().unwrap();

        // Start enclave without resources.
        let result = enclave.start(EnclaveStartInfo::default());
        assert!(result.is_err());

        // Allocate memory for the enclave.
        #[cfg(target_arch = "x86_64")]
        for _i in 0..ENCLAVE_MEM_2MB_CHUNKS {
            mem_regions.push(MemoryRegion::new(libc::MAP_HUGE_2MB).unwrap());
        }

        #[cfg(target_arch = "aarch64")]
        {
            let mut mem_2mb_chunks = ENCLAVE_MEM_2MB_CHUNKS;

            for _i in 0..ENCLAVE_MEM_32MB_CHUNKS {
                let region = MemoryRegion::new(libc::MAP_HUGE_32MB);

                if region.is_err() {
                    break;
                }

                mem_regions.push(region.unwrap());

                mem_2mb_chunks = mem_2mb_chunks - (32 / 2);
            }

            for _i in 0..mem_2mb_chunks {
                mem_regions.push(MemoryRegion::new(libc::MAP_HUGE_2MB).unwrap());
            }
        }

        // Add memory to the enclave.
        for region in &mut mem_regions {
            let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(region));
            assert!(result.is_ok());
        }

        // Start the enclave without cpus.
        let result = enclave.start(EnclaveStartInfo::default());
        assert!(result.is_err());

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
            assert!(result.is_ok());
        }

        // Start enclave without memory.
        let result = enclave.start(EnclaveStartInfo::default());
        assert!(result.is_err());

        drop(enclave);

        let mut enclave = driver.create_enclave().unwrap();

        // Add memory to the enclave.
        for region in &mut mem_regions {
            let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(region));
            assert!(result.is_ok());
        }

        // Add the first available cpu.
        let result = enclave.add_cpu(candidates[0]);
        assert!(result.is_ok());

        // Start without cpu pair.
        #[cfg(target_arch = "aarch64")]
        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        #[cfg(target_arch = "aarch64")]
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        let result = enclave.start(EnclaveStartInfo::default());
        #[cfg(target_arch = "x86_64")]
        assert!(result.is_err());
        #[cfg(target_arch = "aarch64")]
        assert_eq!(result.is_err(), false);

        #[cfg(target_arch = "aarch64")]
        check_dmesg.expect_no_changes().unwrap();

        #[cfg(target_arch = "aarch64")]
        drop(enclave);

        #[cfg(target_arch = "aarch64")]
        let mut enclave = driver.create_enclave().unwrap();

        // Add memory to the enclave.
        #[cfg(target_arch = "aarch64")]
        for region in &mut mem_regions {
            let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(region));
            assert_eq!(result.is_err(), false);
        }

        // Add the first available cpu.
        #[cfg(target_arch = "aarch64")]
        let result = enclave.add_cpu(candidates[0]);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(result.is_err(), false);

        // Add the first cpu pair.
        let result = enclave.add_cpu(candidates[1]);
        assert!(result.is_ok());

        // Start with an invalid flag.
        let enclave_start_info = ne_enclave_start_info {
            flags: 1234,
            ..Default::default()
        };
        let result = enclave.start(enclave_start_info);
        assert!(result.is_err());

        // Start with an invalid CID.
        let mut enclave_start_info = ne_enclave_start_info {
            enclave_cid: VMADDR_CID_LOCAL as u64,
            ..Default::default()
        };
        let result = enclave.start(enclave_start_info);
        assert!(result.is_err());

        enclave_start_info.enclave_cid = VMADDR_CID_HOST as u64;
        let result = enclave.start(enclave_start_info);
        assert!(result.is_err());

        enclave_start_info.enclave_cid = u32::max_value() as u64;
        let result = enclave.start(enclave_start_info);
        assert!(result.is_err());

        enclave_start_info.enclave_cid = u32::max_value() as u64 + 1234_u64;
        let result = enclave.start(enclave_start_info);
        assert!(result.is_err());

        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Start the enclave.
        let result = enclave.start(EnclaveStartInfo::default());
        assert!(result.is_ok());

        check_dmesg.expect_no_changes().unwrap();

        // Try starting an already running enclave.
        let result = enclave.start(EnclaveStartInfo::default());
        assert!(result.is_err());

        // Try adding an already added memory region
        // after the enclave start.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(&mem_regions[0]));
        assert!(result.is_err());

        // Try adding a new memory region after the enclave start.
        let result = enclave.add_mem_region(EnclaveMemoryRegion::new_from(
            &MemoryRegion::new(libc::MAP_HUGE_2MB).unwrap(),
        ));
        assert!(result.is_err());

        // Try adding an already added vcpu after enclave start.
        let result = enclave.add_cpu(candidates[0]);
        assert!(result.is_err());

        // Try adding a new vcpu after enclave start.
        if candidates.len() >= 3 {
            let result = enclave.add_cpu(candidates[2]);
            assert!(result.is_err());
        }
    }

    #[test]
    pub fn test_enclave_multiple_start() {
        let mut mem_regions = Vec::new();
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");

        // Allocate memory for the enclave.
        #[cfg(target_arch = "x86_64")]
        for _i in 0..ENCLAVE_MEM_2MB_CHUNKS {
            mem_regions.push(MemoryRegion::new(libc::MAP_HUGE_2MB).unwrap());
        }

        #[cfg(target_arch = "aarch64")]
        {
            let mut mem_2mb_chunks = ENCLAVE_MEM_2MB_CHUNKS;

            for _i in 0..ENCLAVE_MEM_32MB_CHUNKS {
                let region = MemoryRegion::new(libc::MAP_HUGE_32MB);

                if region.is_err() {
                    break;
                }

                mem_regions.push(region.unwrap());

                mem_2mb_chunks = mem_2mb_chunks - (32 / 2);
            }

            for _i in 0..mem_2mb_chunks {
                mem_regions.push(MemoryRegion::new(libc::MAP_HUGE_2MB).unwrap());
            }
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
                assert!(result.is_ok());
            }

            // Add cpus to the enclave.
            for cpu in &candidates {
                let result = enclave.add_cpu(*cpu);
                assert!(result.is_ok());
            }

            // Start and stop the enclave
            let result = enclave.start(EnclaveStartInfo::default());
            assert!(result.is_ok());
        }
    }
}
