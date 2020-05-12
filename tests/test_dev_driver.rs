// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use std::fs::File;
use std::os::raw::c_ulong;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;

use nitro_cli::common::NitroCliResult;
use nitro_cli::enclave_proc::cpu_info::CpuInfos;
use nitro_cli::enclave_proc::resource_manager::{
    MemoryRegion, KVM_CREATE_VCPU, KVM_CREATE_VM, KVM_SET_USER_MEMORY_REGION,
};

use kvm_bindings::kvm_userspace_memory_region;

#[allow(non_upper_case_globals)]
pub const MiB: u64 = 1024 * 1024;
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

/// Class for managing a Nitro Enclave Vcpu file descriptor.
pub struct EnclaveVcpu {
    vcpu_fd: RawFd,
}

impl EnclaveVcpu {
    pub fn new(vcpu_fd: RawFd) -> NitroCliResult<Self> {
        Ok(EnclaveVcpu { vcpu_fd })
    }

    fn release(&mut self) {
        // Close enclave vcpu descriptor.
        let rc = unsafe { libc::close(self.vcpu_fd) };
        if rc < 0 {
            panic!(format!("Could not close vcpu descriptor: {}.", rc))
        }
    }
}

impl Drop for EnclaveVcpu {
    fn drop(&mut self) {
        if self.vcpu_fd < 0 {
            return;
        }
        self.release();
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

    pub fn add_mem_region(
        &mut self,
        kvm_mem_region: kvm_userspace_memory_region,
    ) -> NitroCliResult<()> {
        let rc = unsafe {
            libc::ioctl(
                self.enc_fd,
                KVM_SET_USER_MEMORY_REGION as _,
                &kvm_mem_region,
            )
        };
        if rc < 0 {
            return Err(format!("Could not add memory region: {}.", rc));
        }

        Ok(())
    }

    pub fn add_cpu(&mut self, cpu_id: u32) -> NitroCliResult<EnclaveVcpu> {
        let vcpu_fd = unsafe { libc::ioctl(self.enc_fd, KVM_CREATE_VCPU as _, &cpu_id) };
        if vcpu_fd < 0 {
            return Err(format!("Could not add vcpu: {}.", vcpu_fd));
        }

        Ok(EnclaveVcpu::new(vcpu_fd).unwrap())
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

    #[test]
    pub fn test_enclave_memory() {
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");
        let mut enclave = driver.create_enclave().unwrap();

        // Add invalid memory region.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            userspace_addr: 0,
            guest_phys_addr: 0,
            memory_size: 2 * MiB as u64,
        });
        assert_eq!(result.is_err(), true);

        // Create a memory region using hugetlbfs.
        let mut region = MemoryRegion::new(2 * MiB).unwrap();

        // Add unaligned memory region.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            userspace_addr: region.mem_addr() + 1,
            guest_phys_addr: 0,
            memory_size: region.mem_size(),
        });
        assert_eq!(result.is_err(), true);

        // Add wrongly sized memory regions of 1 MiB.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            userspace_addr: region.mem_addr(),
            guest_phys_addr: 0,
            memory_size: region.mem_size() / 2,
        });
        assert_eq!(result.is_err(), true);

        // TODO: Enable the following test with Nitro Enclaves Kernel Driver v2.
        // let result = enclave.add_mem_region(kvm_userspace_memory_region {
        //     slot: 0,
        //     flags: 0,
        //     userspace_addr: region.mem_addr(),
        //     guest_phys_addr: 0,
        //     memory_size: region.mem_size() * 2,
        // });
        // assert_eq!(result.is_err(), true);

        let mut check_dmesg = CheckDmesg::new().expect("Failed to obtain dmesg object");
        check_dmesg
            .record_current_line()
            .expect("Failed to record current line");

        // Correctly add the memory region.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            userspace_addr: region.mem_addr(),
            guest_phys_addr: 0,
            memory_size: region.mem_size(),
        });
        assert_eq!(result.is_err(), false);

        check_dmesg.expect_no_changes().unwrap();

        // Add the same memory region twice.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            userspace_addr: region.mem_addr(),
            guest_phys_addr: 0,
            memory_size: region.mem_size(),
        });
        assert_eq!(result.is_err(), true);

        let mut region = MemoryRegion::new(2 * MiB).unwrap();
        // Add a memory region with invalid slot.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 1024,
            flags: 0,
            userspace_addr: region.mem_addr(),
            guest_phys_addr: 0,
            memory_size: region.mem_size(),
        });
        // Kernel Driver does not use the slot.
        assert_eq!(result.is_err(), false);

        let mut region = MemoryRegion::new(2 * MiB).unwrap();
        // Add a memory region with invalid slot.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 1024,
            userspace_addr: region.mem_addr(),
            guest_phys_addr: 0,
            memory_size: region.mem_size(),
        });
        // Kernel Driver does not use the flags.
        assert_eq!(result.is_err(), false);

        let mut region = MemoryRegion::new(2 * MiB).unwrap();
        // Add a memory region with guest_phys_addr.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            userspace_addr: region.mem_addr(),
            guest_phys_addr: 1024,
            memory_size: region.mem_size(),
        });
        // Kernel Driver does not use the guest_phys_addr.
        assert_eq!(result.is_err(), false);

        let mut region = MemoryRegion::new(2 * MiB).unwrap();
        // Add a memory region with guest_phys_addr that does not overflow.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            userspace_addr: region.mem_addr(),
            guest_phys_addr: u64::max_value() - 2 * MiB,
            memory_size: region.mem_size(),
        });
        // Kernel Driver checks if the guest_phys_addr + memory_size overflows.
        assert_eq!(result.is_err(), false);

        let mut region = MemoryRegion::new(2 * MiB).unwrap();
        // Add a memory region with guest_phys_addr that does overflow.
        let result = enclave.add_mem_region(kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            userspace_addr: region.mem_addr(),
            guest_phys_addr: u64::max_value(),
            memory_size: region.mem_size(),
        });
        assert_eq!(result.is_err(), true);
    }

    #[test]
    pub fn test_enclave_vcpu() {
        let mut driver = NitroEnclavesDeviceDriver::new().expect("Failed to open NE device");
        let mut enclave = driver.create_enclave().unwrap();
        let cpu_infos = CpuInfos::new().expect("Failed to obtain CpuInfos");

        // Cpu id 0 is reserved for the EC2 Instance.
        let result = enclave.add_cpu(0);
        assert_eq!(result.is_err(), true);

        // For hyper-threading the sibling of cpu id 0 is reserved.
        if cpu_infos.hyper_threading {
            let sibling = cpu_infos.core_ids.len() / 2;
            let result = enclave.add_cpu(sibling as u32);
            assert_eq!(result.is_err(), true);
        }

        // Add an invalid cpu id.
        let result = enclave.add_cpu(u32::max_value());
        assert_eq!(result.is_err(), true);

        let mut candidates = cpu_infos.get_cpu_candidates();
        // Instance does not have the appropriate number of cpus.
        if candidates.len() == 0 {
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
}
