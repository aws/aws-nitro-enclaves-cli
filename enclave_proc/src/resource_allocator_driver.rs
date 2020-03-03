// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use crate::NitroCliResult;
use nix;
use nix::ioctl_read;
use nix::ioctl_readwrite;
use std::fs::File;
use std::mem::size_of_val;
use std::os::unix::io::AsRawFd;

pub const RESOURCE_ALLOCATOR_PATH: &str = "/dev/nitro_cli_resource_allocator";
/// Structure to communicate with the resource allocator driver.
///
/// The definition is duplicated from nitro_cli_resource_allocator.h
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct nitro_cli_slot_mem_region {
    pub slot_uid: u64,
    pub mem_gpa: u64,
    pub mem_size: u64,
}

/// Structure for storing the mapping between a cpu and a slot
///
/// The definition is duplicated from nitro_cli_resource_allocator.h
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct nitro_cli_slot_cpu_mapping {
    //Slot UID to which this cpu should be added
    pub slot_uid: u64,
    // Bit mask of cpus to be allocated to the slot, it returns the cpus already allocated
    // to the slot.
    pub cpu_mask: [u64; 4],
}

ioctl_readwrite!(
    nitro_cli_slot_alloc_memory,
    b'B',
    0x4,
    nitro_cli_slot_mem_region
);
ioctl_readwrite!(
    nitro_cli_slot_set_cpu_mapping,
    b'B',
    0x5,
    nitro_cli_slot_cpu_mapping
);
ioctl_read!(nitro_cli_slot_free_resources, b'B', 0x6, u64);

/// Helper class to comunicate with /dev/nitro_cli_resource_allocator
pub struct ResourceAllocatorDriver {
    file: File,
}

impl ResourceAllocatorDriver {
    pub fn new() -> NitroCliResult<Self> {
        Ok(ResourceAllocatorDriver {
            file: File::open(RESOURCE_ALLOCATOR_PATH)
                .map_err(|err| format!("Could not open {}: {}", RESOURCE_ALLOCATOR_PATH, err))?,
        })
    }

    pub fn alloc(&self, slot_uid: u64, mem_size: u64) -> NitroCliResult<nitro_cli_slot_mem_region> {
        let mem_region = nitro_cli_slot_mem_region {
            slot_uid,
            mem_size,
            mem_gpa: 0,
        };
        let rc = unsafe {
            nitro_cli_slot_alloc_memory(
                self.file.as_raw_fd(),
                &mem_region as *const nitro_cli_slot_mem_region as *mut nitro_cli_slot_mem_region,
            )
            .map_err(|err| format!("Alloc of {} bytes memory ioctl failed: {}", mem_size, err))?
        };

        if rc != 0 {
            return Err(format!("Alloc memory ioctl failed: {}", rc));
        }

        Ok(mem_region)
    }

    // Sets a mapping between slot_uid and cpu_id inside the driver.
    //
    // When cpu_id is None it just queries the current cpu list.
    pub fn cpu_mapping(
        &self,
        slot_uid: u64,
        cpu_id: Option<u32>,
    ) -> NitroCliResult<nitro_cli_slot_cpu_mapping> {
        let cpu_mask = [0; 4];
        let mut cpu_mapping = nitro_cli_slot_cpu_mapping { slot_uid, cpu_mask };
        if let Some(cpu_id) = cpu_id {
            if size_of_val(&cpu_mapping.cpu_mask) * 8 <= cpu_id as usize {
                return Err("CPU id out of bound".to_string());
            }
            cpu_mapping.cpu_mask[cpu_id as usize / 64] = 1 << (cpu_id % 64);
        }
        let rc = unsafe {
            nitro_cli_slot_set_cpu_mapping(
                self.file.as_raw_fd(),
                &cpu_mapping as *const nitro_cli_slot_cpu_mapping
                    as *mut nitro_cli_slot_cpu_mapping,
            )
            .map_err(|err| {
                format!(
                    "CPU mapping failed slot_uid: {}, cpu_mask: {:?}, err: {}",
                    slot_uid, cpu_mask, err
                )
            })?
        };

        if rc != 0 {
            return Err(format!("Set cpu mapping ioctl failed: {}", rc));
        }

        Ok(cpu_mapping)
    }

    pub fn free(&self, slot_uid: u64) -> NitroCliResult<()> {
        let rc = unsafe {
            nitro_cli_slot_free_resources(
                self.file.as_raw_fd(),
                &slot_uid as *const u64 as *mut u64,
            )
            .map_err(|err| format!("Free resources ioctl failed: {}", err))?
        };

        if rc != 0 {
            return Err(format!("Free resources ioctl failed: {}", rc));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::resource_allocator_driver::ResourceAllocatorDriver;

    #[test]
    fn test_cpu_mapping() {
        let resource_allocator = ResourceAllocatorDriver::new().expect("Could not create driver");
        let mapping = resource_allocator
            .cpu_mapping(1, Some(0))
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [1, 0, 0, 0]);
        let mapping = resource_allocator
            .cpu_mapping(1, None)
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [1, 0, 0, 0]);

        let mapping = resource_allocator
            .cpu_mapping(2, Some(2))
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [1 << 2, 0, 0, 0]);

        let mapping = resource_allocator
            .cpu_mapping(2, Some(3))
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [1 << 2 | 1 << 3, 0, 0, 0]);

        let mapping = resource_allocator
            .cpu_mapping(2, None)
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [1 << 2 | 1 << 3, 0, 0, 0]);

        resource_allocator.free(1).unwrap();
        let mapping = resource_allocator
            .cpu_mapping(1, None)
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [0, 0, 0, 0]);

        let mapping = resource_allocator
            .cpu_mapping(2, None)
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [1 << 2 | 1 << 3, 0, 0, 0]);

        resource_allocator.free(2).unwrap();
        let mapping = resource_allocator
            .cpu_mapping(2, None)
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [0, 0, 0, 0]);
    }

    #[test]
    fn test_cpu_mapping_edge() {
        let resource_allocator = ResourceAllocatorDriver::new().expect("Could not create driver");
        let _mapping = resource_allocator
            .cpu_mapping(1, Some(0))
            .expect("Could could not create mapping");
        let _mapping = resource_allocator
            .cpu_mapping(1, Some(64))
            .expect("Could could not create mapping");
        let _mapping = resource_allocator
            .cpu_mapping(1, Some(129))
            .expect("Could could not create mapping");
        let mapping = resource_allocator
            .cpu_mapping(1, Some(255))
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [1, 1, 2, 1 << 63]);

        let mapping = resource_allocator
            .cpu_mapping(1, None)
            .expect("Could could not create mapping");
        assert_eq!(mapping.cpu_mask, [1, 1, 2, 1 << 63]);

        let mapping = resource_allocator.cpu_mapping(1, Some(333));
        assert_eq!(mapping.is_err(), true);
        resource_allocator.free(1).unwrap();
    }
}
