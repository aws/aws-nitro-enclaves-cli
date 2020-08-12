// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use nitro_cli_poweruser::cli_dev::*;
use nitro_cli_poweruser::cpu_info::CpuInfos;
use nitro_cli_poweruser::json_output::{get_enclave_describe_info, EnclaveDescribeInfo};
use nitro_cli_poweruser::resource_allocator_driver::ResourceAllocatorDriver;
use nitro_cli_poweruser::NitroCliResult;

#[allow(non_upper_case_globals)]
const MiB: u64 = 1024 * 1024;
const MEM_CHUNK: u64 = 4;
const NUM_CPUS: u64 = 2;
const DEFAULT_ENCLAVE_CID: u64 = 10000;
const INVALID_CID: u64 = 1;

/// Struct that stores all the information needed to allocate memory
/// for an enclave and send PCI commands to it
struct NitroEnclaveAllocator {
    pub slot_uid: u64,
    pub default_mem: u64,
    pub resource_allocator: ResourceAllocatorDriver,
    pub cli_dev: CliDev,
}

impl NitroEnclaveAllocator {
    /// Function that creates a new NitroEnclaveAllocator
    pub fn new() -> NitroCliResult<Self> {
        let mut result = NitroEnclaveAllocator {
            slot_uid: 0,
            default_mem: 1024,
            resource_allocator: ResourceAllocatorDriver::new()?,
            cli_dev: CliDev::new()?,
        };
        if !result.cli_dev.enable()? {
            return Err(String::from("Failed to enable Cli Device."));
        }
        result.set_default_mem()?;

        Ok(result)
    }

    /// Function that allocates the specified memory in MiB to the NitroEnclaveAllocator's enclave
    pub fn alloc_and_add_mem(&mut self, mem: u64) -> NitroCliResult<()> {
        for _i in 0..mem / MEM_CHUNK {
            let reply = self
                .resource_allocator
                .alloc(self.slot_uid, MEM_CHUNK * MiB)?;
            let cmd = NitroEnclavesSlotAddMem::new(reply.slot_uid, reply.mem_gpa, reply.mem_size);
            let error = cmd.submit(&mut self.cli_dev);
            if error.is_err() {
                return Err(String::from("Memory allocation failed!"));
            }
        }

        Ok(())
    }

    /// Function that describes the state of all the enclaves running on the instance
    pub fn describe_enclaves(&mut self) -> NitroCliResult<Vec<EnclaveDescribeInfo>> {
        let slot_count = NitroEnclavesSlotCount::new();
        let reply = slot_count.submit(&mut self.cli_dev)?;

        let num_slots = reply.slot_count;

        let mut current_slot = 0;
        let mut infos: Vec<EnclaveDescribeInfo> = Vec::new();

        for _ in 0..num_slots {
            let next_slot = NitroEnclavesNextSlot::new(current_slot);
            let reply = next_slot.submit(&mut self.cli_dev)?;

            let slot_info = NitroEnclavesSlotInfo::new(reply.slot_uid);
            let reply = slot_info.submit(&mut self.cli_dev)?;
            let info = get_enclave_describe_info(reply)?;
            infos.push(info);

            current_slot = reply.slot_uid + 1;
        }

        Ok(infos)
    }

    /// Function that reads the environment variable 'NE_DEFAULT_MEM' and sets
    /// it's content or 1024, if variable not set, to the default memory of the test
    fn set_default_mem(&mut self) -> NitroCliResult<()> {
        self.default_mem = std::env::var("NE_DEFAULT_MEM")
            .map(|value| value.parse::<u64>())
            .unwrap_or(Ok(1024))
            .expect("Setting default memory failed");
        Ok(())
    }

    /// Function that creates and starts an enclave with the specified memory and cpu number
    /// Stores the slot uid associated to the started enclave
    pub fn start_enclave(&mut self, mem: u64, num_cpu: u64) -> NitroCliResult<()> {
        let cmd: NitroEnclavesSlotAlloc = NitroEnclavesSlotAlloc::new();
        let result = cmd.submit(&mut self.cli_dev);

        let reply = result.unwrap();
        self.slot_uid = reply.slot_uid;

        self.alloc_and_add_mem(mem)?;

        let cmd = NitroEnclavesSlotAddBulkVcpu::new(self.slot_uid, num_cpu);
        cmd.submit(&mut self.cli_dev)?;

        let cmd = NitroEnclavesEnclaveStart::new(self.slot_uid, DEFAULT_ENCLAVE_CID, false);
        cmd.submit(&mut self.cli_dev)?;

        Ok(())
    }

    /// Function that stops the enclave stored in NitroEnclaveAllocator
    pub fn stop_enclave(&mut self) -> NitroCliResult<()> {
        let cmd = NitroEnclavesEnclaveStop::new(self.slot_uid);
        cmd.submit(&mut self.cli_dev)?;

        let cmd = NitroEnclavesSlotFree::new(self.slot_uid);
        cmd.submit(&mut self.cli_dev)?;

        Ok(())
    }
}

/// Clears the resources used to start and run the enclave
impl Drop for NitroEnclaveAllocator {
    fn drop(&mut self) {
        self.resource_allocator
            .free(self.slot_uid)
            .expect("Resource allocator failed");
        let reply = self.cli_dev.disable();
        if reply.is_err() || !reply.unwrap() {
            panic!("Failed to disable Cli Device.")
        }
    }
}

#[cfg(test)]
mod test_pci_device {
    use super::*;

    #[test]
    pub fn test_add_same_resources() {
        let mut enclave_allocator = NitroEnclaveAllocator::new().unwrap();
        let cpu_infos = CpuInfos::new().expect("Cpu info failed!");

        let cmd: NitroEnclavesSlotAlloc = NitroEnclavesSlotAlloc::new();
        let reply = cmd.submit(&mut enclave_allocator.cli_dev).unwrap();
        enclave_allocator.slot_uid = reply.slot_uid;

        for _i in 0..enclave_allocator.default_mem / MEM_CHUNK {
            let reply = enclave_allocator
                .resource_allocator
                .alloc(enclave_allocator.slot_uid, MEM_CHUNK * MiB)
                .expect("Alloc memory failed!");
            let cmd = NitroEnclavesSlotAddMem::new(reply.slot_uid, reply.mem_gpa, reply.mem_size);
            cmd.submit(&mut enclave_allocator.cli_dev)
                .expect("Add memory failed!");

            // Check command fails if same memory is added twice
            let error = cmd.submit(&mut enclave_allocator.cli_dev);
            assert_eq!(error.is_err(), true);
        }

        let cpu_ids = cpu_infos
            .get_cpu_ids(NUM_CPUS as u32)
            .expect("Cpu info failed!");
        for id in cpu_ids {
            let cmd = NitroEnclavesSlotAddVcpu::new(enclave_allocator.slot_uid, id);
            cmd.submit(&mut enclave_allocator.cli_dev)
                .expect("Add vcpu failed!");

            // Check command fails if same cpus are added twice
            let error = cmd.submit(&mut enclave_allocator.cli_dev);
            assert_eq!(error.is_err(), true);
        }

        let cmd =
            NitroEnclavesEnclaveStart::new(enclave_allocator.slot_uid, DEFAULT_ENCLAVE_CID, false);
        cmd.submit(&mut enclave_allocator.cli_dev)
            .expect("Submit start failed!");

        // Check that resources were given just once to the enclave
        let cmd = NitroEnclavesSlotInfo::new(enclave_allocator.slot_uid);
        let reply = cmd
            .submit(&mut enclave_allocator.cli_dev)
            .expect("Slot info failed!");
        let nr_cpus = reply.nr_cpus;
        assert_eq!(nr_cpus, NUM_CPUS);
        assert_eq!(reply.mem_size / MiB, enclave_allocator.default_mem);

        enclave_allocator.stop_enclave().unwrap();
    }
}
