// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use nitro_cli::common::json_output::EnclaveDescribeInfo;
use nitro_cli::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use nitro_cli::enclave_proc::cpu_info::CpuInfo;
use nitro_cli::poweruser::cli_dev::*;
use nitro_cli::poweruser::resource_allocator_driver::ResourceAllocatorDriver;
use nitro_cli::poweruser::poweruser_lib::get_enclave_describe_info;

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
            return Err(NitroCliFailure::new()
            .add_subaction("Failed to enable the CLI device".to_string())
            .set_error_code(NitroCliErrorEnum::UnspecifiedError)
            .set_file_and_line(file!(), line!()));
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
                return Err(NitroCliFailure::new()
                .add_subaction("Memory allocation failed!".to_string())
                .set_error_code(NitroCliErrorEnum::UnspecifiedError)
                .set_file_and_line(file!(), line!()));
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

        let cpu_info = CpuInfo::new().expect("Retrieving the cpu ids failed.");
        for id in cpu_info.get_cpu_candidates() {
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

    #[test]
    pub fn test_invalid_cmd() {
        let mut enclave_allocator = NitroEnclaveAllocator::new().unwrap();

        enclave_allocator
            .start_enclave(enclave_allocator.default_mem, NUM_CPUS)
            .unwrap();

        // Check get slot is working properly
        let cmd = NitroEnclavesGetSlot::new(DEFAULT_ENCLAVE_CID);
        let result = cmd.submit(&mut enclave_allocator.cli_dev);
        assert_eq!(result.is_err(), false);
        let slot_uid = result.unwrap().slot_uid;
        assert_eq!(slot_uid, enclave_allocator.slot_uid);

        // Check get slot fails when given invalid cid
        let cmd = NitroEnclavesGetSlot::new(INVALID_CID);
        let result = cmd.submit(&mut enclave_allocator.cli_dev);
        assert_eq!(result.is_err(), true);

        // Check slot count is working properly
        let cmd = NitroEnclavesSlotCount::new();
        let result = cmd
            .submit(&mut enclave_allocator.cli_dev)
            .expect("Slot count failed!");
        let slot_count = result.slot_count;
        assert_eq!(slot_count, 1);

        // Check next slot is working properly
        let cmd = NitroEnclavesNextSlot::new(0);
        let result = cmd
            .submit(&mut enclave_allocator.cli_dev)
            .expect("Next slot failed!");
        let slot_uid = result.slot_uid;
        assert_eq!(slot_uid, enclave_allocator.slot_uid);

        // Check slot info is working properly
        let cmd = NitroEnclavesSlotInfo::new(enclave_allocator.slot_uid);
        let result = cmd
            .submit(&mut enclave_allocator.cli_dev)
            .expect("Slot info failed!");
        let nr_cpus = result.nr_cpus;
        assert_eq!(nr_cpus, NUM_CPUS);
        assert_eq!(result.mem_size / MiB, enclave_allocator.default_mem);

        // Check slot info fails when given invalid cid
        let cmd = NitroEnclavesSlotInfo::new(INVALID_CID);
        let result = cmd.submit(&mut enclave_allocator.cli_dev);
        assert_eq!(result.is_err(), true);

        enclave_allocator.stop_enclave().unwrap();
    }

    #[test]
    pub fn test_pci_shutdown() {
        let mut enclave_allocator = NitroEnclaveAllocator::new().unwrap();

        enclave_allocator
            .start_enclave(enclave_allocator.default_mem, NUM_CPUS)
            .unwrap();

        // Check only one enclave has started
        let info = enclave_allocator
            .describe_enclaves()
            .expect("Describe enclaves failed!");
        assert_eq!(info.len(), 1, "Number of enclaves opened is not 1");

        let reply = enclave_allocator.cli_dev.disable();
        if reply.is_err() || !reply.unwrap() {
            panic!("Failed to disable Cli Device.");
        }

        let reply = enclave_allocator.cli_dev.enable();
        if reply.is_err() || !reply.unwrap() {
            panic!("Failed to enable Cli Device.");
        }

        // Check that the enclave was closed when CliDev was disabled
        let info = enclave_allocator
            .describe_enclaves()
            .expect("Describe enclaves failed!");
        assert_eq!(
            info.len(),
            0,
            "Enclaves did not close after device shutdown"
        );
    }

    #[test]
    pub fn test_poststart_resource() {
        let mut enclave_allocator = NitroEnclaveAllocator::new().unwrap();

        enclave_allocator
            .start_enclave(enclave_allocator.default_mem, NUM_CPUS)
            .unwrap();

        // Check adding one chunk of memory after enclave start
        let reply = enclave_allocator.alloc_and_add_mem(MEM_CHUNK);
        assert_eq!(reply.is_err(), true);

        // Check adding NUM_CPUS cpus after enclave start
        let cmd = NitroEnclavesSlotAddBulkVcpu::new(enclave_allocator.slot_uid, NUM_CPUS);
        let result = cmd.submit(&mut enclave_allocator.cli_dev);
        assert_eq!(result.is_err(), true);

        enclave_allocator.stop_enclave().unwrap();
    }

    #[test]
    pub fn test_unavailable_resource() {
        let mut enclave_allocator = NitroEnclaveAllocator::new().unwrap();

        let cmd: NitroEnclavesSlotAlloc = NitroEnclavesSlotAlloc::new();
        let reply = cmd.submit(&mut enclave_allocator.cli_dev).unwrap();
        enclave_allocator.slot_uid = reply.slot_uid;

        // Check invalid paddr
        let cmd = NitroEnclavesSlotAddMem::new(enclave_allocator.slot_uid, 43537623, 4 * MiB);
        let result = cmd.submit(&mut enclave_allocator.cli_dev);
        assert_eq!(result.is_err(), true);

        // Check more cpus than available
        let cmd = NitroEnclavesSlotAddBulkVcpu::new(enclave_allocator.slot_uid, std::u64::MAX);
        let result = cmd.submit(&mut enclave_allocator.cli_dev);
        assert_eq!(result.is_err(), true);

        // Check starting without any resources given
        let cmd =
            NitroEnclavesEnclaveStart::new(enclave_allocator.slot_uid, DEFAULT_ENCLAVE_CID, false);
        let result = cmd.submit(&mut enclave_allocator.cli_dev);
        assert_eq!(result.is_err(), true);

        let cmd = NitroEnclavesSlotFree::new(enclave_allocator.slot_uid);
        cmd.submit(&mut enclave_allocator.cli_dev).unwrap();
    }
}
