// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]
use log::error;

use crate::cli_dev::{
    sanitize_command, CliDev, NitroEnclavesCmdType, NitroEnclavesEnclaveStart,
    NitroEnclavesSlotAddMem, NitroEnclavesSlotAddVcpu, NitroEnclavesSlotAlloc,
    NitroEnclavesSlotFree,
};

use crate::terminate_enclaves;
use crate::NitroCliResult;
use crate::ENCLAVE_READY_VSOCK_PORT;
use crate::ENCLAVE_VSOCK_LOADER_PORT;
use crate::VMADDR_CID_PARENT;

use crate::resource_allocator_driver::{nitro_cli_slot_mem_region, ResourceAllocatorDriver};
use crate::utils::generate_enclave_id;
use common::commands_parser::TerminateEnclavesArgs;
use common::ExitGracefully;
use nix::fcntl::{flock, FlockArg};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem::size_of_val;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

// sys fs path to online/offline cpus
const CPU_ONLINE_PATTERN: &str = "/sys/devices/system/cpu/cpu%/online";
const MIN_MEM_REGION_SIZE_MIB: u64 = 2;

#[allow(non_upper_case_globals)]
const MiB: u64 = 1024 * 1024;
/// Helper class to allocate the resources needed by an enclave.
pub struct ResourceAllocator {
    memory: u64,
    slot_uid: u64,
    max_regions: u64,
    mem_regions: Vec<nitro_cli_slot_mem_region>,
    resource_allocator_driver: ResourceAllocatorDriver,
}

impl ResourceAllocator {
    pub fn new(slot_uid: u64, memory: u64, max_regions: u64) -> NitroCliResult<Self> {
        Ok(ResourceAllocator {
            memory,
            slot_uid,
            max_regions,
            mem_regions: Vec::new(),
            resource_allocator_driver: ResourceAllocatorDriver::new()?,
        })
    }

    /// Returns a list of memory regions
    ///
    /// It creates a list of memory regions which contain a total
    /// of self.memory mbytes.
    /// It tries to allocate memory in the largest chunk possible and
    /// adaptively reduces the chunk when the allocation fails.
    pub fn allocate(&mut self) -> NitroCliResult<&Vec<nitro_cli_slot_mem_region>> {
        let mut allocated = 0;
        let mut chunk_size = if self.memory.is_power_of_two() {
            self.memory
        } else {
            self.memory
                .checked_next_power_of_two()
                .ok_or("Invalid memory size")?
                / 2
        };

        let min_chunk_size = if self.max_regions > 0 {
            let min_chunk_size =
                std::cmp::max(MIN_MEM_REGION_SIZE_MIB, self.memory / self.max_regions);
            if min_chunk_size.is_power_of_two() {
                min_chunk_size
            } else {
                min_chunk_size.next_power_of_two() / 2
            }
        } else {
            MIN_MEM_REGION_SIZE_MIB
        };
        eprintln!("Start allocating memory...");
        loop {
            if chunk_size < min_chunk_size {
                return Err("Could not allocate enclave memory".to_string());
            }

            if let Ok(region) = self
                .resource_allocator_driver
                .alloc(self.slot_uid, chunk_size * MiB)
            {
                allocated += chunk_size;
                self.mem_regions.push(region);
            } else {
                chunk_size = chunk_size / 2;
            }

            if allocated >= self.memory {
                break;
            }
        }

        Ok(&self.mem_regions)
    }

    pub fn free(&mut self) {
        if let Err(err) = self.resource_allocator_driver.free(self.slot_uid) {
            error!("Error while freeing resources: {}", err);
        }
    }
}

/// Helper class for managing the flow of creating an enclave
///
/// It owns all the resources needed for creating an enclave(slot_id,
/// memory regions) and it releases them only after the enclave started.
pub struct EnclaveResourceManager {
    slot_id: u64,
    resource_allocator: ResourceAllocator,
    enclave_cid: Option<u64>,
    pub allocated_memory_mib: u64,
    pub cpu_ids: Vec<u32>,
    eif_file: File,
    cli_dev: CliDev,
    owns_resources: bool,
    debug_mode: bool,
}

impl EnclaveResourceManager {
    pub fn new(
        enclave_cid: Option<u64>,
        memory_mib: u64,
        cpu_ids: Vec<u32>,
        eif_file: File,
        debug_mode: bool,
    ) -> NitroCliResult<Self> {
        let eif_size = eif_file
            .metadata()
            .map_err(|err| format!("{:?}", err))?
            .len()
            / 1024
            / 1024;
        if eif_size > memory_mib {
            return Err(format!("Requested memory is lower than the Enclave Image File size. The enclave should have at least {} MiB allocated", eif_size));
        }

        let mut cli_dev =
            CliDev::new().map_err(|err| format!("Could not create CLI device: {}", err))?;
        let enabled = cli_dev.enable()?;

        if !enabled {
            return Err("Could not enable CLI device".to_string());
        }

        let alloc = NitroEnclavesSlotAlloc::new();
        let alloc_err_prefix = sanitize_command(NitroEnclavesCmdType::NitroEnclavesSlotAlloc);
        let reply = alloc
            .submit(&mut cli_dev)
            .map_err(|err| format!("{:?} failed with: {}", alloc_err_prefix, err))?;

        let resource_allocator =
            ResourceAllocator::new(reply.slot_uid, memory_mib, reply.mem_regions).map_err(|e| {
                let slot_free = NitroEnclavesSlotFree::new(reply.slot_uid);
                let free_err_prefix = sanitize_command(NitroEnclavesCmdType::NitroEnclavesSlotFree);
                if let Err(err) = slot_free.submit(&mut cli_dev) {
                    error!("{:?} failed with: {:?}", free_err_prefix, err);
                }
                e
            })?;

        Ok(EnclaveResourceManager {
            slot_id: reply.slot_uid,
            enclave_cid,
            allocated_memory_mib: 0,
            cpu_ids,
            eif_file,
            cli_dev,
            resource_allocator,
            owns_resources: true,
            debug_mode,
        })
    }

    pub fn create_enclave(&mut self) -> NitroCliResult<(u64, u64)> {
        self.init_memory()?;
        self.init_cpus()?;
        let enclave_cid = self.start()?;
        eif_loader::enclave_ready(VMADDR_CID_PARENT, ENCLAVE_READY_VSOCK_PORT)
            .map_err(|err| format!("Waiting on enclave to boot failed with error {:?}", err))?;
        Ok((enclave_cid, self.slot_id))
    }

    fn init_memory(&mut self) -> NitroCliResult<()> {
        let regions = self.resource_allocator.allocate()?;
        self.allocated_memory_mib = regions.iter().fold(0, |mut acc, val| {
            acc += val.mem_size / MiB;
            acc
        });
        let err_prefix = sanitize_command(NitroEnclavesCmdType::NitroEnclavesSlotAddMem);
        for region in regions {
            let add_mem =
                NitroEnclavesSlotAddMem::new(self.slot_id, region.mem_gpa, region.mem_size);

            add_mem
                .submit(&mut self.cli_dev)
                .map_err(|err| format!("{:?} failed with error: {}", err_prefix, err))?;
        }
        Ok(())
    }

    fn init_cpus(&mut self) -> NitroCliResult<()> {
        let err_prefix = sanitize_command(NitroEnclavesCmdType::NitroEnclavesSlotAddVcpu);
        for cpu_id in &self.cpu_ids {
            let add_cpu = NitroEnclavesSlotAddVcpu::new(self.slot_id, *cpu_id);
            add_cpu
                .submit(&mut self.cli_dev)
                .map_err(|err| format!("{:?} failed with error: {}", err_prefix, err))?;
            offline_cpu(*cpu_id);
            self.resource_allocator
                .resource_allocator_driver
                .cpu_mapping(self.slot_id, Some(*cpu_id))?;
        }

        if !self.cpu_ids.is_empty() {
            eprintln!("Instance CPUs {:?} going offline", self.cpu_ids);
        }

        Ok(())
    }

    fn start(&mut self) -> NitroCliResult<u64> {
        let start = NitroEnclavesEnclaveStart::new(
            self.slot_id,
            self.enclave_cid.unwrap_or(0),
            self.debug_mode,
        );
        let err_prefix = sanitize_command(NitroEnclavesCmdType::NitroEnclavesEnclaveStart);
        let reply = start
            .submit(&mut self.cli_dev)
            .map_err(|err| format!("{:?} failed with error: {}", err_prefix, err))?;

        self.enclave_cid = Some(reply.enclave_cid);
        eprintln!(
            "Started enclave with enclave-cid: {}, memory: {} MiB, cpu-ids: {:?}",
            { reply.enclave_cid },
            self.allocated_memory_mib,
            self.cpu_ids
        );
        // Starting from here the enclave resources are owned by the
        // running enclave
        self.owns_resources = false;
        eprintln!(
            "Sending image to cid: {} port: {}",
            *self.enclave_cid.as_ref().unwrap(),
            ENCLAVE_VSOCK_LOADER_PORT
        );

        eif_loader::send_image(
            &mut self.eif_file,
            // It is safe to unwrap here, by now we should know what cid we are going to use.
            *self.enclave_cid.as_ref().unwrap_or(&0) as u32,
            ENCLAVE_VSOCK_LOADER_PORT,
            reply.vsock_loader_token.to_be_bytes(),
            between_packets_delay(),
        )
        .map_err(|err| {
            let err_msg =
                format!(
                    "Sending the image to the enclave failed with error {:?}. Could not terminate the enclave.",
                    err
                );
            let fd = self.cli_dev._lock._file.as_raw_fd();
            flock(fd, FlockArg::Unlock).ok_or_exit(&err_msg);
            let enclave_id = generate_enclave_id(self.slot_id).ok_or_exit(&err_msg);
            eprintln!("Sending the image to the enclave failed");
            eprintln!("Terminating the enclave...");
            let terminate_args = TerminateEnclavesArgs { enclave_id };
            terminate_enclaves(terminate_args).ok_or_exit(&err_msg);

            format!(
                "Sending the image to the enclave failed with error {:?}",
                err
            )
        })?;
        let enclave_cid = self.enclave_cid.ok_or("Invalid CID")?;

        Ok(enclave_cid)
    }
}

impl Drop for EnclaveResourceManager {
    fn drop(&mut self) {
        if self.owns_resources {
            let slot_free = NitroEnclavesSlotFree::new(self.slot_id);
            let err_prefix = sanitize_command(NitroEnclavesCmdType::NitroEnclavesSlotFree);
            if let Err(err) = slot_free.submit(&mut self.cli_dev) {
                error!("{:?} failed with error: {:?}", err_prefix, err);
                error!("!!! The instance could be in an inconsistent state, please reboot it !!!");
                return;
            }
            if let Err(err) = online_slot_cpus(
                &self.resource_allocator.resource_allocator_driver,
                self.slot_id,
            ) {
                error!("Error while onlining cpus: {:?}", err);
            }
            self.resource_allocator.free();
        }
    }
}

pub fn online_slot_cpus(
    resource_allocator_driver: &ResourceAllocatorDriver,
    slot_id: u64,
) -> NitroCliResult<()> {
    let cpu_mapping = resource_allocator_driver.cpu_mapping(slot_id, None)?;
    let mut cpus = Vec::new();

    for i in { 0..size_of_val(&cpu_mapping.cpu_mask) * 8 } {
        if cpu_mapping.cpu_mask[i / 64] & 1 << (i % 64) != 0 {
            online_cpu(i as u32);
            cpus.push(i as u32);
        }
    }

    if !cpus.is_empty() {
        eprintln!("Instance CPUs {:?} going online", cpus);
    }

    Ok(())
}

// Writes 0 to /sys/devices/system/cpu/cpu%/online
pub fn offline_cpu(cpu_id: u32) {
    let offline_path = CPU_ONLINE_PATTERN.replace("%", &cpu_id.to_string());
    if let Ok(ref mut file) = OpenOptions::new()
        .read(true)
        .write(true)
        .open(offline_path.clone())
    {
        if let Err(_) = file.write_all("0".as_bytes()) {
            error!("WARNING: Could not offline cpu {}", cpu_id);
        }
    } else {
        error!(
            "WARNING: Could not open {} in order to offline cpu {}",
            offline_path, cpu_id
        );
    }
}

// Write 1 to /sys/devices/system/cpu/cpu%/online
pub fn online_cpu(cpu_id: u32) {
    let online_path = CPU_ONLINE_PATTERN.replace("%", &cpu_id.to_string());
    if let Ok(ref mut file) = OpenOptions::new()
        .read(true)
        .write(true)
        .write(true)
        .write(true)
        .open(online_path.clone())
    {
        if let Err(_) = file.write_all("1".as_bytes()) {
            error!("WARNING: Could not online cpu {}", cpu_id);
        }
    } else {
        error!(
            "WARNING: Could not open {:?} for setting cpu {} back online",
            online_path, cpu_id
        );
    }
}

// Checks if NITRO_BETWEEN_PACKETS_MILLIS environment variable is set, and returns a
// a Duration representing its value.
// This is useful for testing purposes.
pub fn between_packets_delay() -> Option<Duration> {
    if let Ok(value) = std::env::var("NITRO_BETWEEN_PACKETS_MILLIS") {
        if let Ok(value) = value.parse::<u64>() {
            return Some(Duration::from_millis(value));
        }
    }

    return None;
}

#[cfg(test)]
mod tests {
    use crate::resource_manager::EnclaveResourceManager;
    use tempfile;

    #[test]
    fn test_resources_manager_is_not_leaking() {
        for i in { 0..100 } {
            println!("Iteration {}", i);
            let mut resource_manager = EnclaveResourceManager::new(
                None,
                128,
                vec![3],
                tempfile::tempfile().unwrap(),
                false,
            )
            .expect("Failed to create resource manager");
            resource_manager.init_memory().expect("Init memory failed");
            resource_manager.init_cpus().expect("Add cpus failed");
        }
    }
}
