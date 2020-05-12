#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate nitro_cli_poweruser;
extern crate num_traits;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::fs;
use std::fs::File;

#[allow(unused_imports)]
use nitro_cli_poweruser::cli_dev::{
    CliDev,
    NitroEnclavesCmdReply,
    NitroEnclavesEnclaveStart,
    NitroEnclavesGetSlot,
    NitroEnclavesEnclaveStop,
    NitroEnclavesSlotAlloc,
    NitroEnclavesSlotFree,
    NitroEnclavesSlotAddMem,
    NitroEnclavesSlotAddVcpu,
    NitroEnclavesSlotCount,
    NitroEnclavesNextSlot,
    NitroEnclavesSlotInfo,
    NitroEnclavesSlotAddBulkVcpu,
    NitroEnclavesDestroy,
};
use nitro_cli_poweruser::cpu_info::CpuInfos;
use nitro_cli_poweruser::resource_allocator_driver::ResourceAllocatorDriver;
use nitro_cli_poweruser::resource_manager::online_slot_cpus;
use nitro_cli_poweruser::resource_manager::EnclaveResourceManager;

#[derive(FromPrimitive)]
enum NitroEnclavesCmdType {
    NitroEnclavesEnclaveStart = 1,
    NitroEnclavesGetSlot,
    NitroEnclavesEnclaveStop,
    NitroEnclavesSlotAlloc,
    NitroEnclavesSlotFree,
    NitroEnclavesSlotAddMem,
    NitroEnclavesSlotAddVcpu,
    NitroEnclavesSlotCount,
    NitroEnclavesNextSlot,
    NitroEnclavesSlotInfo,
    NitroEnclavesSlotAddBulkVcpu,
    NitroEnclavesDestroy,
}

const EIF_PATH: &str = "command_executer.eif";

fn enclave_start(memory_mib: u64) {
    let eif_file = File::open(EIF_PATH)
        .map_err(|err| format!("Failed to open to eif file: {:?}", err));

    if let Ok(eif_file) = eif_file {
        let enclave_cid: Option<u64> = Some(0);
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            let cpu_ids = cpu_infos.get_cpu_ids(2);

            if let Ok(cpu_ids) = cpu_ids {
                let resource_manager = EnclaveResourceManager::new(
                    enclave_cid,
                    memory_mib,
                    cpu_ids,
                    eif_file,
                    true
                )
                .map_err(|err| format!("Could not create enclave: {:?}", err));

                if let Ok(mut resource_manager) = resource_manager {
                    let enclave_create_result = resource_manager.create_enclave();

                    if let Ok(enclave_create_result) = enclave_create_result {
                        let (_enclave_cid, _slot_id) = enclave_create_result;
                        let crt_slot_uid: u64 = _slot_id;

                        // Stop enclave
                        let stop = NitroEnclavesEnclaveStop::new(_slot_id);
                        let _ = stop.submit(&mut resource_manager.cli_dev);

                        // Slot_free
                        let slot_free = NitroEnclavesSlotFree::new(crt_slot_uid);
                        let _ = slot_free.submit(&mut resource_manager.cli_dev);

                        let resource_allocator_driver = ResourceAllocatorDriver::new();
                        if let Ok(resource_allocator_driver) = resource_allocator_driver {
                            let _ = online_slot_cpus(&resource_allocator_driver, crt_slot_uid);

                            let _ = resource_allocator_driver.free(crt_slot_uid);
                        }
                    }
                }
            } else {
                eprintln!("Could not add the requested number of cpus");
            }
        } else {
            eprintln!("CpuInfos init failed");
        }
    }
}

fn enclave_get_slot(slot_id: u64) {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let cmd = NitroEnclavesGetSlot::new(slot_id);
        let _ = cmd.submit(&mut cli_dev);
    }
}

fn enclave_stop(slot_id: u64) {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let cmd = NitroEnclavesEnclaveStop::new(slot_id);
        let _ = cmd.submit(&mut cli_dev);
    }
}

fn enclave_slot_alloc() {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let cmd = NitroEnclavesSlotAlloc::new();
        let reply = cmd.submit(&mut cli_dev);

        if let Ok(reply) = reply {
            let crt_slot_uid: u64 = reply.slot_uid;

            // Slot_free
            let slot_free = NitroEnclavesSlotFree::new(crt_slot_uid);
            let _ = slot_free.submit(&mut cli_dev);

            let resource_allocator_driver = ResourceAllocatorDriver::new();

            if let Ok(resource_allocator_driver) = resource_allocator_driver {
                let _ = online_slot_cpus(&resource_allocator_driver, crt_slot_uid);

                let _ = resource_allocator_driver.free(crt_slot_uid);
            }
        }
    }
}

fn enclave_slot_free(slot_id: u64) {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let cmd = NitroEnclavesSlotFree::new(slot_id);
        let _ = cmd.submit(&mut cli_dev);
    }
}

fn enclave_slot_add_mem() {
    let eif_file = File::open(EIF_PATH)
        .map_err(|err| format!("Failed to open to eif file: {:?}", err));

    if let Ok(eif_file) = eif_file {
        let enclave_cid: Option<u64> = Some(0);
        let memory_mib: u64 = 32;
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            let cpu_ids = cpu_infos.get_cpu_ids(2);

            if let Ok(cpu_ids) = cpu_ids {
                let resource_manager = EnclaveResourceManager::new(
                    enclave_cid,
                    memory_mib,
                    cpu_ids,
                    eif_file,
                    false,
                )
                .map_err(|err| format!("Could not create enclave: {:?}", err));

                if let Ok(mut resource_manager) = resource_manager {
                    // Only add memory, without vCPUs
                    let crt_slot_uid: u64 = resource_manager.slot_id;
                    let regions = resource_manager.resource_allocator.allocate();

                    if let Ok(regions) = regions {
                        for region in regions {
                            let add_mem = NitroEnclavesSlotAddMem::new(resource_manager.slot_id, region.mem_gpa, region.mem_size);
                            let _ = add_mem.submit(&mut resource_manager.cli_dev);
                        }

                        // Slot_free
                        let slot_free = NitroEnclavesSlotFree::new(crt_slot_uid);
                        let _ = slot_free.submit(&mut resource_manager.cli_dev);

                        let resource_allocator_driver = ResourceAllocatorDriver::new();

                        if let Ok(resource_allocator_driver) = resource_allocator_driver {
                            let _ = online_slot_cpus(&resource_allocator_driver, crt_slot_uid);

                            let _ = resource_allocator_driver.free(crt_slot_uid);
                        }
                    }
                }
            } else {
                eprintln!("Could not add the requested number of cpus");
            }
        } else {
            eprintln!("CpuInfos init failed");
        }
    }
}

fn enclave_slot_add_vcpu() {
    let eif_file = File::open(EIF_PATH)
        .map_err(|err| format!("Failed to open to eif file: {:?}", err));

    if let Ok(eif_file) = eif_file {
        let enclave_cid: Option<u64> = Some(0);
        let memory_mib: u64 = 32;
        let cpu_infos = CpuInfos::new();

        if let Ok(cpu_infos) = cpu_infos {
            let cpu_ids = cpu_infos.get_cpu_ids(2);

            if let Ok(cpu_ids) = cpu_ids {
                let resource_manager = EnclaveResourceManager::new(
                    enclave_cid,
                    memory_mib,
                    cpu_ids,
                    eif_file,
                    false,
                )
                .map_err(|err| format!("Could not create enclave: {:?}", err));

                if let Ok(mut resource_manager) = resource_manager {
                    // Add both memory and vCPUs
                    let regions = resource_manager.resource_allocator.allocate();

                    if let Ok(regions) = regions {
                        for region in regions {
                            let add_mem = NitroEnclavesSlotAddMem::new(resource_manager.slot_id, region.mem_gpa, region.mem_size);
                            let _ = add_mem.submit(&mut resource_manager.cli_dev);
                        }

                        let crt_slot_uid: u64 = resource_manager.slot_id;
                        for cpu_id in &resource_manager.cpu_ids {
                            let add_cpu = NitroEnclavesSlotAddVcpu::new(resource_manager.slot_id, *cpu_id);
                            let _ = add_cpu.submit(&mut resource_manager.cli_dev);
                        }

                        // Slot_free
                        let slot_free = NitroEnclavesSlotFree::new(crt_slot_uid);
                        let _ = slot_free.submit(&mut resource_manager.cli_dev);

                        let resource_allocator_driver = ResourceAllocatorDriver::new();

                        if let Ok(resource_allocator_driver) = resource_allocator_driver {
                            let _ = online_slot_cpus(&resource_allocator_driver, crt_slot_uid);

                            let _ = resource_allocator_driver.free(crt_slot_uid);
                        }
                    }
                }
            } else {
                eprintln!("Could not add the requested number of cpus");
            }
        } else {
            eprintln!("CpuInfos init failed");
        }
    }
}

fn enclave_slot_count() {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let slot_count = NitroEnclavesSlotCount::new();
        let _ = slot_count.submit(&mut cli_dev);
    }
}

fn enclave_next_slot(slot_id: u64) {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let slot_info = NitroEnclavesNextSlot::new(slot_id);
        let _ = slot_info.submit(&mut cli_dev);
    }
}

fn enclave_slot_info() {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let cmd = NitroEnclavesSlotAlloc::new();
        let reply = cmd.submit(&mut cli_dev);

        if let Ok(reply) = reply {
            let crt_slot_uid: u64 = reply.slot_uid;

            let info_cmd = NitroEnclavesSlotInfo::new(crt_slot_uid);
            let _ = info_cmd.submit(&mut cli_dev);

            // Slot_free
            let slot_free = NitroEnclavesSlotFree::new(crt_slot_uid);
            let _ = slot_free.submit(&mut cli_dev);

            let resource_allocator_driver = ResourceAllocatorDriver::new();

            if let Ok(resource_allocator_driver) = resource_allocator_driver {
                let _ = online_slot_cpus(&resource_allocator_driver, crt_slot_uid);

                let _ = resource_allocator_driver.free(crt_slot_uid);
            }
        }
    }
}

fn enclave_slot_add_bulk_vcpu() {
    let eif_file = File::open(EIF_PATH)
        .map_err(|err| format!("Failed to open eif file: {:?}", err));

    if let Ok(eif_file) = eif_file {
        let enclave_cid: Option<u64> = Some(0);
        let memory_mib: u64 = 32;
        let cpu_ids: Vec<u32> = Vec::new();
        // Do not add specific CPU ids, only request 2 vCPUs

        let resource_manager = EnclaveResourceManager::new(
            enclave_cid,
            memory_mib,
            cpu_ids,
            eif_file,
            false,
        )
        .map_err(|err| format!("Could not create enclave: {:?}", err));

        if let Ok(mut resource_manager) = resource_manager {
            // Add both memory and bulk vCPUs
            let regions = resource_manager.resource_allocator.allocate();

            if let Ok(regions) = regions {
                for region in regions {
                    let add_mem = NitroEnclavesSlotAddMem::new(resource_manager.slot_id, region.mem_gpa, region.mem_size);
                    let _ = add_mem.submit(&mut resource_manager.cli_dev);
                }

                let crt_slot_uid: u64 = resource_manager.slot_id;
                let add_bulk_cpu = NitroEnclavesSlotAddBulkVcpu::new(resource_manager.slot_id, 2);
                let _ = add_bulk_cpu.submit(&mut resource_manager.cli_dev);

                // Slot free
                let slot_free = NitroEnclavesSlotFree::new(crt_slot_uid);
                let _ = slot_free.submit(&mut resource_manager.cli_dev);

                let resource_allocator_driver = ResourceAllocatorDriver::new();

                if let Ok(resource_allocator_driver) = resource_allocator_driver {
                    let _ = online_slot_cpus(&resource_allocator_driver, crt_slot_uid);

                    let _ = resource_allocator_driver.free(crt_slot_uid);
                }
            }
        }
    }
}

fn enclave_destroy() {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let shutdown_cmd = NitroEnclavesDestroy::new();
        let _ = shutdown_cmd.submit(&mut cli_dev);
    }
}

fn eif_exists() -> bool {
    fs::metadata(EIF_PATH).is_ok()
}

#[allow(dead_code)]
#[allow(unused_must_use)]
fuzz_target!(|data: &[u8]| {
    if eif_exists() {
        if data.len() >= 10 {
            let cmd_type: u8 = data[0];
            match FromPrimitive::from_u8(cmd_type) {
                Some(NitroEnclavesCmdType::NitroEnclavesEnclaveStart) => {
                    enclave_start(data[9] as u64);
                }
                Some(NitroEnclavesCmdType::NitroEnclavesGetSlot) => {
                    let mut slot: [u8; 8] = Default::default();
                    slot.copy_from_slice(&data[1..9]);

                    enclave_get_slot(u64::from_le_bytes(slot));
                }
                Some(NitroEnclavesCmdType::NitroEnclavesEnclaveStop) => {
                    let mut slot: [u8; 8] = Default::default();
                    slot.copy_from_slice(&data[1..9]);

                    enclave_stop(u64::from_le_bytes(slot));
                }
                Some(NitroEnclavesCmdType::NitroEnclavesSlotAlloc) => {
                    enclave_slot_alloc();
                }
                Some(NitroEnclavesCmdType::NitroEnclavesSlotFree) => {
                    let mut slot: [u8; 8] = Default::default();
                    slot.copy_from_slice(&data[1..9]);

                    enclave_slot_free(u64::from_le_bytes(slot));
                }
                Some(NitroEnclavesCmdType::NitroEnclavesSlotAddMem) => {
                    enclave_slot_add_mem();
                }
                Some(NitroEnclavesCmdType::NitroEnclavesSlotAddVcpu) => {
                    enclave_slot_add_vcpu();
                }
                Some(NitroEnclavesCmdType::NitroEnclavesSlotCount) => {
                    enclave_slot_count();
                }
                Some(NitroEnclavesCmdType::NitroEnclavesNextSlot) => {
                    let mut slot: [u8; 8] = Default::default();
                    slot.copy_from_slice(&data[1..9]);

                    enclave_next_slot(u64::from_le_bytes(slot));
                }
                Some(NitroEnclavesCmdType::NitroEnclavesSlotInfo) => {
                    enclave_slot_info();
                }
                Some(NitroEnclavesCmdType::NitroEnclavesSlotAddBulkVcpu) => {
                    enclave_slot_add_bulk_vcpu();
                }
                Some(NitroEnclavesCmdType::NitroEnclavesDestroy) => {
                    enclave_destroy();
                }
                None => {
                    // Invalid command; do nothing
                }
            }
        }
    } else {
        eprintln!("EIF file not found in current directory. Get it by running `aws s3 cp s3://stronghold-device-fuzzing/command_executer.eif .` inside aws-nitro-enclaves-cli/cli_poweruser/");
    }
});
