#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate nitro_cli_poweruser;
extern crate num_traits;

use std::fs;
use std::mem;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[allow(unused_imports)]
use nitro_cli_poweruser::cli_dev::{
    CliDev, NitroEnclavesCmdReply, NitroEnclavesDestroy, NitroEnclavesEnclaveStart,
    NitroEnclavesEnclaveStop, NitroEnclavesGetSlot, NitroEnclavesNextSlot,
    NitroEnclavesSlotAddBulkVcpu, NitroEnclavesSlotAddMem, NitroEnclavesSlotAddVcpu,
    NitroEnclavesSlotAlloc, NitroEnclavesSlotCount, NitroEnclavesSlotFree, NitroEnclavesSlotInfo,
};
use nitro_cli_poweruser::resource_allocator_driver::ResourceAllocatorDriver;

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

#[derive(FromPrimitive)]
enum FuzzerTestType {
    FuzzerTestValidCommands,
    FuzzerTestValidCommandsInvalidArgs,
    FuzzerTestInvalidCommands,
}

const EIF_PATH: &str = "command_executer.eif";
const MIN_PAYLOAD_LENGTH: usize = 23;
const WAIT_PERIOD: u64 = 100;

fn eif_exists() -> bool {
    fs::metadata(EIF_PATH).is_ok()
}

fn generate_and_submit_random_cmd(data: &[u8], cmd_type: u8) {
    let cli_dev = CliDev::new();

    if let Ok(mut cli_dev) = cli_dev {
        let enable_res = cli_dev.enable();
        if let Ok(enable_res) = enable_res {
            if enable_res {
                match FromPrimitive::from_u8(cmd_type) {
                    Some(NitroEnclavesCmdType::NitroEnclavesEnclaveStart) => {
                        let cmd_ptr: *const NitroEnclavesEnclaveStart =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesEnclaveStart = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesGetSlot) => {
                        let cmd_ptr: *const NitroEnclavesGetSlot =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesGetSlot = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesEnclaveStop) => {
                        let cmd_ptr: *const NitroEnclavesEnclaveStop =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesEnclaveStop = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesSlotAlloc) => {
                        let cmd_ptr: *const NitroEnclavesSlotAlloc =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesSlotAlloc = unsafe { *cmd_ptr };
                        let reply = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                        if let Ok(reply) = reply {
                            let crt_slot_uid: u64 = reply.slot_uid;

                            // Slot free
                            let slot_free = NitroEnclavesSlotFree::new(crt_slot_uid);
                            let _ = slot_free.submit(&mut cli_dev);
                            std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));

                            let resource_allocator_driver = ResourceAllocatorDriver::new();

                            if let Ok(resource_allocator_driver) = resource_allocator_driver {
                                let _ = resource_allocator_driver.free(crt_slot_uid);
                            }
                        }
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesSlotFree) => {
                        let cmd_ptr: *const NitroEnclavesSlotFree =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesSlotFree = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesSlotAddMem) => {
                        let cmd_ptr: *const NitroEnclavesSlotAddMem =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesSlotAddMem = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesSlotAddVcpu) => {
                        let cmd_ptr: *const NitroEnclavesSlotAddVcpu =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesSlotAddVcpu = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesSlotCount) => {
                        let cmd_ptr: *const NitroEnclavesSlotCount =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesSlotCount = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesNextSlot) => {
                        let cmd_ptr: *const NitroEnclavesNextSlot =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesNextSlot = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesSlotInfo) => {
                        let cmd_ptr: *const NitroEnclavesSlotInfo =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesSlotInfo = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesSlotAddBulkVcpu) => {
                        let cmd_ptr: *const NitroEnclavesSlotAddBulkVcpu =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesSlotAddBulkVcpu = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    Some(NitroEnclavesCmdType::NitroEnclavesDestroy) => {
                        let cmd_ptr: *const NitroEnclavesDestroy =
                            unsafe { mem::transmute(data.as_ptr()) };
                        let cmd: NitroEnclavesDestroy = unsafe { *cmd_ptr };
                        let _ = cmd.submit(&mut cli_dev);
                        std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
                    }
                    None => {
                        // Invalid command; do nothing
                    }
                }
            }
        }
    }
}

#[allow(dead_code)]
#[allow(unused_must_use)]
fuzz_target!(|data: &[u8]| {
    std::thread::sleep(std::time::Duration::from_millis(WAIT_PERIOD));
    if eif_exists() {
        if data.len() >= MIN_PAYLOAD_LENGTH {
            let cmd_type: u8 = data[1];

            generate_and_submit_random_cmd(data, cmd_type);
        }
    } else {
        eprintln!("EIF file not found in current directory. Get it by running `aws s3 cp s3://stronghold-device-fuzzing/command_executer.eif .` inside aws-nitro-enclaves-cli/cli_poweruser/");
    }
});
