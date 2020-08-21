// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

/// Module for communicating with the cli device.
///
/// The definitions need to be kept in sync with the device API.
use log::debug;
use memmap::{MmapMut, MmapOptions};
use std::ffi::CStr;
use std::fmt::Debug;
use std::fs::read_to_string;
use std::fs::OpenOptions;
use std::io::Result as IoResult;
use std::io::{Error, ErrorKind};
use std::mem::size_of;
use std::slice;
use std::thread::sleep;
use std::time;

use crate::utils::FileLock;
use crate::NitroCliResult;
use serde::Deserialize;

// Command types for sending requests to the NitroEnclaves device.
#[derive(Debug, Copy, Clone, Primitive)]
#[repr(u32)]
pub enum NitroEnclavesCmdType {
    NitroEnclavesInvalidCmd = 0,
    NitroEnclavesEnclaveStart = 1,
    NitroEnclavesGetSlot = 2,
    NitroEnclavesEnclaveStop = 3,
    NitroEnclavesSlotAlloc = 4,
    NitroEnclavesSlotFree = 5,
    NitroEnclavesSlotAddMem = 6,
    NitroEnclavesSlotAddVcpu = 7,
    NitroEnclavesSlotCount = 8,
    NitroEnclavesNextSlot = 9,
    NitroEnclavesSlotInfo = 10,
    NitroEnclavesSlotAddBulkVcpu = 11,
    NitroEnclavesDestroy = 12,
    NitroEnclavesMaxCmd = 13,
}

// NitroEnclaves device registers to be used for sending requests and receiving responses.
// (1 byte) Register to notify the device that a driver is actively using it.
pub const NITRO_ENCLAVES_DEV_ENABLE: usize = 0x00;
// (1 byte) Register to mask all interrupts coming from the device.
pub const NITRO_ENCLAVES_MASK_IRQ: usize = 0x01;
// (2 bytes) Version selector for the device.
pub const NITRO_ENCLAVES_VERSION: usize = 0x02;
// (4 bytes) Register for command type.
pub const NITRO_ENCLAVES_CMD_REG: usize = 0x04;
// (2 bytes) Register to provide the expected command size.
pub const NITRO_ENCLAVES_RESERVED: usize = 0x08;
// (4 bytes) Register to signal a reply is available to be read.
pub const NITRO_ENCLAVES_RPLY_PENDING: usize = 0x0c;
// (240 Bytes) Buffer for sending cmd body.
pub const NITRO_ENCLAVES_SEND_DATA: usize = 0x010;
// 240 Bytes) Buffer for reading a reply.
pub const NITRO_ENCLAVES_RECV_DATA: usize = 0x100;
// The device enable register can hold 3 states: disabled, disabling, enabled
// that are represented on 2 bits. Mask the first 2 least significant bits
// for determining the state of the device.
const DEV_ENABLE_MASK: u8 = 0x3;
const DEBUG_FLAG: u64 = 0x1;

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesEnclaveStart {
    slot_uid: u64,
    enclave_cid: u64,
    flags: u64,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesEnclaveStop {
    slot_uid: u64,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesSlotAlloc {
    unused: u8,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesSlotFree {
    slot_uid: u64,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesSlotAddMem {
    slot_uid: u64,
    paddr: u64,
    size: u64,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesSlotAddVcpu {
    slot_uid: u64,
    cpu_id: u32,
    padding: [u8; 4],
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesGetSlot {
    enclave_cid: u64,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesSlotCount {
    unused: u8,
}

#[derive(Copy, Clone, Default, Debug, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesNextSlot {
    slot_uid: u64,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesSlotAddBulkVcpu {
    slot_uid: u64,
    nr_cpus: u64,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesSlotInfo {
    slot_uid: u64,
}

#[derive(Default, Debug, Copy, Clone, Deserialize)]
#[repr(packed)]
pub struct NitroEnclavesDestroy {}

#[derive(Default, Debug, Copy, Clone)]
#[repr(packed)]
pub struct NitroEnclavesCmdReply {
    pub rc: i32,
    pub padding0: [u8; 4],
    pub slot_uid: u64,
    pub enclave_cid: u64,
    pub slot_count: u64,
    pub mem_regions: u64,
    pub mem_size: u64,
    pub nr_cpus: u64,
    pub flags: u64,
    pub state: u16,
    pub padding1: [u8; 6],
}

impl NitroEnclavesEnclaveStart {
    pub fn new(slot_uid: u64, enclave_cid: u64, debug_mode: bool) -> Self {
        NitroEnclavesEnclaveStart {
            slot_uid,
            enclave_cid,
            flags: if debug_mode { DEBUG_FLAG } else { 0 },
        }
    }

    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesEnclaveStart, self)
    }
}

impl NitroEnclavesEnclaveStop {
    pub fn new(slot_uid: u64) -> Self {
        NitroEnclavesEnclaveStop { slot_uid }
    }

    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesEnclaveStop, self)
    }
}

impl NitroEnclavesSlotAlloc {
    pub fn new() -> Self {
        NitroEnclavesSlotAlloc { unused: 0 }
    }

    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesSlotAlloc, self)
    }
}

impl NitroEnclavesSlotFree {
    pub fn new(slot_uid: u64) -> Self {
        NitroEnclavesSlotFree { slot_uid }
    }

    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesSlotFree, self)
    }
}

impl NitroEnclavesSlotAddMem {
    pub fn new(slot_uid: u64, paddr: u64, size: u64) -> Self {
        NitroEnclavesSlotAddMem {
            slot_uid,
            paddr,
            size,
        }
    }

    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesSlotAddMem, self)
    }
}

impl NitroEnclavesSlotAddVcpu {
    pub fn new(slot_uid: u64, cpu_id: u32) -> Self {
        let padding: [u8; 4] = [0; 4];
        NitroEnclavesSlotAddVcpu {
            slot_uid,
            cpu_id,
            padding,
        }
    }
    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesSlotAddVcpu, self)
    }
}

impl NitroEnclavesSlotAddBulkVcpu {
    pub fn new(slot_uid: u64, nr_cpus: u64) -> Self {
        NitroEnclavesSlotAddBulkVcpu { slot_uid, nr_cpus }
    }
    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesSlotAddBulkVcpu, self)
    }
}

impl NitroEnclavesGetSlot {
    pub fn new(enclave_cid: u64) -> Self {
        NitroEnclavesGetSlot { enclave_cid }
    }
    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesGetSlot, self)
    }
}

impl NitroEnclavesSlotCount {
    pub fn new() -> Self {
        NitroEnclavesSlotCount { unused: 0 }
    }
    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesSlotCount, self)
    }
}

impl NitroEnclavesNextSlot {
    pub fn new(slot_uid: u64) -> Self {
        NitroEnclavesNextSlot { slot_uid }
    }
    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesNextSlot, self)
    }
}

impl NitroEnclavesSlotInfo {
    pub fn new(slot_uid: u64) -> Self {
        NitroEnclavesSlotInfo { slot_uid }
    }
    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesSlotInfo, self)
    }
}

impl NitroEnclavesDestroy {
    pub fn new() -> Self {
        NitroEnclavesDestroy {}
    }

    pub fn submit(self, cli_dev: &mut CliDev) -> NitroCliResult<NitroEnclavesCmdReply> {
        cli_dev.submit_and_wait_reply(NitroEnclavesCmdType::NitroEnclavesDestroy, self)
    }
}

impl NitroEnclavesCmdReply {
    pub fn state_to_string(&self) -> String {
        match self.state {
            0 => "UNUSED",
            1 => "EMPTY",
            2 => "RUNNING",
            3 => "ZOMBIE",
            4 => "SCRUBBING",
            std::u16::MAX => "ZOMBIE",
            _ => "UNKNOWN_STATE",
        }
        .to_string()
    }

    pub fn flags_to_string(&self) -> String {
        if self.flags & DEBUG_FLAG == DEBUG_FLAG {
            "DEBUG_MODE"
        } else {
            "NONE"
        }
        .to_string()
    }
}

pub struct CliDev {
    mmap: MmapMut,
    pub _lock: FileLock,
}

impl CliDev {
    pub fn new() -> NitroCliResult<Self> {
        Ok(CliDev {
            mmap: get_mmap().map_err(|err| format!("Could not create CLI device: {}", err))?,
            _lock: FileLock::new(ENCLAVE_SYS_PATH)?,
        })
    }

    pub fn enable(&mut self) -> NitroCliResult<bool> {
        self.write_u8(NITRO_ENCLAVES_DEV_ENABLE, 0x1)?;
        let dev_enable = self.read_u8(NITRO_ENCLAVES_DEV_ENABLE)?;
        Ok(dev_enable & DEV_ENABLE_MASK == 0x1)
    }

    pub fn disable(&mut self) -> NitroCliResult<bool> {
        self.write_u8(NITRO_ENCLAVES_DEV_ENABLE, 0x0)?;

        let dev_enable = self.read_u8(NITRO_ENCLAVES_DEV_ENABLE)?;
        Ok(dev_enable & DEV_ENABLE_MASK == 0x0)
    }

    pub fn read_u8(&mut self, offset: usize) -> NitroCliResult<u8> {
        self.read(offset)
    }

    pub fn write_u8(&mut self, offset: usize, value: u8) -> NitroCliResult<()> {
        self.write(offset, value)
    }

    pub fn read_u16(&mut self, offset: usize) -> NitroCliResult<u16> {
        self.read(offset)
    }

    pub fn write_u16(&mut self, offset: usize, value: u16) -> NitroCliResult<()> {
        self.write(offset, value)
    }

    pub fn read_u32(&mut self, offset: usize) -> NitroCliResult<u32> {
        self.read(offset)
    }

    pub fn write_u32(&mut self, offset: usize, value: u32) -> NitroCliResult<()> {
        self.write(offset, value)
    }

    fn read<T: Copy + Debug>(&mut self, offset: usize) -> NitroCliResult<T> {
        let slice = self.mmap.as_ref();
        if offset + size_of::<T>() < slice.len() {
            let value_ptr = slice[offset..].as_ptr() as *const T;
            // It is safe because we checked we have space for reading.
            debug!("read: offset: 0x{:x}, value: {:?}", offset, unsafe {
                *value_ptr
            });
            Ok(unsafe { *value_ptr })
        } else {
            Err(format!(
                "Could not read from the CLI device at offset 0x{:x}",
                offset
            ))
        }
    }

    fn write<T: Copy + Debug>(&mut self, offset: usize, value: T) -> NitroCliResult<()> {
        let slice = self.mmap.as_mut();
        debug!("write: offset: 0x{:x}, value: {:?}", offset, value);

        if offset + size_of::<T>() < slice.len() {
            let value_ptr = slice[offset..].as_ptr() as *mut T;
            // It is safe because we checked we have space for writing.
            unsafe {
                *value_ptr = value;
            }
            Ok(())
        } else {
            Err(format!(
                "Could not write to the CLI device at offset 0x{:x} with value {:?}",
                offset, value
            ))
        }
    }

    fn submit_and_wait_reply<C: Copy + Debug>(
        &mut self,
        cmd_type: NitroEnclavesCmdType,
        command: C,
    ) -> NitroCliResult<NitroEnclavesCmdReply> {
        debug!("submit: {:?}", command);
        let past_reply = self.read_u32(NITRO_ENCLAVES_RPLY_PENDING)?;

        self.submit_command(cmd_type, command)?;

        let mut num_trys = 20000;
        let mut warn_trys = 200;
        let err_prefix = sanitize_command(cmd_type);
        while past_reply == self.read_u32(NITRO_ENCLAVES_RPLY_PENDING)? && num_trys > 0 {
            sleep(time::Duration::from_millis(10));
            num_trys -= 1;
            warn_trys -= 1;
            if warn_trys == 0 {
                warn_trys = 200;
                println!(
                    "{}",
                    format!("{:?} is pending a reply from the device ...", err_prefix)
                );
            }
        }

        if num_trys == 0 {
            return Err("Did not receive a reply from the device".to_string());
        }

        let reply = self.read_reply()?;
        debug!("reply: {:?}", reply);
        if reply.rc != 0 {
            let mut dev_reply = reply.rc;
            if reply.rc < 0 {
                dev_reply = -reply.rc
            }
            let err_cstr = unsafe { libc::strerror(dev_reply) };
            let err_str: &CStr = unsafe { CStr::from_ptr(err_cstr) };
            Err(format!("{:?}", err_str.to_str().unwrap()))
        } else {
            Ok(reply)
        }
    }

    fn submit_command<C: Copy + Debug>(
        &mut self,
        cmd_type: NitroEnclavesCmdType,
        command: C,
    ) -> NitroCliResult<()> {
        let ptr = &command as *const C as *const u8;
        // It's safe because we just casted this pointer.
        let bytes = unsafe { slice::from_raw_parts(ptr, size_of::<C>()) };

        for (index, byte) in bytes.iter().enumerate() {
            self.write_u8(NITRO_ENCLAVES_SEND_DATA + index, *byte)?;
        }

        self.write_u32(NITRO_ENCLAVES_CMD_REG, cmd_type as u32)
    }

    fn read_reply(&mut self) -> NitroCliResult<NitroEnclavesCmdReply> {
        let mut reply_bytes = [0u8; size_of::<NitroEnclavesCmdReply>()];

        for (index, reply_byte) in reply_bytes.iter_mut().enumerate() {
            *reply_byte = self.read_u8(NITRO_ENCLAVES_RECV_DATA + index)?;
        }

        let reply_ptr = reply_bytes.as_ptr() as *const NitroEnclavesCmdReply;
        // It is safe because reply_bytes has exactly size_of NitroEnclavesCmdReply bytes
        Ok(unsafe { *reply_ptr })
    }
}

// Path to the NitroEnclaves PCI device used for enclave lifetime management.
pub const ENCLAVE_SYS_PATH: &str = "/sys/devices/pci0000:00/0000:00:02.0/resource";
pub const ENCLAVE_SYS_PATH_R: &str = "/sys/devices/pci0000:00/0000:00:02.0/resource3";
pub const CLI_RESOURCES_LINE: usize = 3;
pub const CLI_BASE_LINE_COLUMN: usize = 0;
pub const CLI_END_COLUMN: usize = 1;

/// Returns the size of the CLI Dev BAR by parsing the sysfs entry
///
/// It is parsing the sysfs file and returns the difference between
/// what's on column0 and column1 on the third line.
/// TODO: NPE-421: Mechanism of getting this based on just the device PCI id.
fn get_bar_size() -> IoResult<usize> {
    let sysfs_content = read_to_string(ENCLAVE_SYS_PATH)?;
    let lines: Vec<&str> = sysfs_content.split('\n').collect();
    if lines.len() <= CLI_RESOURCES_LINE {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Error while parsing {}", ENCLAVE_SYS_PATH),
        ));
    }

    let tokens: Vec<&str> = lines[CLI_RESOURCES_LINE].split(' ').collect();
    if CLI_BASE_LINE_COLUMN < tokens.len() && CLI_END_COLUMN < tokens.len() {
        let base_without_prefix = tokens[CLI_BASE_LINE_COLUMN].trim_start_matches("0x");
        let end_without_prefix = tokens[CLI_END_COLUMN].trim_start_matches("0x");

        if let Ok(base_addr) = usize::from_str_radix(base_without_prefix, 16) {
            if base_addr % page_size::get() != 0 {
                return Err(Error::new(
                    ErrorKind::Other,
                    "CLI BAR is not page aligned. Please contact Amazon support.",
                ));
            }
            if let Ok(end_addr) = usize::from_str_radix(end_without_prefix, 16) {
                return Ok((end_addr - base_addr) + 1);
            }
        }
    }

    Err(Error::new(
        ErrorKind::Other,
        format!("Error while parsing {}", ENCLAVE_SYS_PATH),
    ))
}

/// Maps the the CLI BAR
///
/// TODO: NPE-421: Mechanism of getting this based on just the device PCI id.
fn get_mmap() -> IoResult<MmapMut> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(ENCLAVE_SYS_PATH_R)?;

    let mut mmap_options = MmapOptions::new();
    mmap_options.len(get_bar_size()?);
    unsafe { mmap_options.map_mut(&file) }
}

pub fn sanitize_command(cmd_type: NitroEnclavesCmdType) -> &'static str {
    // The string returned needs to fit in the phrase "... failed with error \"...\""
    match cmd_type {
        NitroEnclavesCmdType::NitroEnclavesInvalidCmd
        | NitroEnclavesCmdType::NitroEnclavesMaxCmd => "An invalid command",
        NitroEnclavesCmdType::NitroEnclavesEnclaveStart => "Starting an enclave",
        NitroEnclavesCmdType::NitroEnclavesGetSlot => "Obtaining the current enclave slot",
        NitroEnclavesCmdType::NitroEnclavesEnclaveStop => "Stopping an enclave",
        NitroEnclavesCmdType::NitroEnclavesSlotAlloc => "Allocating of the enclave slot",
        NitroEnclavesCmdType::NitroEnclavesSlotFree => "Freeing of the enclave slot",
        NitroEnclavesCmdType::NitroEnclavesSlotAddMem => "Adding memory to the enclave slot",
        NitroEnclavesCmdType::NitroEnclavesSlotAddVcpu
        | NitroEnclavesCmdType::NitroEnclavesSlotAddBulkVcpu => "Adding vCPUs to the enclave slot",
        NitroEnclavesCmdType::NitroEnclavesSlotCount => "Obtaining the number of enclave slots",
        NitroEnclavesCmdType::NitroEnclavesNextSlot => "Obtaining the next enclave slot",
        NitroEnclavesCmdType::NitroEnclavesSlotInfo => {
            "Obtaining the information about the enclave slot"
        }
        NitroEnclavesCmdType::NitroEnclavesDestroy => "Destroying an enclave",
    }
}
