// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use kvm_bindings::kvm_userspace_memory_region;
use kvm_bindings::KVMIO;
use log::{debug, error, info};
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::SeekFrom;
use std::os::raw::c_ulong;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::common::notify_error;
use crate::common::{ExitGracefully, NitroCliResult};
use crate::enclave_proc::commands::{DEBUG_FLAG, ENCLAVE_READY_VSOCK_PORT, VMADDR_CID_PARENT};
use crate::enclave_proc::connection::Connection;
use crate::enclave_proc::connection::{safe_conn_eprintln, safe_conn_println};
use crate::enclave_proc::utils::get_run_enclaves_info;

type UnpackedHandle = (u64, u64, u64, Vec<u32>, u64, u16, EnclaveState);

/// IOCTL code for `KVM_CREATE_VM`.
pub const KVM_CREATE_VM: u64 = nix::request_code_none!(KVMIO, 0x01) as _;

/// IOCTL code for `KVM_SET_USER_MEMORY_REGION`.
pub const KVM_SET_USER_MEMORY_REGION: u64 = nix::request_code_write!(
    KVMIO,
    0x46,
    std::mem::size_of::<kvm_userspace_memory_region>()
) as _;

/// IOCTL code for `KVM_CREATE_VCPU`.
pub const KVM_CREATE_VCPU: u64 = nix::request_code_none!(KVMIO, 0x41) as _;

/// IOCTL code for `NE_ENCLAVE_START`.
pub const NE_ENCLAVE_START: u64 =
    nix::request_code_readwrite!(0x42, 0x1, std::mem::size_of::<EnclaveStartMetadata>()) as _;

/// The maximum allowable memory size of an enclave is 4 GB.
const ENCLAVE_MEMORY_MAX_SIZE: u64 = 1 << 32;

/// Offset where the enclave image file should be loaded to.
const OFFSET_IMGFORMAT: usize = 8 * 1024 * 1024;

/// The state an enclave may be in.
#[derive(Clone)]
pub enum EnclaveState {
    /// The enclave is not running (it's either not started or has been terminated).
    Empty,
    /// The enclave is running.
    Running,
    /// The enclave is in the process of terminating.
    Terminating,
}

/// A memory region used by the enclave memory allocator.
#[derive(Clone)]
pub struct MemoryRegion {
    /// The region's virtual address.
    mem_addr: u64,
    /// The region's size in bytes.
    mem_size: u64,
}

/// Meta-data necessary for the starting of an enclave.
#[repr(packed)]
pub struct EnclaveStartMetadata {
    /// The Context ID (CID) for the enclave's vsock device. If 0, the CID is auto-generated.
    enclave_cid: u64,
    /// Flags for the enclave to start with (ex.: debug mode).
    #[allow(dead_code)]
    flags: u64,
    /// Slot-unique ID mapped to the enclave.
    slot_uid: u64,
}

/// Helper structure to allocate memory resources needed by an enclave.
#[derive(Clone, Default)]
struct ResourceAllocator {
    /// The requested memory size in bytes.
    requested_mem: u64,
    /// The size of single memory region.
    region_size: u64,
    /// The maximum number of available memory regions.
    max_regions: u64,
    /// The memory regions that have actually been allocated.
    mem_regions: Vec<MemoryRegion>,
}

/// Helper structure for managing an enclave's resources.
#[derive(Default)]
struct EnclaveHandle {
    /// List of CPU IDs provided to the enclave.
    cpu_ids: Vec<u32>,
    /// List of corresponding CPU descriptors provided by the driver.
    cpu_fds: Vec<i32>,
    /// Amount of memory allocated for the enclave, in MB.
    allocated_memory_mib: u64,
    /// The enclave slot ID.
    slot_uid: u64,
    /// The enclave CID.
    enclave_cid: Option<u64>,
    /// Enclave flags (including the enclave debug mode flag).
    flags: u64,
    /// The driver-provided enclave descriptor.
    enc_fd: RawFd,
    /// The allocator used to manage enclave memory.
    resource_allocator: ResourceAllocator,
    /// The enclave image file.
    eif_file: Option<File>,
    /// The current state the enclave is in.
    state: EnclaveState,
}

/// The structure which manages an enclave in a thread-safe manner.
#[derive(Clone, Default)]
pub struct EnclaveManager {
    /// The full ID of the managed enclave.
    pub enclave_id: String,
    /// A thread-safe handle to the enclave's resources.
    enclave_handle: Arc<Mutex<EnclaveHandle>>,
}

impl ToString for EnclaveState {
    fn to_string(&self) -> String {
        match self {
            EnclaveState::Empty => "EMPTY",
            EnclaveState::Running => "RUNNING",
            EnclaveState::Terminating => "TERMINATING",
        }
        .to_string()
    }
}

impl Default for EnclaveState {
    fn default() -> Self {
        EnclaveState::Empty
    }
}

impl MemoryRegion {
    /// Create a new `MemoryRegion` instance with the specified size (in bytes).
    pub fn new(region_size: u64) -> NitroCliResult<Self> {
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                region_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err("Failed to map memory.".to_string());
        }

        // Record the allocated region.
        Ok(MemoryRegion {
            mem_addr: addr as u64,
            mem_size: region_size,
        })
    }

    /// Free the memory region, if it has been allocated earlier.
    fn free(&mut self) -> NitroCliResult<()> {
        // Do nothing if the region has already been freed.
        if self.mem_addr == 0 {
            return Ok(());
        }

        let rc =
            unsafe { libc::munmap(self.mem_addr as *mut libc::c_void, self.mem_size as usize) };

        if rc < 0 {
            return Err("Failed to unmap memory.".to_string());
        }

        // Set the address and length to 0 to avoid double-freeing.
        self.mem_addr = 0;
        self.mem_size = 0;

        Ok(())
    }

    /// Write the content from a file into memory at a given offset.
    fn fill_from_file(
        &self,
        file: &mut File,
        region_offset: usize,
        size: usize,
    ) -> NitroCliResult<()> {
        if region_offset
            .checked_add(size)
            .ok_or_else(|| "Memory overflow".to_string())?
            > self.mem_size as usize
        {
            return Err("Out of region".to_string());
        }

        let bytes = unsafe {
            std::slice::from_raw_parts_mut(self.mem_addr as *mut u8, self.mem_size as usize)
        };

        file.read_exact(&mut bytes[region_offset..region_offset + size])
            .map_err(|err| format!("Error while reading from enclave image: %{:?}", err))?;

        Ok(())
    }

    /// Get the virtual address of the memory region.
    pub fn mem_addr(&mut self) -> u64 {
        self.mem_addr
    }

    /// Get the size in bytes of the memory region.
    pub fn mem_size(&mut self) -> u64 {
        self.mem_size
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        self.free().ok_or_exit("Failed to drop memory region.");
    }
}

impl ResourceAllocator {
    /// Create a new `ResourceAllocator` instance which must cover at least the requested amount of memory (in bytes).
    fn new(requested_mem: u64) -> NitroCliResult<Self> {
        let mem_info = procfs::Meminfo::new()
            .map_err(|e| format!("Failed to read platform memory information: {:?}", e))?;
        let region_size = match mem_info.hugepagesize {
            Some(value) => value,
            None => procfs::page_size().map_err(|e| format!("Failed to read page size: {:?}", e))?
                as u64,
        };
        let mut max_regions = match mem_info.hugepages_total {
            Some(value) => value,
            None => 0,
        };

        max_regions = std::cmp::min(max_regions, 1 + (ENCLAVE_MEMORY_MAX_SIZE - 1) / region_size);
        info!(
            "Region size = {}, Maximum number of regions = {}",
            region_size, max_regions
        );

        if max_regions == 0 {
            return Err("Maximum number of memory regions cannot be 0.".to_string());
        }

        Ok(ResourceAllocator {
            requested_mem,
            region_size,
            max_regions,
            mem_regions: Vec::new(),
        })
    }

    /// Allocate and provide a list of memory regions. This function creates a list of
    /// memory regions which contain at least `self.requested_mem` bytes. Each region
    /// is equivalent to a huge-page and is allocated using memory mapping.
    fn allocate(&mut self) -> NitroCliResult<&Vec<MemoryRegion>> {
        let requested_regions = 1 + (self.requested_mem - 1) / self.region_size;
        let mut allocated_mem: u64 = 0;

        if requested_regions > self.max_regions {
            let err_msg = format!(
                "Requested number of memory regions ({}) is too high.",
                requested_regions
            );
            error!("{}", err_msg);
            return Err(err_msg);
        }

        info!(
            "Allocating {} regions to hold {} bytes.",
            requested_regions, self.requested_mem
        );

        loop {
            // Map an individual region.
            let region = MemoryRegion::new(self.region_size)?;
            allocated_mem += region.mem_size;
            self.mem_regions.push(region);

            if allocated_mem >= self.requested_mem {
                break;
            }
        }

        info!("Allocated {} regions.", self.mem_regions.len());
        Ok(&self.mem_regions)
    }

    /// Free all previously-allocated memory regions.
    fn free(&mut self) -> NitroCliResult<()> {
        for region in self.mem_regions.iter_mut() {
            region.free()?;
        }

        self.mem_regions.clear();
        Ok(())
    }
}

impl Drop for ResourceAllocator {
    fn drop(&mut self) {
        self.free().ok_or_exit("Failed to drop resource allocator.");
    }
}

impl EnclaveHandle {
    /// Create a new enclave resource manager instance.
    fn new(
        enclave_cid: Option<u64>,
        memory_mib: u64,
        cpu_ids: Vec<u32>,
        eif_file: File,
        debug_mode: bool,
    ) -> NitroCliResult<Self> {
        let requested_mem = memory_mib << 20;
        let eif_size = eif_file
            .metadata()
            .map_err(|e| format!("Failed to get enclave file metadata: {:?}", e))?
            .len();
        if eif_size > requested_mem {
            return Err(format!("Requested memory is lower than the enclave image. At least {} MiB must be allocated.", eif_size >> 20));
        }

        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nitro_enclaves")
            .map_err(|e| format!("Failed to open device file: {:?}", e))?;
        let enc_type: c_ulong = 0;
        let enc_fd = unsafe { libc::ioctl(dev_file.as_raw_fd(), KVM_CREATE_VM as _, &enc_type) };
        let flags: u64 = if debug_mode { u64::from(DEBUG_FLAG) } else { 0 };

        if enc_fd < 0 {
            return Err("Failed to get enclave device descriptor.".to_string());
        }

        Ok(EnclaveHandle {
            cpu_ids,
            cpu_fds: vec![],
            allocated_memory_mib: 0,
            slot_uid: 0,
            enclave_cid,
            flags,
            enc_fd,
            resource_allocator: ResourceAllocator::new(requested_mem)?,
            eif_file: Some(eif_file),
            state: EnclaveState::default(),
        })
    }

    /// Initialize the enclave environment and start the enclave.
    fn create_enclave(&mut self, connection: Option<&Connection>) -> NitroCliResult<String> {
        self.init_memory(connection)?;
        self.init_cpus()?;
        let enclave_start = self.start(connection)?;
        eif_loader::enclave_ready(VMADDR_CID_PARENT, ENCLAVE_READY_VSOCK_PORT).map_err(|err| {
            let err_msg = format!("Waiting on enclave to boot failed with error {:?}", err);
            self.terminate_enclave_error(&err_msg);
            err_msg
        })?;

        self.enclave_cid = Some(enclave_start.enclave_cid);
        self.slot_uid = enclave_start.slot_uid;

        let info = get_run_enclaves_info(
            enclave_start.enclave_cid,
            enclave_start.slot_uid,
            self.cpu_ids.clone(),
            self.allocated_memory_mib,
        )?;

        safe_conn_println(
            connection,
            serde_json::to_string_pretty(&info)
                .map_err(|err| format!("{:?}", err))?
                .as_str(),
        )?;

        Ok(info.enclave_id)
    }

    /// Allocate memory and provide it to the enclave.
    fn init_memory(&mut self, connection: Option<&Connection>) -> NitroCliResult<()> {
        // Allocate the memory regions needed by the enclave.
        safe_conn_eprintln(connection, "Start allocating memory...")?;

        let regions = self.resource_allocator.allocate()?;
        self.allocated_memory_mib = regions.iter().fold(0, |mut acc, val| {
            acc += val.mem_size;
            acc
        }) >> 20;

        let eif_file = self
            .eif_file
            .as_mut()
            .ok_or_else(|| "Cannot get eif_file".to_string())?;

        write_eif_to_regions(eif_file, regions)?;

        // Provide the regions to the driver for ownership change.
        for region in regions {
            let kvm_mem_region = kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                userspace_addr: region.mem_addr,
                guest_phys_addr: 0,
                memory_size: region.mem_size,
            };

            let rc = unsafe {
                libc::ioctl(
                    self.enc_fd,
                    KVM_SET_USER_MEMORY_REGION as _,
                    &kvm_mem_region,
                )
            };
            if rc < 0 {
                error!("Failed to KVM_SET_USER_MEMORY_REGION: {}\n", rc);
                return Err("".to_string());
            }
        }

        info!("Finished initializing memory.");

        Ok(())
    }

    /// Provide CPUs from the parent instance to the enclave.
    fn init_cpus(&mut self) -> NitroCliResult<()> {
        for cpu_id in &self.cpu_ids {
            let vcpu_fd = unsafe { libc::ioctl(self.enc_fd, KVM_CREATE_VCPU as _, cpu_id) };
            if vcpu_fd < 0 {
                return Err(format!(
                    "Creating vCPU {} failed with error: {}",
                    cpu_id,
                    std::io::Error::last_os_error()
                ));
            }

            self.cpu_fds.push(vcpu_fd);
        }

        Ok(())
    }

    /// Start an enclave after providing it with its necessary resources.
    fn start(&mut self, connection: Option<&Connection>) -> NitroCliResult<EnclaveStartMetadata> {
        let mut start = EnclaveStartMetadata::new(&self);
        let rc = unsafe { libc::ioctl(self.enc_fd, NE_ENCLAVE_START as _, &mut start) };

        if rc < 0 {
            return Err(format!("Failed to start enclave: {}", rc));
        }

        safe_conn_eprintln(
            connection,
            format!(
                "Started enclave with enclave-cid: {}, memory: {} MiB, cpu-ids: {:?}",
                { start.enclave_cid },
                self.allocated_memory_mib,
                self.cpu_ids
            )
            .as_str(),
        )?;

        Ok(start)
    }

    /// Terminate an enclave.
    fn terminate_enclave(&mut self) -> NitroCliResult<()> {
        if self.enclave_cid.unwrap_or(0) != 0 {
            release_enclave_descriptors(self.enc_fd, &self.cpu_fds)?;

            // Release used memory.
            self.resource_allocator.free()?;
            info!("Enclave terminated.");

            // Mark enclave as termiated.
            self.clear();
        }

        Ok(())
    }

    /// Terminate an enclave and notify in case of errors.
    fn terminate_enclave_and_notify(&mut self) {
        // Attempt to terminate the enclave we are holding.
        if let Err(err) = self.terminate_enclave() {
            let mut err_msg = format!(
                "Terminating enclave '{:X}' failed with error: {:?}",
                self.slot_uid, err
            );
            err_msg.push_str(
                "!!! The instance could be in an inconsistent state, please reboot it !!!",
            );

            // The error message should reach both the user and the logger.
            notify_error(&err_msg);
        }
    }

    /// Clear handle resources after terminating an enclave.
    fn clear(&mut self) {
        self.cpu_fds.clear();
        self.cpu_ids.clear();
        self.allocated_memory_mib = 0;
        self.enclave_cid = Some(0);
        self.enc_fd = -1;
        self.slot_uid = 0;
    }

    /// Terminate the enclave if `run-enclave` failed.
    fn terminate_enclave_error(&mut self, err: &str) {
        let err_msg = format!("{}. Terminating the enclave...", err);

        // Notify the user and the logger of the error, then terminate the enclave.
        notify_error(&err_msg);
        self.terminate_enclave_and_notify();
    }
}

impl Drop for EnclaveHandle {
    fn drop(&mut self) {
        // Check if we are (still) owning an enclave.
        if self.enclave_cid.unwrap_or(0) == 0 {
            debug!("Resource manager does not hold an enclave.");
            return;
        }

        // Terminate the enclave, notifying of any errors.
        self.terminate_enclave_and_notify();
    }
}

impl EnclaveStartMetadata {
    /// Create a new `EnclaveStartMetadata` instance from the given enclave handle.
    fn new(enclave_handle: &EnclaveHandle) -> Self {
        EnclaveStartMetadata {
            slot_uid: 0,
            enclave_cid: enclave_handle.enclave_cid.unwrap_or(0),
            flags: enclave_handle.flags,
        }
    }

    /// Create an empty `EnclaveStartMetadata` instance.
    pub fn new_empty() -> Self {
        EnclaveStartMetadata {
            slot_uid: 0,
            enclave_cid: 0,
            flags: 0,
        }
    }
}

impl EnclaveManager {
    /// Create a new `EnclaveManager` instance.
    pub fn new(
        enclave_cid: Option<u64>,
        memory_mib: u64,
        cpu_ids: Vec<u32>,
        eif_file: File,
        debug_mode: bool,
    ) -> NitroCliResult<Self> {
        let enclave_handle =
            EnclaveHandle::new(enclave_cid, memory_mib, cpu_ids, eif_file, debug_mode)?;
        Ok(EnclaveManager {
            enclave_id: String::new(),
            enclave_handle: Arc::new(Mutex::new(enclave_handle)),
        })
    }

    /// Launch an enclave using the previously-set configuration.
    ///
    /// The enclave handle is locked throughout enclave creation. This is fine, since
    /// the socket for receiving commands is exposed only after creation has completed.
    pub fn run_enclave(&mut self, connection: Option<&Connection>) -> NitroCliResult<()> {
        self.enclave_id = self
            .enclave_handle
            .lock()
            .map_err(|e| e.to_string())?
            .create_enclave(connection)?;
        Ok(())
    }

    /// Get the resources needed for describing an enclave.
    ///
    /// The enclave handle is locked during this operation.
    pub fn get_description_resources(&self) -> NitroCliResult<UnpackedHandle> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| e.to_string())?;
        Ok((
            locked_handle.slot_uid,
            locked_handle.enclave_cid.unwrap(),
            locked_handle.cpu_ids.len() as u64,
            locked_handle.cpu_ids.clone(),
            locked_handle.allocated_memory_mib,
            locked_handle.flags as u16,
            locked_handle.state.clone(),
        ))
    }

    /// Get the resources needed for connecting to the enclave console.
    ///
    /// The enclave handle is locked during this operation.
    pub fn get_console_resources(&self) -> NitroCliResult<u64> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| e.to_string())?;
        Ok(locked_handle.enclave_cid.unwrap())
    }

    /// Get the resources needed for enclave termination.
    ///
    /// The enclave handle is locked during this operation.
    fn get_termination_resources(&self) -> NitroCliResult<(RawFd, Vec<RawFd>, ResourceAllocator)> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| e.to_string())?;
        Ok((
            locked_handle.enc_fd,
            locked_handle.cpu_fds.clone(),
            locked_handle.resource_allocator.clone(),
        ))
    }

    /// Get the enclave descriptor.
    ///
    /// The enclave handle is locked during this operation.
    pub fn get_enclave_descriptor(&self) -> NitroCliResult<RawFd> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| e.to_string())?;
        Ok(locked_handle.enc_fd)
    }

    /// Update the state the enclave is in.
    ///
    /// The enclave handle is locked during this operation.
    pub fn update_state(&mut self, state: EnclaveState) -> NitroCliResult<()> {
        let mut locked_handle = self.enclave_handle.lock().map_err(|e| e.to_string())?;
        locked_handle.state = state;
        Ok(())
    }

    /// Terminate the owned enclave.
    ///
    /// The enclave handle is locked only when getting the resources needed for termination.
    /// This will allow the enclave process to execute other commands while termination
    /// is taking place.
    pub fn terminate_enclave(&mut self) -> NitroCliResult<()> {
        let (enc_fd, cpu_fds, mut resource_allocator) = self.get_termination_resources()?;
        release_enclave_descriptors(enc_fd, &cpu_fds)?;
        resource_allocator.free()?;
        self.enclave_handle
            .lock()
            .map_err(|e| e.to_string())?
            .clear();
        Ok(())
    }
}

/// Write an enclave image file to the specified list of memory regions.
fn write_eif_to_regions(eif_file: &mut File, regions: &[MemoryRegion]) -> NitroCliResult<()> {
    let file_size = eif_file
        .metadata()
        .map_err(|err| format!("Error during fs::metadata: {}", err))?
        .len() as usize;

    eif_file
        .seek(SeekFrom::Start(0))
        .map_err(|err| format!("Error during file seek: {}", err))?;

    let mut total_written: usize = 0;

    for region in regions {
        if total_written
            >= file_size
                .checked_add(OFFSET_IMGFORMAT)
                .ok_or_else(|| "Memory overflow".to_string())?
        {
            // All bytes have been written.
            break;
        }
        if total_written
            .checked_add(region.mem_size as usize)
            .ok_or_else(|| "Memory overflow".to_string())?
            < OFFSET_IMGFORMAT
        {
            // All bytes need to be skiped to get to OFFSET_IMGFORMAT.
        } else {
            let offset = OFFSET_IMGFORMAT.saturating_sub(total_written);
            let bytes_left_in_file = file_size
                .checked_add(OFFSET_IMGFORMAT)
                .ok_or_else(|| "Memory overflow".to_string())?
                .checked_sub(total_written)
                .ok_or_else(|| "Corruption, written more than file size".to_string())?;
            let size = std::cmp::min(bytes_left_in_file, region.mem_size as usize - offset);
            region.fill_from_file(eif_file, offset, size)?;
        }
        total_written += region.mem_size as usize;
    }

    Ok(())
}

/// Release the enclave and vCPU descriptors.
fn release_enclave_descriptors(enc_fd: RawFd, cpu_fds: &[RawFd]) -> NitroCliResult<()> {
    // Close vCPU descriptors.
    for cpu_fd in cpu_fds.iter() {
        let rc = unsafe { libc::close(*cpu_fd) };
        if rc < 0 {
            return Err("Failed to close CPU descriptor.".to_string());
        }
    }

    // Close enclave descriptor.
    let rc = unsafe { libc::close(enc_fd) };
    if rc < 0 {
        return Err("Failed to close enclave descriptor.".to_string());
    }

    Ok(())
}

/// Check if the `NITRO_BETWEEN_PACKETS_MILLIS` environment variable is set.
/// If it is, return a `Duration` representing its value.
pub fn between_packets_delay() -> Option<Duration> {
    if let Ok(value) = std::env::var("NITRO_BETWEEN_PACKETS_MILLIS") {
        if let Ok(value) = value.parse::<u64>() {
            return Some(Duration::from_millis(value));
        }
    }

    None
}
