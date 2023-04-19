// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]
#![allow(unknown_lints)]
#![allow(deref_nullptr)]

use aws_nitro_enclaves_image_format::defs::EifIdentityInfo;
use driver_bindings::*;
use eif_loader::{enclave_ready, TIMEOUT_MINUTE_MS};
use libc::c_int;
use log::{debug, info};
use std::collections::BTreeMap;
use std::convert::{From, Into};
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::Error;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vsock::{VsockAddr, VsockListener};

use crate::common::json_output::EnclaveBuildInfo;
use crate::common::{construct_error_message, notify_error};
use crate::common::{
    ExitGracefully, NitroCliErrorEnum, NitroCliFailure, NitroCliResult, ENCLAVE_READY_VSOCK_PORT,
    VMADDR_CID_PARENT,
};
use crate::enclave_proc::connection::Connection;
use crate::enclave_proc::connection::{safe_conn_eprintln, safe_conn_println};
use crate::enclave_proc::cpu_info::EnclaveCpuConfig;
use crate::enclave_proc::utils::get_run_enclaves_info;
use crate::enclave_proc::utils::{GiB, MiB};
use crate::new_nitro_cli_failure;
use crate::utils::ceil_div;

/// CamelCase alias for the bindgen generated driver struct (ne_enclave_start_info).
pub type EnclaveStartInfo = ne_enclave_start_info;

/// CamelCase alias for the bindgen generated driver struct (ne_user_memory_region).
pub type UserMemoryRegion = ne_user_memory_region;

/// CamelCase alias for the bindgen generate struct (ne_image_load_info).
pub type ImageLoadInfo = ne_image_load_info;

/// The internal data type needed for describing an enclave.
type UnpackedHandle = (u64, u64, u64, Vec<u32>, u64, u64, EnclaveState);

/// The bit indicating if an enclave has been launched in debug mode.
pub const NE_ENCLAVE_DEBUG_MODE: u64 = 0x1;

/// Constant number used for computing the lower memory limit.
const ENCLAVE_MEMORY_EIF_SIZE_RATIO: u64 = 4;

/// Enclave Image Format (EIF) flag.
const NE_EIF_IMAGE: u64 = 0x01;

/// Flag indicating a memory region for enclave general usage.
const NE_DEFAULT_MEMORY_REGION: u64 = 0;

/// Magic number for Nitro Enclave IOCTL codes.
const NE_MAGIC: u64 = 0xAE;

/// Path corresponding to the Nitro Enclaves device file.
const NE_DEV_FILEPATH: &str = "/dev/nitro_enclaves";

/// IOCTL code for `NE_CREATE_VM`.
pub const NE_CREATE_VM: u64 = nix::request_code_read!(NE_MAGIC, 0x20, size_of::<u64>()) as _;

/// IOCTL code for `NE_ADD_VCPU`.
pub const NE_ADD_VCPU: u64 = nix::request_code_readwrite!(NE_MAGIC, 0x21, size_of::<u32>()) as _;

/// IOCTL code for `NE_GET_IMAGE_LOAD_INFO`.
pub const NE_GET_IMAGE_LOAD_INFO: u64 =
    nix::request_code_readwrite!(NE_MAGIC, 0x22, size_of::<ImageLoadInfo>()) as _;

/// IOCTL code for `NE_SET_USER_MEMORY_REGION`.
pub const NE_SET_USER_MEMORY_REGION: u64 =
    nix::request_code_write!(NE_MAGIC, 0x23, size_of::<MemoryRegion>()) as _;

/// IOCTL code for `NE_START_ENCLAVE`.
pub const NE_START_ENCLAVE: u64 =
    nix::request_code_readwrite!(NE_MAGIC, 0x24, size_of::<EnclaveStartInfo>()) as _;

/// Mapping between hugepage size and allocation flag, in descending order of size.
const HUGE_PAGE_MAP: [(libc::c_int, u64); 9] = [
    (libc::MAP_HUGE_16GB, 16 * GiB),
    (libc::MAP_HUGE_2GB, 2 * GiB),
    (libc::MAP_HUGE_1GB, GiB),
    (libc::MAP_HUGE_512MB, 512 * MiB),
    (libc::MAP_HUGE_256MB, 256 * MiB),
    (libc::MAP_HUGE_32MB, 32 * MiB),
    (libc::MAP_HUGE_16MB, 16 * MiB),
    (libc::MAP_HUGE_8MB, 8 * MiB),
    (libc::MAP_HUGE_2MB, 2 * MiB),
];

/// A memory region used by the enclave memory allocator.
#[derive(Clone, Debug)]
pub struct MemoryRegion {
    /// Flags to determine the usage for the memory region.
    flags: u64,
    /// The region's size in bytes.
    mem_size: u64,
    /// The region's virtual address.
    mem_addr: u64,
}

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

/// Helper structure to allocate memory resources needed by an enclave.
#[derive(Clone, Default)]
struct ResourceAllocator {
    /// The requested memory size in bytes.
    requested_mem: u64,
    /// The memory regions that have actually been allocated.
    mem_regions: Vec<MemoryRegion>,
}

/// Helper structure for managing an enclave's resources.
#[derive(Default)]
struct EnclaveHandle {
    /// The CPU configuration as requested by the user.
    #[allow(dead_code)]
    cpu_config: EnclaveCpuConfig,
    /// List of CPU IDs provided to the enclave.
    cpu_ids: Vec<u32>,
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
    /// PCR values.
    build_info: EnclaveBuildInfo,
    /// EIF metadata
    metadata: Option<EifIdentityInfo>,
}

/// The structure which manages an enclave in a thread-safe manner.
#[derive(Clone, Default)]
pub struct EnclaveManager {
    /// The full ID of the managed enclave.
    pub enclave_id: String,
    /// Name of the managed enclave.
    pub enclave_name: String,
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

impl Default for EnclaveBuildInfo {
    fn default() -> Self {
        EnclaveBuildInfo::new(BTreeMap::new())
    }
}

/// Construct a UserMemoryRegion object from a MemoryRegion instance.
/// Implementing the `From` trait automatically gives access to an
/// implementation of `Into` which can be used for a MemoryRegion instance.
impl From<&MemoryRegion> for UserMemoryRegion {
    fn from(mem_reg: &MemoryRegion) -> UserMemoryRegion {
        UserMemoryRegion {
            flags: mem_reg.flags,
            memory_size: mem_reg.mem_size,
            userspace_addr: mem_reg.mem_addr,
        }
    }
}

impl MemoryRegion {
    /// Create a new `MemoryRegion` instance with the specified size (in bytes).
    pub fn new(hugepage_flag: libc::c_int) -> NitroCliResult<Self> {
        let region_index = HUGE_PAGE_MAP
            .iter()
            .position(|&page_info| page_info.0 == hugepage_flag)
            .ok_or_else(|| {
                new_nitro_cli_failure!(
                    &format!(
                        "Failed to find huge page entry for flag {:X?}",
                        hugepage_flag
                    ),
                    NitroCliErrorEnum::NoSuchHugepageFlag
                )
            })?;
        let region_size = HUGE_PAGE_MAP[region_index].1;

        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                region_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB | hugepage_flag,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err(new_nitro_cli_failure!(
                "Failed to map memory",
                NitroCliErrorEnum::EnclaveMmapError
            ));
        }

        // Record the allocated region.
        Ok(MemoryRegion {
            flags: NE_DEFAULT_MEMORY_REGION,
            mem_size: region_size,
            mem_addr: addr as u64,
        })
    }

    /// Create a new `MemoryRegion` instance with the specified values.
    pub fn new_with(flags: u64, mem_addr: u64, mem_size: u64) -> Self {
        MemoryRegion {
            flags,
            mem_size,
            mem_addr,
        }
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
            return Err(new_nitro_cli_failure!(
                "Failed to unmap memory",
                NitroCliErrorEnum::EnclaveMunmapError
            ));
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
        let offset_plus_size = region_offset.checked_add(size).ok_or_else(|| {
            new_nitro_cli_failure!(
                "Memory overflow when writing EIF file to region",
                NitroCliErrorEnum::MemoryOverflow
            )
        })?;

        if offset_plus_size > self.mem_size as usize {
            return Err(new_nitro_cli_failure!(
                "Out of region",
                NitroCliErrorEnum::MemoryOverflow
            ));
        }

        let bytes = unsafe {
            std::slice::from_raw_parts_mut(self.mem_addr as *mut u8, self.mem_size as usize)
        };

        file.read_exact(&mut bytes[region_offset..region_offset + size])
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Error while reading from enclave image: {:?}", e),
                    NitroCliErrorEnum::EifParsingError
                )
            })?;

        Ok(())
    }

    /// Get the virtual address of the memory region.
    pub fn mem_addr(&self) -> u64 {
        self.mem_addr
    }

    /// Get the size in bytes of the memory region.
    pub fn mem_size(&self) -> u64 {
        self.mem_size
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        self.free()
            .ok_or_exit_with_errno(Some("Failed to drop memory region"));
    }
}

impl ResourceAllocator {
    /// Create a new `ResourceAllocator` instance which must cover at least the requested amount of memory (in bytes).
    fn new(requested_mem: u64) -> NitroCliResult<Self> {
        if requested_mem == 0 {
            return Err(new_nitro_cli_failure!(
                "Cannot start an enclave with no memory",
                NitroCliErrorEnum::InsufficientMemoryRequested
            )
            .add_info(vec!["memory", &(requested_mem >> 20).to_string()]));
        }

        Ok(ResourceAllocator {
            requested_mem,
            mem_regions: Vec::new(),
        })
    }

    /// Allocate and provide a list of memory regions. This function creates a list of
    /// memory regions which contain at least `self.requested_mem` bytes. Each region
    /// is equivalent to a huge-page and is allocated using memory mapping.
    fn allocate(&mut self) -> NitroCliResult<&Vec<MemoryRegion>> {
        let mut allocated_pages = BTreeMap::<u64, u32>::new();
        let mut needed_mem = self.requested_mem as i64;
        let mut split_index = 0;

        info!(
            "Allocating memory regions to hold {} bytes.",
            self.requested_mem
        );

        // Always allocate larger pages first, to reduce fragmentation and page count.
        // Once an allocation of a given page size fails, proceed to the next smaller
        // page size and retry.
        for (_, page_info) in HUGE_PAGE_MAP.iter().enumerate() {
            while needed_mem >= page_info.1 as i64 {
                match MemoryRegion::new(page_info.0) {
                    Ok(value) => {
                        needed_mem -= value.mem_size as i64;
                        self.mem_regions.push(value);
                    }
                    Err(_) => break,
                }
            }
        }

        // If the user requested exactly the amount of memory that was reserved earlier,
        // we should be left with no more memory that needs allocation. But if the user
        // requests a smaller amount, we must then aim to reduce waster memory from
        // larger-page allocations (Ex: if we have 1 x 1 GB page and 1 x 2 MB page, but
        // we want to allocate only 512 MB, the above algorithm will have allocated only
        // the 2 MB page, since the 1 GB page was too large for what was needed; we now
        // need to allocate in increasing order of page size in order to reduce wastage).

        if needed_mem > 0 {
            for (_, page_info) in HUGE_PAGE_MAP.iter().rev().enumerate() {
                while needed_mem > 0 {
                    match MemoryRegion::new(page_info.0) {
                        Ok(value) => {
                            needed_mem -= value.mem_size as i64;
                            self.mem_regions.push(value);
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        // If we still have memory to allocate, it means we have insufficient resources.
        if needed_mem > 0 {
            return Err(new_nitro_cli_failure!(
                &format!(
                    "Failed to allocate entire memory ({} MB remained)",
                    needed_mem >> 20
                ),
                NitroCliErrorEnum::InsufficientMemoryAvailable
            )
            .add_info(vec!["memory", &(self.requested_mem >> 20).to_string()]));
        }

        // At this point, we may have allocated more than we need, so we release all
        // regions we no longer need, starting with the smallest ones.
        self.mem_regions
            .sort_by(|reg1, reg2| reg2.mem_size.cmp(&reg1.mem_size));

        needed_mem = self.requested_mem as i64;
        for (_, region) in self.mem_regions.iter().enumerate() {
            if needed_mem <= 0 {
                break;
            }

            needed_mem -= region.mem_size as i64;
            split_index += 1
        }

        // The regions that we no longer need are freed automatically on draining, since
        // MemRegion implements Drop.
        self.mem_regions.drain(split_index..);

        // Generate a summary of the allocated memory.
        for (_, region) in self.mem_regions.iter().enumerate() {
            if let Some(page_count) = allocated_pages.get_mut(&region.mem_size) {
                *page_count += 1;
            } else {
                allocated_pages.insert(region.mem_size, 1);
            }
        }

        info!(
            "Allocated {} region(s): {}",
            self.mem_regions.len(),
            allocated_pages
                .iter()
                .map(|(size, count)| format!("{} page(s) of {} MB", count, size >> 20))
                .collect::<Vec<String>>()
                .join(", ")
        );

        Ok(&self.mem_regions)
    }

    /// Free all previously-allocated memory regions.
    fn free(&mut self) -> NitroCliResult<()> {
        for region in self.mem_regions.iter_mut() {
            region
                .free()
                .map_err(|e| e.add_subaction("Failed to free enclave memory region".to_string()))?;
        }

        self.mem_regions.clear();
        Ok(())
    }
}

impl Drop for ResourceAllocator {
    fn drop(&mut self) {
        self.free()
            .ok_or_exit_with_errno(Some("Failed to drop resource allocator"));
    }
}

impl EnclaveHandle {
    /// Create a new enclave handle instance.
    fn new(
        enclave_cid: Option<u64>,
        memory_mib: u64,
        cpu_config: EnclaveCpuConfig,
        eif_file: File,
        debug_mode: bool,
    ) -> NitroCliResult<Self> {
        let requested_mem = memory_mib << 20;
        let eif_size = eif_file
            .metadata()
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to get enclave image file metadata: {:?}", e),
                    NitroCliErrorEnum::FileOperationFailure
                )
            })?
            .len();
        if ENCLAVE_MEMORY_EIF_SIZE_RATIO * eif_size > requested_mem {
            return Err(new_nitro_cli_failure!(
                &format!(
                    "At least {} MB must be allocated (which is {} times the EIF file size)",
                    ceil_div(ceil_div(eif_size, 1024), 1024) * ENCLAVE_MEMORY_EIF_SIZE_RATIO,
                    ENCLAVE_MEMORY_EIF_SIZE_RATIO
                ),
                NitroCliErrorEnum::InsufficientMemoryRequested
            )
            .add_info(vec![
                "memory",
                &memory_mib.to_string(),
                &(ceil_div(ceil_div(eif_size, 1024), 1024) * ENCLAVE_MEMORY_EIF_SIZE_RATIO)
                    .to_string(),
            ]));
        }

        // Open the device file.
        let dev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(NE_DEV_FILEPATH)
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to open device file: {:?}", e),
                    NitroCliErrorEnum::FileOperationFailure
                )
                .add_info(vec![NE_DEV_FILEPATH, "Open"])
            })?;

        let mut slot_uid: u64 = 0;
        let enc_fd = EnclaveHandle::do_ioctl(dev_file.as_raw_fd(), NE_CREATE_VM, &mut slot_uid)
            .map_err(|e| e.add_subaction("Create VM ioctl failed".to_string()))?;
        let flags: u64 = if debug_mode { NE_ENCLAVE_DEBUG_MODE } else { 0 };

        if enc_fd < 0 {
            return Err(new_nitro_cli_failure!(
                &format!("Invalid enclave file descriptor ({})", enc_fd),
                NitroCliErrorEnum::InvalidEnclaveFd
            ));
        }

        Ok(EnclaveHandle {
            cpu_config,
            cpu_ids: vec![],
            allocated_memory_mib: 0,
            slot_uid,
            enclave_cid,
            flags,
            enc_fd,
            resource_allocator: ResourceAllocator::new(requested_mem)
                .map_err(|e| e.add_subaction("Create resource allocator".to_string()))?,
            eif_file: Some(eif_file),
            state: EnclaveState::default(),
            build_info: EnclaveBuildInfo::new(BTreeMap::new()),
            metadata: None,
        })
    }

    /// Initialize the enclave environment and start the enclave.
    fn create_enclave(
        &mut self,
        enclave_name: String,
        connection: Option<&Connection>,
    ) -> NitroCliResult<String> {
        self.init_memory(connection)
            .map_err(|e| e.add_subaction("Memory initialization issue".to_string()))?;
        self.init_cpus()
            .map_err(|e| e.add_subaction("vCPUs initialization issue".to_string()))?;

        let sockaddr = VsockAddr::new(VMADDR_CID_PARENT, ENCLAVE_READY_VSOCK_PORT);
        let listener = VsockListener::bind(&sockaddr).map_err(|_| {
            new_nitro_cli_failure!(
                "Enclave boot heartbeat vsock connection - vsock bind error",
                NitroCliErrorEnum::EnclaveBootFailure
            )
        })?;

        let enclave_start = self
            .start(connection)
            .map_err(|e| e.add_subaction("Enclave start issue".to_string()))?;

        // Get eif size to feed it to calculate_necessary_timeout helper function
        let eif_size = self
            .eif_file
            .as_ref()
            .ok_or_else(|| {
                new_nitro_cli_failure!(
                    "Failed to get EIF file",
                    NitroCliErrorEnum::FileOperationFailure
                )
            })?
            .metadata()
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to get enclave image file metadata: {:?}", e),
                    NitroCliErrorEnum::FileOperationFailure
                )
            })?
            .len();

        // Update the poll timeout based on the eif size or allocated memory
        let poll_timeout = calculate_necessary_timeout(eif_size);

        enclave_ready(listener, poll_timeout).map_err(|err| {
            let err_msg = format!("Waiting on enclave to boot failed with error {:?}", err);
            self.terminate_enclave_error(&err_msg);
            new_nitro_cli_failure!(&err_msg, NitroCliErrorEnum::EnclaveBootFailure)
        })?;

        self.enclave_cid = Some(enclave_start.enclave_cid);

        let info = get_run_enclaves_info(
            enclave_name,
            enclave_start.enclave_cid,
            self.slot_uid,
            self.cpu_ids.clone(),
            self.allocated_memory_mib,
        )
        .map_err(|e| e.add_subaction("Get RunEnclaves information issue".to_string()))?;

        safe_conn_println(
            connection,
            serde_json::to_string_pretty(&info)
                .map_err(|err| {
                    new_nitro_cli_failure!(
                        &format!("Failed to display RunEnclaves data: {:?}", err),
                        NitroCliErrorEnum::SerdeError
                    )
                })?
                .as_str(),
        )?;

        Ok(info.enclave_id)
    }

    /// Allocate memory and provide it to the enclave.
    fn init_memory(&mut self, connection: Option<&Connection>) -> NitroCliResult<()> {
        // Allocate the memory regions needed by the enclave.
        safe_conn_eprintln(connection, "Start allocating memory...")?;

        let requested_mem_mib = self.resource_allocator.requested_mem >> 20;
        let regions = self
            .resource_allocator
            .allocate()
            .map_err(|e| e.add_subaction("Failed to allocate enclave memory".to_string()))?;

        self.allocated_memory_mib = regions.iter().fold(0, |mut acc, val| {
            acc += val.mem_size;
            acc
        }) >> 20;

        if self.allocated_memory_mib < requested_mem_mib {
            return Err(new_nitro_cli_failure!(
                &format!(
                    "Failed to allocate sufficient memory (requested {} MB, but got {} MB)",
                    requested_mem_mib, self.allocated_memory_mib
                ),
                NitroCliErrorEnum::InsufficientMemoryAvailable
            )
            .add_info(vec!["memory", &requested_mem_mib.to_string()]));
        }

        let eif_file = self.eif_file.as_mut().ok_or_else(|| {
            new_nitro_cli_failure!(
                "Failed to get mutable reference to EIF file",
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

        let mut image_load_info = ImageLoadInfo {
            flags: NE_EIF_IMAGE,
            memory_offset: 0,
        };
        EnclaveHandle::do_ioctl(self.enc_fd, NE_GET_IMAGE_LOAD_INFO, &mut image_load_info)
            .map_err(|e| e.add_subaction("Get image load info ioctl failed".to_string()))?;

        debug!("Memory load information: {:?}", image_load_info);
        write_eif_to_regions(eif_file, regions, image_load_info.memory_offset as usize)
            .map_err(|e| e.add_subaction("Write EIF to enclave memory regions".to_string()))?;

        // Provide the regions to the driver for ownership change.
        for region in regions {
            let mut user_mem_region: UserMemoryRegion = region.into();
            EnclaveHandle::do_ioctl(self.enc_fd, NE_SET_USER_MEMORY_REGION, &mut user_mem_region)
                .map_err(|e| e.add_subaction("Set user memory region ioctl failed".to_string()))?;
        }

        info!("Finished initializing memory.");

        Ok(())
    }

    /// Initialize a single vCPU from a given ID.
    fn init_single_cpu(&mut self, mut cpu_id: u32) -> NitroCliResult<()> {
        EnclaveHandle::do_ioctl(self.enc_fd, NE_ADD_VCPU, &mut cpu_id)
            .map_err(|e| e.add_subaction("Add vCPU ioctl failed".to_string()))?;

        self.cpu_ids.push(cpu_id);
        debug!("Added CPU with ID {}.", cpu_id);

        Ok(())
    }

    /// Provide CPUs from the parent instance to the enclave.
    fn init_cpus(&mut self) -> NitroCliResult<()> {
        let cpu_config = self.cpu_config.clone();

        match cpu_config {
            EnclaveCpuConfig::List(cpu_ids) => {
                for cpu_id in cpu_ids {
                    self.init_single_cpu(cpu_id).map_err(|e| {
                        e.add_subaction(format!("Failed to add CPU with ID {}", cpu_id))
                    })?;
                }
            }
            EnclaveCpuConfig::Count(cpu_count) => {
                for _ in 0..cpu_count {
                    self.init_single_cpu(0)?;
                }
            }
        }

        Ok(())
    }

    /// Start an enclave after providing it with its necessary resources.
    fn start(&mut self, connection: Option<&Connection>) -> NitroCliResult<EnclaveStartInfo> {
        let mut start = EnclaveStartInfo {
            flags: self.flags,
            enclave_cid: self.enclave_cid.unwrap_or(0),
        };

        EnclaveHandle::do_ioctl(self.enc_fd, NE_START_ENCLAVE, &mut start)
            .map_err(|e| e.add_subaction("Start enclave ioctl failed".to_string()))?;

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
            release_enclave_descriptor(self.enc_fd)
                .map_err(|e| e.add_subaction("Failed to release enclave descriptor".to_string()))?;

            // Release used memory.
            self.resource_allocator
                .free()
                .map_err(|e| e.add_subaction("Failed to release used memory".to_string()))?;
            info!("Enclave terminated.");

            // Mark enclave as terminated.
            self.clear();
        }

        Ok(())
    }

    /// Terminate an enclave and notify in case of errors.
    fn terminate_enclave_and_notify(&mut self) {
        // Attempt to terminate the enclave we are holding.
        if let Err(error_info) = self.terminate_enclave() {
            let mut err_msg = format!(
                "Terminating enclave '{:X}' failed with error: {:?}",
                self.slot_uid,
                construct_error_message(&error_info).as_str()
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

    /// Wrapper over an `ioctl()` operation
    fn do_ioctl<T>(fd: RawFd, ioctl_code: u64, arg: &mut T) -> NitroCliResult<i32> {
        let rc = unsafe { libc::ioctl(fd, ioctl_code as _, arg) };
        if rc >= 0 {
            return Ok(rc);
        }

        let err_msg = match Error::last_os_error().raw_os_error().unwrap_or(0) as u32 {
            NE_ERR_VCPU_ALREADY_USED => "The provided vCPU is already used".to_string(),
            NE_ERR_VCPU_NOT_IN_CPU_POOL => {
                "The provided vCPU is not available in the CPU pool".to_string()
            }
            NE_ERR_VCPU_INVALID_CPU_CORE => {
                "The vCPU core ID is invalid for the CPU pool".to_string()
            }
            NE_ERR_INVALID_MEM_REGION_SIZE => {
                "The memory region's size is not a multiple of 2 MiB".to_string()
            }
            NE_ERR_INVALID_MEM_REGION_ADDR => "The memory region's address is invalid".to_string(),
            NE_ERR_UNALIGNED_MEM_REGION_ADDR => {
                "The memory region's address is not aligned".to_string()
            }
            NE_ERR_MEM_REGION_ALREADY_USED => "The memory region is already used".to_string(),
            NE_ERR_MEM_NOT_HUGE_PAGE => {
                "The memory region is not backed by contiguous physical huge page(s)".to_string()
            }
            NE_ERR_MEM_DIFFERENT_NUMA_NODE => {
                "The memory region's pages and the CPUs belong to different NUMA nodes".to_string()
            }
            NE_ERR_MEM_MAX_REGIONS => {
                "The maximum number of memory regions per enclave has been reached".to_string()
            }
            NE_ERR_NO_MEM_REGIONS_ADDED => {
                "The enclave cannot start because no memory regions have been added".to_string()
            }
            NE_ERR_NO_VCPUS_ADDED => {
                "The enclave cannot start because no vCPUs have been added".to_string()
            }
            NE_ERR_ENCLAVE_MEM_MIN_SIZE => {
                "The enclave's memory size is lower than the minimum supported".to_string()
            }
            NE_ERR_FULL_CORES_NOT_USED => {
                "The enclave cannot start because full CPU cores have not been set".to_string()
            }
            NE_ERR_NOT_IN_INIT_STATE => {
                "The enclave is in an incorrect state to set resources or start".to_string()
            }
            NE_ERR_INVALID_VCPU => {
                "The provided vCPU is out of range of the available CPUs".to_string()
            }
            NE_ERR_NO_CPUS_AVAIL_IN_POOL => {
                "The enclave cannot be created because no CPUs are available in the pool"
                    .to_string()
            }
            NE_ERR_INVALID_PAGE_SIZE => {
                "The memory region is not backed by page(s) multiple of 2 MiB".to_string()
            }
            NE_ERR_INVALID_FLAG_VALUE => {
                "The provided flags value in the ioctl arg data structure is invalid".to_string()
            }
            NE_ERR_INVALID_ENCLAVE_CID => {
                "The provided enclave CID is invalid, being a well-known CID or the parent VM CID"
                    .to_string()
            }
            e => format!("An error has occurred: {} (rc: {})", e, rc),
        };

        Err(new_nitro_cli_failure!(
            &err_msg,
            NitroCliErrorEnum::IoctlFailure
        ))
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

impl EnclaveManager {
    /// Create a new `EnclaveManager` instance.
    pub fn new(
        enclave_cid: Option<u64>,
        memory_mib: u64,
        cpu_ids: EnclaveCpuConfig,
        eif_file: File,
        debug_mode: bool,
        enclave_name: String,
    ) -> NitroCliResult<Self> {
        let enclave_handle =
            EnclaveHandle::new(enclave_cid, memory_mib, cpu_ids, eif_file, debug_mode)
                .map_err(|e| e.add_subaction("Failed to create enclave handle".to_string()))?;
        Ok(EnclaveManager {
            enclave_id: String::new(),
            enclave_name,
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
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to acquire lock: {:?}", e),
                    NitroCliErrorEnum::LockAcquireFailure
                )
            })?
            .create_enclave(self.enclave_name.clone(), connection)
            .map_err(|e| e.add_subaction("Failed to create enclave".to_string()))?;
        Ok(())
    }

    /// Set measurements field inside EnclaveHandle
    pub fn set_measurements(
        &mut self,
        measurements: BTreeMap<String, String>,
    ) -> NitroCliResult<()> {
        self.enclave_handle
            .lock()
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to acquire lock: {:?}", e),
                    NitroCliErrorEnum::LockAcquireFailure
                )
            })?
            .build_info = EnclaveBuildInfo::new(measurements);
        Ok(())
    }

    /// Set metadata field inside EnclaveHandle
    pub fn set_metadata(&mut self, metadata: EifIdentityInfo) -> NitroCliResult<()> {
        self.enclave_handle
            .lock()
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to acquire lock: {:?}", e),
                    NitroCliErrorEnum::LockAcquireFailure
                )
            })?
            .metadata = Some(metadata);
        Ok(())
    }

    /// Get the resources needed for describing an enclave.
    ///
    /// The enclave handle is locked during this operation.
    pub fn get_description_resources(&self) -> NitroCliResult<UnpackedHandle> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        Ok((
            locked_handle.slot_uid,
            locked_handle.enclave_cid.unwrap(),
            locked_handle.cpu_ids.len() as u64,
            locked_handle.cpu_ids.clone(),
            locked_handle.allocated_memory_mib,
            locked_handle.flags,
            locked_handle.state.clone(),
        ))
    }

    /// Get measurements from enclave handle
    pub fn get_measurements(&self) -> NitroCliResult<EnclaveBuildInfo> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        Ok(locked_handle.build_info.clone())
    }

    /// Get metadata from enclave handle
    pub fn get_metadata(&self) -> NitroCliResult<Option<EifIdentityInfo>> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        Ok(locked_handle.metadata.clone())
    }

    /// Get the resources (enclave CID) needed for connecting to the enclave console.
    ///
    /// The enclave handle is locked during this operation.
    pub fn get_console_resources_enclave_cid(&self) -> NitroCliResult<u64> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        Ok(locked_handle.enclave_cid.unwrap())
    }

    /// Get the resources (enclave flags) needed for connecting to the enclave console.
    ///
    /// The enclave handle is locked during this operation.
    pub fn get_console_resources_enclave_flags(&self) -> NitroCliResult<u64> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        Ok(locked_handle.flags)
    }

    /// Get the resources needed for enclave termination.
    ///
    /// The enclave handle is locked during this operation.
    fn get_termination_resources(&self) -> NitroCliResult<(RawFd, ResourceAllocator)> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        Ok((
            locked_handle.enc_fd,
            locked_handle.resource_allocator.clone(),
        ))
    }

    /// Get the enclave descriptor.
    ///
    /// The enclave handle is locked during this operation.
    pub fn get_enclave_descriptor(&self) -> NitroCliResult<RawFd> {
        let locked_handle = self.enclave_handle.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        Ok(locked_handle.enc_fd)
    }

    /// Update the state the enclave is in.
    ///
    /// The enclave handle is locked during this operation.
    pub fn update_state(&mut self, state: EnclaveState) -> NitroCliResult<()> {
        let mut locked_handle = self.enclave_handle.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        locked_handle.state = state;
        Ok(())
    }

    /// Terminate the owned enclave.
    ///
    /// The enclave handle is locked only when getting the resources needed for termination.
    /// This will allow the enclave process to execute other commands while termination
    /// is taking place.
    pub fn terminate_enclave(&mut self) -> NitroCliResult<()> {
        let (enc_fd, mut resource_allocator) = self.get_termination_resources().map_err(|e| {
            e.add_subaction("Enclave manager failed to get termination resources".to_string())
        })?;
        release_enclave_descriptor(enc_fd).map_err(|e| {
            e.add_subaction("Enclave manager failed to release enclave descriptor".to_string())
        })?;
        resource_allocator.free().map_err(|e| {
            e.add_subaction("Enclave manager failed to free enclave memory".to_string())
        })?;
        self.enclave_handle
            .lock()
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to acquire lock: {:?}", e),
                    NitroCliErrorEnum::LockAcquireFailure
                )
            })?
            .clear();
        Ok(())
    }
}

/// Write an enclave image file to the specified list of memory regions.
fn write_eif_to_regions(
    eif_file: &mut File,
    regions: &[MemoryRegion],
    image_write_offset: usize,
) -> NitroCliResult<()> {
    let file_size = eif_file
        .metadata()
        .map_err(|_| {
            new_nitro_cli_failure!(
                "Failed to obtain EIF file metadata",
                NitroCliErrorEnum::FileOperationFailure
            )
        })?
        .len() as usize;

    eif_file.rewind().map_err(|_| {
        new_nitro_cli_failure!(
            "Failed to seek to the beginning of the EIF file",
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    let mut total_written: usize = 0;

    for region in regions {
        let offset_plus_file_size = file_size.checked_add(image_write_offset).ok_or_else(|| {
            new_nitro_cli_failure!(
                "Memory overflow when trying to write EIF file",
                NitroCliErrorEnum::MemoryOverflow
            )
        })?;

        if total_written >= offset_plus_file_size {
            // All bytes have been written.
            break;
        }

        let written_plus_region_size = total_written
            .checked_add(region.mem_size as usize)
            .ok_or_else(|| {
                new_nitro_cli_failure!(
                    "Memory overflow when trying to write EIF file",
                    NitroCliErrorEnum::MemoryOverflow
                )
            })?;

        if written_plus_region_size <= image_write_offset {
            // All bytes need to be skipped to get to the image write offset.
        } else {
            let region_offset = image_write_offset.saturating_sub(total_written);
            let file_offset = total_written.saturating_sub(image_write_offset);
            let size = std::cmp::min(
                region.mem_size as usize - region_offset,
                file_size - file_offset,
            );
            region
                .fill_from_file(eif_file, region_offset, size)
                .map_err(|e| {
                    e.add_subaction("Failed to fill region with file content".to_string())
                })?;
        }
        total_written += region.mem_size as usize;
    }

    Ok(())
}

/// Release the enclave descriptor.
fn release_enclave_descriptor(enc_fd: RawFd) -> NitroCliResult<()> {
    // Close enclave descriptor.
    let rc = unsafe { libc::close(enc_fd) };
    if rc < 0 {
        return Err(new_nitro_cli_failure!(
            "Failed to close enclave descriptor",
            NitroCliErrorEnum::FileOperationFailure
        ));
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

/// Helper function which contains heuristic for enclave build timeout calculation
///
/// # Arguments
///
/// * `eif_size` - The EIF size in bytes
///
/// # Examples
///
/// ```
/// use nitro_cli::enclave_proc::resource_manager::calculate_necessary_timeout;
/// use nitro_cli::enclave_proc::utils::GiB;
/// // Returns the timeout based on the 8GiB EIF size
/// let timeout = calculate_necessary_timeout(8 * GiB);
/// ```
pub fn calculate_necessary_timeout(eif_size: u64) -> c_int {
    // in case we have a valid eif_size give TIMEOUT_MINUTE_MS ms for each 6GiB
    let poll_timeout: c_int =
        ((1 + (eif_size - 1) / (6 * GiB)) as i32).saturating_mul(TIMEOUT_MINUTE_MS);

    poll_timeout
}

#[cfg(test)]
mod tests {
    use super::calculate_necessary_timeout;
    use crate::enclave_proc::utils::GiB;
    use eif_loader::TIMEOUT_MINUTE_MS;

    #[test]
    fn test_timeout_calculation() {
        assert_eq!(calculate_necessary_timeout(2 * GiB), TIMEOUT_MINUTE_MS);
        assert_eq!(calculate_necessary_timeout(6 * GiB), TIMEOUT_MINUTE_MS);
        assert_eq!(calculate_necessary_timeout(10 * GiB), 2 * TIMEOUT_MINUTE_MS);
    }
}
