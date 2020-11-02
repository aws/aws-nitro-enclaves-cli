// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module containing all driver's structs and variables
pub mod includes;

use crate::includes::{ne_enclave_start_info, ne_image_load_info, ne_user_memory_region};
use std::mem::size_of;

/// Struct containing setup info necessary for enclave start
/// It contains the following fields:
///  * flags: u64 (in) = flags for the enclave to start with
///  * enclave_cid: u64 (in / out) = context id for the enclave to start with;
///    if it is 0, hypervisor will auto-generate a cid and fill in this field
pub type EnclaveStartInfo = ne_enclave_start_info;

/// Struct representing memory region to be set for an enclave
/// It contains the following fields:
///  * flags: u64 (in) = flags to determine the usage for the memory region
///  * memory_size: u64 (in) = the size, in bytes, of the memory region to be set for
///  * userspace_addr: u64 (in) = the start address of the userspace allocated memory of
///    the memory region to set for an enclave
pub type UserMemoryRegion = ne_user_memory_region;

/// Struct containing info necessary for in-memory enclave image loading
/// It contains the following fields:
///  * flags: u64 (in) = flags to determine the enclave image type
///  * memory_offset: u64 (out) = field which will be filled with
///    offset in enclave memory where to start placing the enclave image
pub type ImageLoadInfo = ne_image_load_info;

/// The bit indicating if an enclave has been launched in debug mode.
pub const NE_ENCLAVE_DEBUG_MODE: u64 = 0x1;

/// Enclave Image Format (EIF) flag.
pub const NE_EIF_IMAGE: u64 = 0x01;

/// Flag indicating a memory region for enclave general usage.
pub const NE_DEFAULT_MEMORY_REGION: u64 = 0;

/// Magic number for Nitro Enclave IOCTL codes.
pub const NE_MAGIC: u64 = 0xAE;

/// IOCTL code for `NE_CREATE_VM`.
pub const NE_CREATE_VM: u64 = nix::request_code_read!(NE_MAGIC, 0x20, size_of::<u64>()) as _;

/// IOCTL code for `NE_ADD_VCPU`.
pub const NE_ADD_VCPU: u64 = nix::request_code_readwrite!(NE_MAGIC, 0x21, size_of::<u32>()) as _;

/// IOCTL code for `NE_GET_IMAGE_LOAD_INFO`.
pub const NE_GET_IMAGE_LOAD_INFO: u64 =
    nix::request_code_readwrite!(NE_MAGIC, 0x22, size_of::<ImageLoadInfo>()) as _;

/// IOCTL code for `NE_SET_USER_MEMORY_REGION`.
pub const NE_SET_USER_MEMORY_REGION: u64 =
    nix::request_code_write!(NE_MAGIC, 0x23, size_of::<UserMemoryRegion>()) as _;

/// IOCTL code for `NE_START_ENCLAVE`.
pub const NE_START_ENCLAVE: u64 =
    nix::request_code_readwrite!(NE_MAGIC, 0x24, size_of::<EnclaveStartInfo>()) as _;

impl EnclaveStartInfo {
    /// Create an empty `EnclaveStartInfo` instance.
    pub fn new_empty() -> Self {
        EnclaveStartInfo {
            flags: 0,
            enclave_cid: 0,
        }
    }
}
