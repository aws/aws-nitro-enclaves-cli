// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
/// Definition Eif (Enclave Image format)
///
/// This crate is consumed by the following clients:
///    - eif_utils: needed by the eif_builder.
///    - eif_loader: needed to properly send an eif file over vsock.
///
/// With that in mind please be frugal with the dependencies for this
/// crate.

pub const EIF_MAGIC: [u8; 4] = [46, 101, 105, 102]; // .eif in ascii
pub const MAX_NUM_SECTIONS: usize = 32;

/// Current EIF version to be incremented every time we change the format
/// of this structures, we assume changes are backwards compatible.
/// V0 -> V1: Add support to generate and check CRC.
pub const CURRENT_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct EifHeader {
    /// Magic number used to identify this file format
    pub magic: [u8; 4],
    /// EIF version
    pub version: u16,
    pub flags: u16,
    /// Default enclave memory used to boot this eif file
    pub default_mem: u64,
    /// Default enclave cpus number used to boot this eif file
    pub default_cpus: u64,
    pub reserved: u16,
    pub num_sections: u16,
    pub section_offsets: [u64; MAX_NUM_SECTIONS],
    /// Sizes for each section, we need this information in the
    /// header because the vsock_loader needs to know how large are the
    /// ramdisks
    pub section_sizes: [u64; MAX_NUM_SECTIONS],
    pub unused: u32,
    /// crc32 IEEE used for validating the eif file is corect, it contains
    /// the crc for everything except the bytes representing this field.
    /// Needs to be the last field of the header.
    pub eif_crc32: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u16)]
pub enum EifSectionType {
    EifSectionInvalid,
    EifSectionKernel,
    EifSectionCmdline,
    EifSectionRamdisk,
}

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct EifSectionHeader {
    pub section_type: EifSectionType,
    pub flags: u16,
    pub section_size: u64,
}

#[cfg(test)]
mod tests {
    use crate::EifHeader;
    use crate::EifSectionHeader;
    use crate::EifSectionType;

    #[test]
    fn test_eif_header_size() {
        assert_eq!(std::mem::size_of::<EifHeader>(), 548);
    }

    #[test]
    fn test_eif_section_header_size() {
        assert_eq!(std::mem::size_of::<EifSectionHeader>(), 12);
    }

    #[test]
    fn test_eif_section_type() {
        assert_eq!(std::mem::size_of::<EifSectionType>(), 2);
    }
}

pub mod eif_hasher;
