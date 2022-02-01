// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
use byteorder::{BigEndian, ByteOrder};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::mem::size_of;

pub const EIF_MAGIC: [u8; 4] = [46, 101, 105, 102]; // .eif in ascii
pub const MAX_NUM_SECTIONS: usize = 32;
/// EIF Header Flags
/// bits 1  : Architecture - toggled for aarch64, cleared for x86_64
/// bits 2-8: Unused
pub const EIF_HDR_ARCH_ARM64: u16 = 0x1;

/// Current EIF version to be incremented every time we change the format
/// of this structures, we assume changes are backwards compatible.
/// V1 -> V2: Add support to generate and check CRC.
/// V2 -> V3: Add the signature section.
/// V3 -> V4: Add the metadata section.
pub const CURRENT_VERSION: u16 = 4;

#[derive(Clone, Copy, Debug)]
pub struct EifHeader {
    /// Magic number used to identify this file format
    pub magic: [u8; 4],
    /// EIF version
    pub version: u16,
    /// EIF header flags
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
    /// crc32 IEEE used for validating the eif file is correct, it contains
    /// the crc for everything except the bytes representing this field.
    /// Needs to be the last field of the header.
    pub eif_crc32: u32,
}

impl EifHeader {
    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pos = 0;

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[pos..pos + size_of::<[u8; 4]>()]);
        pos += size_of::<[u8; 4]>();

        let version = BigEndian::read_u16(&bytes[pos..]);
        pos += size_of::<u16>();
        let flags = BigEndian::read_u16(&bytes[pos..]);
        pos += size_of::<u16>();
        let default_mem = BigEndian::read_u64(&bytes[pos..]);
        pos += size_of::<u64>();
        let default_cpus = BigEndian::read_u64(&bytes[pos..]);
        pos += size_of::<u64>();
        let reserved = BigEndian::read_u16(&bytes[pos..]);
        pos += size_of::<u16>();
        let num_sections = BigEndian::read_u16(&bytes[pos..]);
        pos += size_of::<u16>();

        let mut section_offsets = [0u64; MAX_NUM_SECTIONS];
        for item in section_offsets.iter_mut() {
            *item = BigEndian::read_u64(&bytes[pos..]);
            pos += size_of::<u64>();
        }

        let mut section_sizes = [0u64; MAX_NUM_SECTIONS];
        for item in section_sizes.iter_mut() {
            *item = BigEndian::read_u64(&bytes[pos..]);
            pos += size_of::<u64>();
        }

        let unused = BigEndian::read_u32(&bytes[pos..]);
        pos += size_of::<u32>();
        let eif_crc32 = BigEndian::read_u32(&bytes[pos..]);
        pos += size_of::<u32>();

        if bytes.len() != pos {
            return Err("Invalid EifHeader length".to_string());
        }

        Ok(EifHeader {
            magic,
            version,
            flags,
            default_mem,
            default_cpus,
            reserved,
            num_sections,
            section_offsets,
            section_sizes,
            unused,
            eif_crc32,
        })
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; Self::size()];
        let mut result = Vec::new();
        let mut pos = 0;

        buf[pos..pos + size_of::<[u8; 4]>()].copy_from_slice(&self.magic);
        pos += size_of::<[u8; 4]>();

        BigEndian::write_u16(&mut buf[pos..], self.version);
        pos += size_of::<u16>();
        BigEndian::write_u16(&mut buf[pos..], self.flags);
        pos += size_of::<u16>();
        BigEndian::write_u64(&mut buf[pos..], self.default_mem);
        pos += size_of::<u64>();
        BigEndian::write_u64(&mut buf[pos..], self.default_cpus);
        pos += size_of::<u64>();
        BigEndian::write_u16(&mut buf[pos..], self.reserved);
        pos += size_of::<u16>();
        BigEndian::write_u16(&mut buf[pos..], self.num_sections);
        pos += size_of::<u16>();

        for elem in self.section_offsets.iter() {
            BigEndian::write_u64(&mut buf[pos..], *elem);
            pos += size_of::<u64>();
        }

        for elem in self.section_sizes.iter() {
            BigEndian::write_u64(&mut buf[pos..], *elem);
            pos += size_of::<u64>();
        }

        BigEndian::write_u32(&mut buf[pos..], self.unused);
        pos += size_of::<u32>();
        BigEndian::write_u32(&mut buf[pos..], self.eif_crc32);

        result.extend_from_slice(&buf[..]);
        result
    }

    pub const fn size() -> usize {
        4 * size_of::<u16>()
            + 2 * size_of::<u32>()
            + 2 * size_of::<u64>()
            + size_of::<[u8; 4]>()
            + 2 * size_of::<[u64; MAX_NUM_SECTIONS]>()
    }
}

#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq)]
#[repr(u16)]
pub enum EifSectionType {
    EifSectionInvalid,
    EifSectionKernel,
    EifSectionCmdline,
    EifSectionRamdisk,
    EifSectionSignature,
    EifSectionMetadata,
}

#[derive(Clone, Copy, Debug)]
pub struct EifSectionHeader {
    pub section_type: EifSectionType,
    pub flags: u16,
    pub section_size: u64,
}

impl EifSectionHeader {
    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pos = 0;

        let section_type = BigEndian::read_u16(&bytes[pos..]);
        pos += size_of::<u16>();
        let flags = BigEndian::read_u16(&bytes[pos..]);
        pos += size_of::<u16>();
        let section_size = BigEndian::read_u64(&bytes[pos..]);
        pos += size_of::<u64>();

        if bytes.len() != pos {
            return Err("Invalid EifSectionHeader length".to_string());
        }

        Ok(EifSectionHeader {
            section_type: FromPrimitive::from_u16(section_type)
                .ok_or_else(|| "Invalid section type".to_string())?,
            flags,
            section_size,
        })
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let mut buf = [0u8; Self::size()];
        let mut pos = 0;

        BigEndian::write_u16(&mut buf[pos..], self.section_type as u16);
        pos += size_of::<u16>();
        BigEndian::write_u16(&mut buf[pos..], self.flags);
        pos += size_of::<u16>();
        BigEndian::write_u64(&mut buf[pos..], self.section_size);

        result.extend_from_slice(&buf[..]);
        result
    }

    pub const fn size() -> usize {
        size_of::<EifSectionType>() + size_of::<u16>() + size_of::<u64>()
    }
}

/// Array containing the signatures of at least one PCR.
/// For now, it only contains the signature of PRC0.
pub type EifSignature = Vec<PcrSignature>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcrSignature {
    /// The PEM-formatted signing certificate
    pub signing_certificate: Vec<u8>,
    /// The serialized COSESign1 object generated using the byte array
    /// formed from RegisterIndex and RegisterValue as payload
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcrInfo {
    /// The index of the PCR
    pub register_index: i32,
    /// The value of the PCR
    pub register_value: Vec<u8>,
}

impl PcrInfo {
    pub fn new(register_index: i32, register_value: Vec<u8>) -> Self {
        PcrInfo {
            register_index,
            register_value,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EifBuildInfo {
    #[serde(rename = "BuildTime")]
    pub build_time: String,
    #[serde(rename = "BuildTool")]
    pub build_tool: String,
    #[serde(rename = "BuildToolVersion")]
    pub build_tool_version: String,
    #[serde(rename = "OperatingSystem")]
    pub img_os: String,
    #[serde(rename = "KernelVersion")]
    pub img_kernel: String,
}

/// Structure used for (de)serializing metadata when
/// writing or reading the metadata section of the EIF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EifIdentityInfo {
    #[serde(rename = "ImageName")]
    pub img_name: String,
    #[serde(rename = "ImageVersion")]
    pub img_version: String,
    #[serde(rename = "BuildMetadata")]
    pub build_info: EifBuildInfo,
    #[serde(rename = "DockerInfo")]
    pub docker_info: serde_json::Value,
    #[serde(rename = "CustomMetadata")]
    pub custom_info: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use crate::{EifHeader, EifSectionHeader, EifSectionType};
    use crate::{EIF_MAGIC, MAX_NUM_SECTIONS};

    #[test]
    fn test_eif_section_type() {
        assert_eq!(std::mem::size_of::<EifSectionType>(), 2);
    }

    #[test]
    fn test_eif_section_header_to_from_be_bytes() {
        let eif_section_header = EifSectionHeader {
            section_type: EifSectionType::EifSectionSignature,
            flags: 3,
            section_size: 123,
        };

        let bytes = eif_section_header.to_be_bytes();
        assert_eq!(bytes.len(), EifSectionHeader::size());

        let new_eif_section_header = EifSectionHeader::from_be_bytes(&bytes).unwrap();
        assert_eq!(
            eif_section_header.section_type,
            new_eif_section_header.section_type
        );
        assert_eq!(eif_section_header.flags, new_eif_section_header.flags);
        assert_eq!(
            eif_section_header.section_size,
            new_eif_section_header.section_size
        );
    }

    #[test]
    fn test_eif_header_to_from_be_bytes() {
        let eif_header = EifHeader {
            magic: EIF_MAGIC,
            version: 3,
            flags: 4,
            default_mem: 5,
            default_cpus: 6,
            reserved: 2,
            num_sections: 5,
            section_offsets: [12u64; MAX_NUM_SECTIONS],
            section_sizes: [13u64; MAX_NUM_SECTIONS],
            unused: 0,
            eif_crc32: 123,
        };

        let bytes = eif_header.to_be_bytes();
        assert_eq!(bytes.len(), EifHeader::size());

        let new_eif_header = EifHeader::from_be_bytes(&bytes).unwrap();
        assert_eq!(eif_header.magic, new_eif_header.magic);
        assert_eq!(eif_header.version, new_eif_header.version);
        assert_eq!(eif_header.flags, new_eif_header.flags);
        assert_eq!(eif_header.default_mem, new_eif_header.default_mem);
        assert_eq!(eif_header.default_cpus, new_eif_header.default_cpus);
        assert_eq!(eif_header.reserved, new_eif_header.reserved);
        assert_eq!(eif_header.num_sections, new_eif_header.num_sections);
        assert_eq!(eif_header.section_offsets, new_eif_header.section_offsets);
        assert_eq!(eif_header.section_sizes, new_eif_header.section_sizes);
        assert_eq!(eif_header.unused, new_eif_header.unused);
        assert_eq!(eif_header.eif_crc32, new_eif_header.eif_crc32);
    }

    #[test]
    fn test_eif_header_size() {
        assert_eq!(EifHeader::size(), 548);
    }

    #[test]
    fn test_eif_section_header_size() {
        assert_eq!(EifSectionHeader::size(), 12);
    }

    #[test]
    fn test_eif_header_from_be_bytes_invalid_length() {
        let bytes = [0u8; 550];
        assert!(EifHeader::from_be_bytes(&bytes).is_err());
    }

    #[test]
    fn test_eif_section_header_from_be_bytes_invalid_length() {
        let bytes = [0u8; 16];
        assert!(EifSectionHeader::from_be_bytes(&bytes).is_err());
    }

    #[test]
    fn test_eif_section_header_from_be_bytes_invalid_section_type() {
        let mut bytes = [0u8; 12];
        // As there are 6 EIF section types, set the enum index to 6
        // so we get an invalid section to cause the error.
        bytes[1] = 6;

        assert_eq!(EifSectionHeader::from_be_bytes(&bytes).is_err(), true);
    }
}

pub mod eif_hasher;
