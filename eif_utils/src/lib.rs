// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
use crc::{crc32, Hasher32};
use eif_defs::eif_hasher::EifHasher;
use eif_defs::{EifHeader, EifSectionHeader, EifSectionType, EIF_MAGIC, MAX_NUM_SECTIONS};
use sha2::Digest;
use std::collections::BTreeMap;

/// Contains code for EifBuilder a simple library used for building an EifFile
/// from a:
///    - kernel_file
///    - cmdline string
///    - ramdisks files.
///  TODO:
///     - Unittests.
///     - Add support to write default_mem & default_cpus, flags.
///     - Various validity checks: E.g: kernel is a bzImage.
use std::ffi::CString;
use std::fmt::Debug;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::path::Path;
use std::slice;

pub struct EifBuilder<T: Digest + Debug + Write + Clone> {
    kernel: File,
    cmdline: Vec<u8>,
    ramdisks: Vec<File>,
    default_mem: u64,
    default_cpus: u64,
    /// Hash of the whole EifImage.
    image_hasher: EifHasher<T>,
    /// Hash of the EifSections provided by Amazon
    /// Kernel + cmdline + First Ramdisk
    bootstrap_hasher: EifHasher<T>,
    /// Hash of the remaining ramdisks.
    customer_app_hasher: EifHasher<T>,
    hasher_template: T,
    eif_crc: crc32::Digest,
}

impl<T: Digest + Debug + Write + Clone> EifBuilder<T> {
    pub fn new(kernel_path: &Path, cmdline: String, hasher: T) -> Self {
        let kernel_file = File::open(kernel_path).expect("Invalid kernel path");
        let cmdline = CString::new(cmdline).expect("Invalid cmdline");
        EifBuilder {
            kernel: kernel_file,
            cmdline: cmdline.into_bytes(),
            ramdisks: Vec::new(),
            default_mem: 1024 * 1024 * 1024,
            default_cpus: 2,
            image_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create image_hasher"),
            bootstrap_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create bootstrap_hasher"),
            customer_app_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create customer app hasher"),
            hasher_template: hasher.clone(),
            eif_crc: crc32::Digest::new_with_initial(crc32::IEEE, 0),
        }
    }

    pub fn add_ramdisk(&mut self, ramdisk_path: &Path) {
        let ramdisk_file = File::open(ramdisk_path).expect("Invalid ramdisk path");
        self.ramdisks.push(ramdisk_file);
    }

    /// The first two sections are the kernel and the cmdline.
    fn num_sections(&self) -> u16 {
        2 + self.ramdisks.len() as u16
    }

    fn sections_offsets(&self) -> [u64; MAX_NUM_SECTIONS] {
        let mut result = [0; MAX_NUM_SECTIONS];
        result[0] = self.kernel_offset();
        result[1] = self.cmdline_offset();

        for i in { 0..self.ramdisks.len() } {
            result[i + 2] = self.ramdisk_offset(i);
        }

        result
    }

    fn sections_sizes(&self) -> [u64; MAX_NUM_SECTIONS] {
        let mut result = [0; MAX_NUM_SECTIONS];

        result[0] = self.kernel_size();
        result[1] = self.cmdline_size();

        for i in { 0..self.ramdisks.len() } {
            result[i + 2] = self.ramdisk_size(&self.ramdisks[i]);
        }

        result
    }

    fn eif_header_offset(&self) -> u64 {
        0
    }

    fn kernel_offset(&self) -> u64 {
        self.eif_header_offset() + std::mem::size_of::<EifHeader>() as u64
    }

    fn kernel_size(&self) -> u64 {
        self.kernel.metadata().unwrap().len() as u64
    }

    fn cmdline_offset(&self) -> u64 {
        self.kernel_offset() + std::mem::size_of::<EifSectionHeader>() as u64 + self.kernel_size()
    }

    fn cmdline_size(&self) -> u64 {
        self.cmdline.len() as u64
    }

    fn ramdisk_offset(&self, index: usize) -> u64 {
        self.cmdline_offset()
            + self.cmdline_size()
            + std::mem::size_of::<EifSectionHeader>() as u64
            + self.ramdisks[0..index]
                .iter()
                .fold(0, |mut total_len, file| {
                    total_len += file.metadata().expect("Invalid ramdisk metadata").len()
                        + std::mem::size_of::<EifSectionHeader>() as u64;
                    total_len
                })
    }

    fn ramdisk_size(&self, ramdisk: &File) -> u64 {
        ramdisk.metadata().unwrap().len() as u64
    }

    pub fn header(&mut self) -> EifHeader {
        EifHeader {
            magic: EIF_MAGIC,
            version: eif_defs::CURRENT_VERSION,
            flags: 0,
            default_mem: self.default_mem,
            default_cpus: self.default_cpus,
            reserved: 0,
            num_sections: self.num_sections(),
            section_offsets: self.sections_offsets(),
            section_sizes: self.sections_sizes(),
            unused: 0,
            eif_crc32: self.eif_crc.sum32(),
        }
    }

    pub fn compute_crc(&mut self) {
        let eif_header = self.header();
        let eif_buffer = unsafe {
            slice::from_raw_parts(
                &eif_header as *const EifHeader as *const u8,
                std::mem::size_of::<EifHeader>(),
            )
        };
        // The last field of the EifHeader is the CRC itself, so we need
        // to exclude it from contributing to the CRC.
        let len_without_crc = eif_buffer.len() - size_of::<u32>();
        self.eif_crc.write(&eif_buffer[..len_without_crc]);

        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionKernel,
            flags: 0,
            section_size: self.kernel_size(),
        };

        let eif_buffer = unsafe {
            slice::from_raw_parts(
                &eif_section as *const EifSectionHeader as *const u8,
                std::mem::size_of::<EifSectionHeader>(),
            )
        };
        self.eif_crc.write(&eif_buffer[..]);
        let mut kernel_file = &self.kernel;

        kernel_file
            .seek(SeekFrom::Start(0))
            .expect("Could not seek kernel to begining");
        let mut buffer = Vec::new();
        kernel_file
            .read_to_end(&mut buffer)
            .expect("Failed to read kernel content");

        self.eif_crc.write(&buffer[..]);

        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionCmdline,
            flags: 0,
            section_size: self.cmdline_size(),
        };

        let eif_buffer = unsafe {
            slice::from_raw_parts(
                &eif_section as *const EifSectionHeader as *const u8,
                std::mem::size_of::<EifSectionHeader>(),
            )
        };
        self.eif_crc.write(eif_buffer);
        self.eif_crc.write(&self.cmdline[..]);

        for mut ramdisk in &self.ramdisks {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionRamdisk,
                flags: 0,
                section_size: self.ramdisk_size(&ramdisk),
            };

            let eif_buffer = unsafe {
                slice::from_raw_parts(
                    &eif_section as *const EifSectionHeader as *const u8,
                    std::mem::size_of::<EifSectionHeader>(),
                )
            };
            self.eif_crc.write(&eif_buffer[..]);

            ramdisk
                .seek(SeekFrom::Start(0))
                .expect("Could not seek kernel to begining");
            let mut buffer = Vec::new();
            ramdisk
                .read_to_end(&mut buffer)
                .expect("Failed to read kernel content");
            self.eif_crc.write(&buffer[..]);
        }
    }

    pub fn write_header(&mut self, file: &mut File) {
        let eif_header = self.header();
        file.seek(SeekFrom::Start(self.eif_header_offset())).expect(
            "Could not seek while writing eif \
             header",
        );
        let eif_buffer = unsafe {
            slice::from_raw_parts(
                &eif_header as *const EifHeader as *const u8,
                std::mem::size_of::<EifHeader>(),
            )
        };
        self.image_hasher.write(eif_buffer).unwrap();
        file.write_all(eif_buffer)
            .expect("Failed to write eif header");
    }

    pub fn write_kernel(&mut self, eif_file: &mut File) {
        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionKernel,
            flags: 0,
            section_size: self.kernel_size(),
        };

        eif_file
            .seek(SeekFrom::Start(self.kernel_offset()))
            .expect("Could not seek while writing kernel section");
        let eif_buffer = unsafe {
            slice::from_raw_parts(
                &eif_section as *const EifSectionHeader as *const u8,
                std::mem::size_of::<EifSectionHeader>(),
            )
        };
        self.image_hasher.write(eif_buffer).unwrap();
        self.bootstrap_hasher.write(eif_buffer).unwrap();
        eif_file
            .write_all(eif_buffer)
            .expect("Failed to write kernel header");
        let mut kernel_file = &self.kernel;

        kernel_file
            .seek(SeekFrom::Start(0))
            .expect("Could not seek kernel to begining");
        let mut buffer = Vec::new();
        kernel_file
            .read_to_end(&mut buffer)
            .expect("Failed to read kernel content");

        self.image_hasher.write(&buffer[..]).unwrap();
        self.bootstrap_hasher.write(&buffer[..]).unwrap();
        eif_file
            .write_all(&buffer[..])
            .expect("Failed to write kernel data");
    }

    pub fn write_cmdline(&mut self, eif_file: &mut File) {
        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionCmdline,
            flags: 0,
            section_size: self.cmdline_size(),
        };

        eif_file
            .seek(SeekFrom::Start(self.cmdline_offset()))
            .expect(
                "Could not seek while writing
        cmdline section",
            );
        let eif_buffer = unsafe {
            slice::from_raw_parts(
                &eif_section as *const EifSectionHeader as *const u8,
                std::mem::size_of::<EifSectionHeader>(),
            )
        };
        self.image_hasher.write(eif_buffer).unwrap();
        self.bootstrap_hasher.write(eif_buffer).unwrap();
        eif_file
            .write_all(eif_buffer)
            .expect("Failed to write cmdline header");

        self.image_hasher.write(&self.cmdline[..]).unwrap();
        self.bootstrap_hasher.write(&self.cmdline[..]).unwrap();
        eif_file
            .write_all(&self.cmdline[..])
            .expect("Failed write cmdline header");
    }

    pub fn write_ramdisks(&mut self, eif_file: &mut File) {
        for (index, mut ramdisk) in (&self.ramdisks).iter().enumerate() {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionRamdisk,
                flags: 0,
                section_size: self.ramdisk_size(&ramdisk),
            };

            eif_file
                .seek(SeekFrom::Start(self.ramdisk_offset(index)))
                .expect(
                    "Could not seek while writing
        kernel section",
                );
            let eif_buffer = unsafe {
                slice::from_raw_parts(
                    &eif_section as *const EifSectionHeader as *const u8,
                    std::mem::size_of::<EifSectionHeader>(),
                )
            };

            eif_file
                .write_all(eif_buffer)
                .expect("Failed to write section header");
            self.image_hasher.write(&eif_buffer[..]).unwrap();
            // The first ramdisk is provided by amazon and it contains the
            // code to bootstrap the docker container
            if index == 0 {
                self.bootstrap_hasher.write(&eif_buffer[..]).unwrap();
            } else {
                self.customer_app_hasher.write(&eif_buffer[..]).unwrap();
            }

            ramdisk
                .seek(SeekFrom::Start(0))
                .expect("Could not seek kernel to begining");
            let mut buffer = Vec::new();
            ramdisk
                .read_to_end(&mut buffer)
                .expect("Failed to read kernel content");
            self.image_hasher.write(&buffer[..]).unwrap();
            if index == 0 {
                self.bootstrap_hasher.write(&buffer[..]).unwrap();
            } else {
                self.customer_app_hasher.write(&buffer[..]).unwrap();
            }
            eif_file
                .write_all(&buffer[..])
                .expect("Failed to write kernel data");
        }
    }

    pub fn write_to(&mut self, output_file: &mut File) {
        self.compute_crc();
        self.write_header(output_file);
        self.write_kernel(output_file);
        self.write_cmdline(output_file);
        self.write_ramdisks(output_file);
    }

    pub fn boot_measurement(mut self) -> BTreeMap<String, String> {
        let mut measurements = BTreeMap::new();
        let image_hasher = hex::encode(
            self.image_hasher
                .tpm_extend_result_reset()
                .expect("Could not get result for image_hasher"),
        );
        let bootstrap_hasher = hex::encode(
            self.bootstrap_hasher
                .tpm_extend_result_reset()
                .expect("Could not get result for bootstrap_hasher"),
        );
        let app_hash = hex::encode(
            self.customer_app_hasher
                .tpm_extend_result_reset()
                .expect("Could not get result for app_hasher"),
        );
        measurements.insert(
            "HashAlgorithm".to_string(),
            format!("{:?}", self.hasher_template),
        );
        measurements.insert("PCR0".to_string(), image_hasher);
        measurements.insert("PCR1".to_string(), bootstrap_hasher);
        measurements.insert("PCR2".to_string(), app_hash);

        measurements
    }
}
