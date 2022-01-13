// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
use aws_nitro_enclaves_cose::{header_map::HeaderMap, CoseSign1};
use crc::{crc32, Hasher32};
use eif_defs::eif_hasher::EifHasher;
use eif_defs::{
    EifHeader, EifSectionHeader, EifSectionType, PcrInfo, PcrSignature, EIF_MAGIC, MAX_NUM_SECTIONS,
};
use openssl::asn1::Asn1Time;
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use sha2::{Digest, Sha384};
use std::cmp::Ordering;
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

pub const DEFAULT_SECTIONS_COUNT: u16 = 2;

#[derive(Clone, Debug)]
pub struct SignEnclaveInfo {
    pub signing_certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl SignEnclaveInfo {
    pub fn new(cert_path: &str, key_path: &str) -> Result<Self, String> {
        let mut certificate_file = File::open(cert_path)
            .map_err(|err| format!("Could not open the certificate file: {:?}", err))?;
        let mut signing_certificate = Vec::new();
        certificate_file
            .read_to_end(&mut signing_certificate)
            .map_err(|err| format!("Could not read the certificate file: {:?}", err))?;

        let mut key_file = File::open(key_path)
            .map_err(|err| format!("Could not open the key file: {:?}", err))?;
        let mut private_key = Vec::new();
        key_file
            .read_to_end(&mut private_key)
            .map_err(|err| format!("Could not read the key file: {:?}", err))?;

        Ok(SignEnclaveInfo {
            signing_certificate,
            private_key,
        })
    }
}

/// Utility function to calculate PCRs, used at build and describe.
pub fn get_pcrs<T: Digest + Debug + Write + Clone>(
    image_hasher: &mut EifHasher<T>,
    bootstrap_hasher: &mut EifHasher<T>,
    app_hasher: &mut EifHasher<T>,
    cert_hasher: &mut EifHasher<T>,
    hasher: T,
    is_signed: bool,
) -> Result<BTreeMap<String, String>, String> {
    let mut measurements = BTreeMap::new();
    let image_hasher = hex::encode(
        image_hasher
            .tpm_extend_finalize_reset()
            .map_err(|e| format!("Could not get result for image_hasher: {:?}", e))?,
    );
    let bootstrap_hasher = hex::encode(
        bootstrap_hasher
            .tpm_extend_finalize_reset()
            .map_err(|e| format!("Could not get result for bootstrap_hasher: {:?}", e))?,
    );
    let app_hash = hex::encode(
        app_hasher
            .tpm_extend_finalize_reset()
            .map_err(|e| format!("Could not get result for app_hasher: {:?}", e))?,
    );

    // Hash certificate only if signing key is set, otherwise related PCR will be zero
    let cert_hash = if is_signed {
        Some(hex::encode(
            cert_hasher
                .tpm_extend_finalize_reset()
                .map_err(|e| format!("Could not get result for cert_hash: {:?}", e))?,
        ))
    } else {
        None
    };

    measurements.insert("HashAlgorithm".to_string(), format!("{:?}", hasher));
    measurements.insert("PCR0".to_string(), image_hasher);
    measurements.insert("PCR1".to_string(), bootstrap_hasher);
    measurements.insert("PCR2".to_string(), app_hash);
    if let Some(cert_hash) = cert_hash {
        measurements.insert("PCR8".to_string(), cert_hash);
    }

    Ok(measurements)
}

pub struct EifBuilder<T: Digest + Debug + Write + Clone> {
    kernel: File,
    cmdline: Vec<u8>,
    ramdisks: Vec<File>,
    sign_info: Option<SignEnclaveInfo>,
    signature: Option<Vec<u8>>,
    signature_size: u64,
    eif_hdr_flags: u16,
    default_mem: u64,
    default_cpus: u64,
    /// Hash of the whole EifImage.
    pub image_hasher: EifHasher<T>,
    /// Hash of the EifSections provided by Amazon
    /// Kernel + cmdline + First Ramdisk
    pub bootstrap_hasher: EifHasher<T>,
    /// Hash of the remaining ramdisks.
    pub customer_app_hasher: EifHasher<T>,
    /// Hash the signing certificate
    pub certificate_hasher: EifHasher<T>,
    hasher_template: T,
    eif_crc: crc32::Digest,
}

impl<T: Digest + Debug + Write + Clone> EifBuilder<T> {
    pub fn new(
        kernel_path: &Path,
        cmdline: String,
        sign_info: Option<SignEnclaveInfo>,
        hasher: T,
        flags: u16,
    ) -> Self {
        let kernel_file = File::open(kernel_path).expect("Invalid kernel path");
        let cmdline = CString::new(cmdline).expect("Invalid cmdline");
        EifBuilder {
            kernel: kernel_file,
            cmdline: cmdline.into_bytes(),
            ramdisks: Vec::new(),
            sign_info,
            signature: None,
            signature_size: 0,
            eif_hdr_flags: flags,
            default_mem: 1024 * 1024 * 1024,
            default_cpus: 2,
            image_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create image_hasher"),
            bootstrap_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create bootstrap_hasher"),
            customer_app_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create customer app hasher"),
            certificate_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create certificate hasher"),
            hasher_template: hasher,
            eif_crc: crc32::Digest::new_with_initial(crc32::IEEE, 0),
        }
    }

    pub fn is_signed(&mut self) -> bool {
        self.sign_info.is_some()
    }

    pub fn add_ramdisk(&mut self, ramdisk_path: &Path) {
        let ramdisk_file = File::open(ramdisk_path).expect("Invalid ramdisk path");
        self.ramdisks.push(ramdisk_file);
    }

    /// The first two sections are the kernel and the cmdline.
    fn num_sections(&self) -> u16 {
        DEFAULT_SECTIONS_COUNT + self.ramdisks.len() as u16 + self.sign_info.iter().count() as u16
    }

    fn sections_offsets(&self) -> [u64; MAX_NUM_SECTIONS] {
        let mut result = [0; MAX_NUM_SECTIONS];
        result[0] = self.kernel_offset();
        result[1] = self.cmdline_offset();

        for i in 0..self.ramdisks.len() {
            result[i + DEFAULT_SECTIONS_COUNT as usize] = self.ramdisk_offset(i);
        }

        if self.sign_info.is_some() {
            result[DEFAULT_SECTIONS_COUNT as usize + self.ramdisks.len()] = self.signature_offset();
        }

        result
    }

    fn sections_sizes(&self) -> [u64; MAX_NUM_SECTIONS] {
        let mut result = [0; MAX_NUM_SECTIONS];

        result[0] = self.kernel_size();
        result[1] = self.cmdline_size();

        for i in 0..self.ramdisks.len() {
            result[i + DEFAULT_SECTIONS_COUNT as usize] = self.ramdisk_size(&self.ramdisks[i]);
        }

        if self.sign_info.is_some() {
            result[DEFAULT_SECTIONS_COUNT as usize + self.ramdisks.len()] = self.signature_size();
        }

        result
    }

    fn eif_header_offset(&self) -> u64 {
        0
    }

    fn kernel_offset(&self) -> u64 {
        self.eif_header_offset() + EifHeader::size() as u64
    }

    fn kernel_size(&self) -> u64 {
        self.kernel.metadata().unwrap().len() as u64
    }

    fn cmdline_offset(&self) -> u64 {
        self.kernel_offset() + EifSectionHeader::size() as u64 + self.kernel_size()
    }

    fn cmdline_size(&self) -> u64 {
        self.cmdline.len() as u64
    }

    fn ramdisk_offset(&self, index: usize) -> u64 {
        self.cmdline_offset()
            + self.cmdline_size()
            + EifSectionHeader::size() as u64
            + self.ramdisks[0..index]
                .iter()
                .fold(0, |mut total_len, file| {
                    total_len += file.metadata().expect("Invalid ramdisk metadata").len()
                        + EifSectionHeader::size() as u64;
                    total_len
                })
    }

    fn ramdisk_size(&self, ramdisk: &File) -> u64 {
        ramdisk.metadata().unwrap().len() as u64
    }

    fn signature_offset(&self) -> u64 {
        let index = self.ramdisks.len() - 1;
        self.ramdisk_offset(index)
            + EifSectionHeader::size() as u64
            + self.ramdisk_size(&self.ramdisks[index])
    }

    fn signature_size(&self) -> u64 {
        self.signature_size
    }

    /// Generate the signature of a certain PCR.
    fn generate_pcr_signature(
        &mut self,
        register_index: i32,
        register_value: Vec<u8>,
    ) -> PcrSignature {
        let sign_info = self.sign_info.as_ref().unwrap();
        let signing_certificate = sign_info.signing_certificate.clone();
        let pcr_info = PcrInfo::new(register_index, register_value);

        let payload = to_vec(&pcr_info).expect("Could not serialize PCR info");
        let private_key = PKey::private_key_from_pem(&sign_info.private_key)
            .expect("Could not deserialize the PEM-formatted private key");

        let signature = CoseSign1::new(&payload, &HeaderMap::new(), private_key.as_ref())
            .unwrap()
            .as_bytes(false)
            .unwrap();

        PcrSignature {
            signing_certificate,
            signature,
        }
    }

    /// Generate the signature of the EIF.
    /// eif_signature = [pcr0_signature]
    fn generate_eif_signature(&mut self, measurements: &BTreeMap<String, String>) {
        let pcr0_index = 0;
        let pcr0_value = hex::decode(measurements.get("PCR0").unwrap()).unwrap();
        let pcr0_signature = self.generate_pcr_signature(pcr0_index, pcr0_value);

        let eif_signature = vec![pcr0_signature];
        let serialized_signature =
            to_vec(&eif_signature).expect("Could not serialize the signature");
        self.signature_size = serialized_signature.len() as u64;
        self.signature = Some(serialized_signature)
    }

    pub fn header(&mut self) -> EifHeader {
        EifHeader {
            magic: EIF_MAGIC,
            version: eif_defs::CURRENT_VERSION,
            flags: self.eif_hdr_flags,
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

    /// Compute the crc for the whole enclave image, excluding the
    /// eif_crc32 field from the EIF header.
    pub fn compute_crc(&mut self) {
        let eif_header = self.header();
        let eif_buffer = eif_header.to_be_bytes();
        // The last field of the EifHeader is the CRC itself, so we need
        // to exclude it from contributing to the CRC.
        let len_without_crc = eif_buffer.len() - size_of::<u32>();
        self.eif_crc.write(&eif_buffer[..len_without_crc]);

        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionKernel,
            flags: 0,
            section_size: self.kernel_size(),
        };

        let eif_buffer = eif_section.to_be_bytes();
        self.eif_crc.write(&eif_buffer[..]);
        let mut kernel_file = &self.kernel;

        kernel_file
            .seek(SeekFrom::Start(0))
            .expect("Could not seek kernel to beginning");
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

        let eif_buffer = eif_section.to_be_bytes();
        self.eif_crc.write(&eif_buffer[..]);
        self.eif_crc.write(&self.cmdline[..]);

        for mut ramdisk in &self.ramdisks {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionRamdisk,
                flags: 0,
                section_size: self.ramdisk_size(ramdisk),
            };

            let eif_buffer = eif_section.to_be_bytes();
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

        if let Some(signature) = &self.signature {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionSignature,
                flags: 0,
                section_size: self.signature_size(),
            };

            let eif_buffer = eif_section.to_be_bytes();
            self.eif_crc.write(&eif_buffer[..]);
            self.eif_crc.write(&signature[..]);
        }
    }

    pub fn write_header(&mut self, file: &mut File) {
        let eif_header = self.header();
        file.seek(SeekFrom::Start(self.eif_header_offset())).expect(
            "Could not seek while writing eif \
             header",
        );
        let eif_buffer = eif_header.to_be_bytes();
        file.write_all(&eif_buffer[..])
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
        let eif_buffer = eif_section.to_be_bytes();
        eif_file
            .write_all(&eif_buffer[..])
            .expect("Failed to write kernel header");
        let mut kernel_file = &self.kernel;

        kernel_file
            .seek(SeekFrom::Start(0))
            .expect("Could not seek kernel to begining");
        let mut buffer = Vec::new();
        kernel_file
            .read_to_end(&mut buffer)
            .expect("Failed to read kernel content");

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
        let eif_buffer = eif_section.to_be_bytes();
        eif_file
            .write_all(&eif_buffer[..])
            .expect("Failed to write cmdline header");

        eif_file
            .write_all(&self.cmdline[..])
            .expect("Failed write cmdline header");
    }

    pub fn write_ramdisks(&mut self, eif_file: &mut File) {
        for (index, mut ramdisk) in (&self.ramdisks).iter().enumerate() {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionRamdisk,
                flags: 0,
                section_size: self.ramdisk_size(ramdisk),
            };

            eif_file
                .seek(SeekFrom::Start(self.ramdisk_offset(index)))
                .expect(
                    "Could not seek while writing
        kernel section",
                );
            let eif_buffer = eif_section.to_be_bytes();
            eif_file
                .write_all(&eif_buffer[..])
                .expect("Failed to write section header");

            ramdisk
                .seek(SeekFrom::Start(0))
                .expect("Could not seek ramdisk to beginning");
            let mut buffer = Vec::new();
            ramdisk
                .read_to_end(&mut buffer)
                .expect("Failed to read ramdisk content");
            eif_file
                .write_all(&buffer[..])
                .expect("Failed to write ramdisk data");
        }
    }

    pub fn write_signature(&mut self, eif_file: &mut File) {
        if let Some(signature) = &self.signature {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionSignature,
                flags: 0,
                section_size: self.signature_size(),
            };

            eif_file
                .seek(SeekFrom::Start(self.signature_offset()))
                .expect("Could not seek while writing signature section");
            let eif_buffer = eif_section.to_be_bytes();
            eif_file
                .write_all(&eif_buffer[..])
                .expect("Failed to write signature header");

            eif_file
                .write_all(&signature[..])
                .expect("Failed write signature header");
        }
    }

    pub fn write_to(&mut self, output_file: &mut File) -> BTreeMap<String, String> {
        self.measure();
        let measurements = get_pcrs(
            &mut self.image_hasher,
            &mut self.bootstrap_hasher,
            &mut self.customer_app_hasher,
            &mut self.certificate_hasher,
            self.hasher_template.clone(),
            self.sign_info.is_some(),
        )
        .expect("Failed to get measurements");
        if self.sign_info.is_some() {
            self.generate_eif_signature(&measurements);
        }
        self.compute_crc();
        self.write_header(output_file);
        self.write_kernel(output_file);
        self.write_cmdline(output_file);
        self.write_ramdisks(output_file);
        self.write_signature(output_file);
        measurements
    }

    pub fn measure(&mut self) {
        let mut kernel_file = &self.kernel;
        kernel_file
            .seek(SeekFrom::Start(0))
            .expect("Could not seek kernel to beginning");
        let mut buffer = Vec::new();
        kernel_file
            .read_to_end(&mut buffer)
            .expect("Failed to read kernel content");
        self.image_hasher.write_all(&buffer[..]).unwrap();
        self.bootstrap_hasher.write_all(&buffer[..]).unwrap();

        self.image_hasher.write_all(&self.cmdline[..]).unwrap();
        self.bootstrap_hasher.write_all(&self.cmdline[..]).unwrap();

        for (index, mut ramdisk) in (&self.ramdisks).iter().enumerate() {
            ramdisk
                .seek(SeekFrom::Start(0))
                .expect("Could not seek kernel to beginning");
            let mut buffer = Vec::new();
            ramdisk
                .read_to_end(&mut buffer)
                .expect("Failed to read kernel content");
            self.image_hasher.write_all(&buffer[..]).unwrap();
            // The first ramdisk is provided by amazon and it contains the
            // code to bootstrap the docker container.
            if index == 0 {
                self.bootstrap_hasher.write_all(&buffer[..]).unwrap();
            } else {
                self.customer_app_hasher.write_all(&buffer[..]).unwrap();
            }
        }

        if let Some(sign_info) = self.sign_info.as_ref() {
            let cert = openssl::x509::X509::from_pem(&sign_info.signing_certificate[..]).unwrap();
            let cert_der = cert.to_der().unwrap();
            // This is equivalent to extend(cert.digest(sha384)), since hasher is going to
            // hash the DER certificate (cert.digest()) and then tpm_extend_finalize_reset
            // will do the extend.
            self.certificate_hasher.write_all(&cert_der).unwrap();
        }
    }
}

/// The information about the signing certificate to be provided for a `describe-eif` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignCertificateInfo {
    #[serde(rename = "IssuerName")]
    /// Certificate's subject name.
    pub issuer_name: BTreeMap<String, String>,
    #[serde(rename = "Algorithm")]
    /// Certificate's signature algorithm
    pub algorithm: String,
    #[serde(rename = "NotBefore")]
    /// Not before validity period
    pub not_before: String,
    #[serde(rename = "NotAfter")]
    /// Not after validity period
    pub not_after: String,
    #[serde(rename = "Signature")]
    /// Certificate's signature in hex format: 'XX:XX:XX..'
    pub signature: String,
}

impl SignCertificateInfo {
    /// Create new signing certificate information structure
    pub fn new(
        issuer_name: BTreeMap<String, String>,
        algorithm: String,
        not_before: String,
        not_after: String,
        signature: String,
    ) -> Self {
        SignCertificateInfo {
            issuer_name,
            algorithm,
            not_before,
            not_after,
            signature,
        }
    }
}

/// PCR Signature verifier that checks the validity of
/// the certificate used to sign the enclave
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcrSignatureChecker {
    signing_certificate: Vec<u8>,
    signature: Vec<u8>,
}

impl PcrSignatureChecker {
    pub fn new(pcr_signature: &PcrSignature) -> Self {
        PcrSignatureChecker {
            signing_certificate: pcr_signature.signing_certificate.clone(),
            signature: pcr_signature.signature.clone(),
        }
    }

    /// Reads EIF section headers and looks for a signature.
    /// Seek to the signature section, if present, and save the certificate and signature
    pub fn from_eif(eif_path: &str) -> Result<Self, String> {
        let mut signing_certificate = Vec::new();
        let mut signature = Vec::new();

        let mut curr_seek = 0;
        let mut eif_file =
            File::open(eif_path).map_err(|e| format!("Failed to open the EIF file: {:?}", e))?;

        // Skip header
        let mut header_buf = vec![0u8; EifHeader::size()];
        eif_file
            .read_exact(&mut header_buf)
            .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;

        curr_seek += EifHeader::size();
        eif_file
            .seek(SeekFrom::Start(curr_seek as u64))
            .map_err(|e| format!("Failed to seek file from start: {:?}", e))?;

        let mut section_buf = vec![0u8; EifSectionHeader::size()];

        // Read all section headers and skip if different from signature section
        while eif_file.read_exact(&mut section_buf).is_ok() {
            let section = EifSectionHeader::from_be_bytes(&section_buf)
                .map_err(|e| format!("Error extracting EIF section header: {:?}", e))?;
            curr_seek += EifSectionHeader::size();

            if section.section_type == EifSectionType::EifSectionSignature {
                let mut buf = vec![0u8; section.section_size as usize];
                eif_file
                    .seek(SeekFrom::Start(curr_seek as u64))
                    .map_err(|e| format!("Failed to seek after EIF section header: {:?}", e))?;
                eif_file.read_exact(&mut buf).map_err(|e| {
                    format!("Error while reading signature section from EIF: {:?}", e)
                })?;

                // Deserialize PCR signature structure and save certificate and signature
                let des_sign: Vec<PcrSignature> = from_slice(&buf[..])
                    .map_err(|e| format!("Error deserializing certificate: {:?}", e))?;

                signing_certificate = des_sign[0].signing_certificate.clone();
                signature = des_sign[0].signature.clone();
            }

            curr_seek += section.section_size as usize;
            eif_file
                .seek(SeekFrom::Start(curr_seek as u64))
                .map_err(|e| format!("Failed to seek after EIF section: {:?}", e))?;
        }

        Ok(Self {
            signing_certificate,
            signature,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.signing_certificate.len() == 0 && self.signature.len() == 0
    }

    /// Verifies the validity of the signing certificate
    pub fn verify(&mut self) -> Result<(), String> {
        let signature = CoseSign1::from_bytes(&self.signature[..])
            .map_err(|err| format!("Could not deserialize the signature: {:?}", err))?;
        let cert = openssl::x509::X509::from_pem(&self.signing_certificate[..])
            .map_err(|_| "Could not deserialize the signing certificate".to_string())?;
        let public_key = cert
            .public_key()
            .map_err(|_| "Could not get the public key from the signing certificate".to_string())?;

        // Verify the signature
        let result = signature
            .verify_signature(public_key.as_ref())
            .map_err(|err| format!("Could not verify EIF signature: {:?}", err))?;
        if !result {
            return Err("The EIF signature is not valid".to_string());
        }

        // Verify that the signing certificate is not expired
        let current_time = Asn1Time::days_from_now(0).map_err(|err| err.to_string())?;
        if current_time
            .compare(cert.not_after())
            .map_err(|err| err.to_string())?
            == Ordering::Greater
            || current_time
                .compare(cert.not_before())
                .map_err(|err| err.to_string())?
                == Ordering::Less
        {
            return Err("The signing certificate is expired".to_string());
        }

        Ok(())
    }
}

/// Used for providing EIF info when requested by
/// 'describe-eif' or 'describe-enclaves' commands
pub struct EifReader {
    /// Deserialized EIF header
    pub header: EifHeader,
    /// Serialized signature section
    pub signature_section: Option<Vec<u8>>,
    /// Hash of the whole EifImage.
    pub image_hasher: EifHasher<Sha384>,
    /// Hash of the EifSections provided by Amazon
    /// Kernel + cmdline + First Ramdisk
    pub bootstrap_hasher: EifHasher<Sha384>,
    /// Hash of the remaining ramdisks.
    pub app_hasher: EifHasher<Sha384>,
    /// Hash the signing certificate
    pub cert_hasher: EifHasher<Sha384>,
}

impl EifReader {
    /// Reads EIF and extracts section to be written in the hashers
    pub fn from_eif(eif_path: String) -> Result<Self, String> {
        let mut curr_seek = 0;
        let mut eif_file =
            File::open(eif_path).map_err(|e| format!("Failed to open the EIF file: {:?}", e))?;

        // Extract EIF header
        let mut header_buf = vec![0u8; EifHeader::size()];
        eif_file
            .read_exact(&mut header_buf)
            .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;
        let header = EifHeader::from_be_bytes(&header_buf)
            .map_err(|e| format!("Error while parsing EIF header: {:?}", e))?;

        curr_seek += EifHeader::size();
        eif_file
            .seek(SeekFrom::Start(curr_seek as u64))
            .map_err(|e| format!("Failed to seek file from start: {:?}", e))?;

        let mut section_buf = vec![0u8; EifSectionHeader::size()];
        let mut image_hasher = EifHasher::new_without_cache(Sha384::new())
            .map_err(|e| format!("Could not create image_hasher: {:?}", e))?;
        let mut bootstrap_hasher = EifHasher::new_without_cache(Sha384::new())
            .map_err(|e| format!("Could not create bootstrap_hasher: {:?}", e))?;
        let mut app_hasher = EifHasher::new_without_cache(Sha384::new())
            .map_err(|e| format!("Could not create app_hasher: {:?}", e))?;
        let mut cert_hasher = EifHasher::new_without_cache(Sha384::new())
            .map_err(|e| format!("Could not create cert_hasher: {:?}", e))?;
        let mut ramdisk_idx = 0;
        let mut signature_section = None;

        // Read all section headers and treat by type
        while eif_file
            .read_exact(&mut section_buf)
            .map_err(|e| format!("Error while reading EIF header: {:?}", e))
            .is_ok()
        {
            let section = EifSectionHeader::from_be_bytes(&section_buf)
                .map_err(|e| format!("Error extracting EIF section header: {:?}", e))?;

            let mut buf = vec![0u8; section.section_size as usize];
            curr_seek += EifSectionHeader::size();
            eif_file
                .seek(SeekFrom::Start(curr_seek as u64))
                .map_err(|e| format!("Failed to seek after EIF header: {:?}", e))?;
            eif_file
                .read_exact(&mut buf)
                .map_err(|e| format!("Error while reading kernel from EIF: {:?}", e))?;
            curr_seek += section.section_size as usize;
            eif_file
                .seek(SeekFrom::Start(curr_seek as u64))
                .map_err(|e| format!("Failed to seek after EIF section: {:?}", e))?;

            match section.section_type {
                EifSectionType::EifSectionKernel | EifSectionType::EifSectionCmdline => {
                    image_hasher.write_all(&buf).map_err(|e| {
                        format!("Failed to write EIF section to image_hasher: {:?}", e)
                    })?;
                    bootstrap_hasher.write_all(&buf).map_err(|e| {
                        format!("Failed to write EIF section to bootstrap_hasher: {:?}", e)
                    })?;
                }
                EifSectionType::EifSectionRamdisk => {
                    image_hasher.write_all(&buf).map_err(|e| {
                        format!("Failed to write ramdisk section to image_hasher: {:?}", e)
                    })?;
                    if ramdisk_idx == 0 {
                        bootstrap_hasher.write_all(&buf).map_err(|e| {
                            format!(
                                "Failed to write ramdisk section to bootstrap_hasher: {:?}",
                                e
                            )
                        })?;
                    } else {
                        app_hasher.write_all(&buf).map_err(|e| {
                            format!("Failed to write ramdisk section to app_hasher: {:?}", e)
                        })?;
                    }
                    ramdisk_idx += 1;
                }
                EifSectionType::EifSectionSignature => {
                    signature_section = Some(buf.clone());
                    // Deserialize PCR0 signature structure and write it to the hasher
                    let des_sign: Vec<PcrSignature> = from_slice(&buf[..])
                        .map_err(|e| format!("Error deserializing certificate: {:?}", e))?;

                    let cert = openssl::x509::X509::from_pem(&des_sign[0].signing_certificate)
                        .map_err(|e| format!("Error while digesting certificate: {:?}", e))?;
                    let cert_der = cert.to_der().map_err(|e| {
                        format!("Failed to deserialize signing certificate: {:?}", e)
                    })?;
                    cert_hasher.write_all(&cert_der).map_err(|e| {
                        format!("Failed to write signature section to cert_hasher: {:?}", e)
                    })?;
                }
                EifSectionType::EifSectionInvalid | EifSectionType::EifSectionMetadata => {
                    return Err("Eif contains an invalid section".to_string());
                }
            }
        }

        Ok(EifReader {
            header,
            signature_section,
            image_hasher,
            bootstrap_hasher,
            app_hasher,
            cert_hasher,
        })
    }

    /// Returns deserialized header section
    pub fn get_header(&self) -> EifHeader {
        self.header
    }

    /// Extract signature section from EIF and parse the signing certificate
    pub fn get_certificate_info(&self) -> Result<SignCertificateInfo, String> {
        let signature_buf = match &self.signature_section {
            Some(section) => section,
            None => {
                return Err("Signature section missing from EIF.".to_string());
            }
        };
        // Deserialize PCR0 signature structure and write it to the hasher
        let des_sign: Vec<PcrSignature> = from_slice(&signature_buf[..])
            .map_err(|e| format!("Error deserializing certificate: {:?}", e))?;

        let cert = openssl::x509::X509::from_pem(&des_sign[0].signing_certificate)
            .map_err(|e| format!("Error while digesting certificate: {:?}", e))?;

        // Parse issuer into a BTreeMap
        let mut issuer_name = BTreeMap::new();
        for (_, e) in cert.issuer_name().entries().enumerate() {
            issuer_name.insert(
                e.object().to_string(),
                format!("{:?}", e.data()).replace(&['\"'][..], ""),
            );
        }

        return Ok(SignCertificateInfo {
            issuer_name,
            algorithm: format!("{:#?}", cert.signature_algorithm().object()),
            not_before: format!("{:#?}", cert.not_before()),
            not_after: format!("{:#?}", cert.not_after()),
            // Change format from [\  XX, \  X, ..] to XX:XX:XX...
            signature: format!("{:02X?}", cert.signature().as_slice().to_vec())
                .replace(&vec!['[', ']'][..], "")
                .replace(", ", ":"),
        });
    }
}
