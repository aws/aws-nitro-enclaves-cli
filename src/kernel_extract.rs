// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

//! Module for extracting kernel binaries and modules from RPM packages.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::read::GzDecoder;

use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::new_nitro_cli_failure;

/// Kernel config options we care about
const REQUIRED_CONFIG_OPTIONS: &[&str] = &[
    "CONFIG_NSM",
    "CONFIG_VIRTIO_VSOCKETS",
    "CONFIG_VIRTIO_MMIO",
    "CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES",
];

/// Module names corresponding to config options (when built as modules)
const CONFIG_TO_MODULE: &[(&str, &str)] = &[
    ("CONFIG_NSM", "nsm"),
    ("CONFIG_VIRTIO_VSOCKETS", "vmw_vsock_virtio_transport"),
    ("CONFIG_VIRTIO_MMIO", "virtio_mmio"),
];

/// Config option value
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    /// Built-in (=y)
    BuiltIn,
    /// Module (=m)
    Module,
    /// Not set
    NotSet,
}

/// Information about extracted kernel
#[derive(Debug)]
pub struct KernelExtractInfo {
    /// Path to kernel image (bzImage or Image)
    pub kernel_image: PathBuf,
    /// Path to kernel config
    pub kernel_config: PathBuf,
    /// List of extracted modules with their dependencies
    pub modules: Vec<ModuleInfo>,
    /// Path to modules manifest file
    pub modules_manifest: PathBuf,
}

/// Information about a kernel module
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module name
    pub name: String,
    /// Path to the .ko file
    pub path: PathBuf,
    /// Dependencies (other module names)
    pub dependencies: Vec<String>,
}

/// Parse kernel config file and return config values
fn parse_kernel_config(config_path: &Path) -> NitroCliResult<HashMap<String, ConfigValue>> {
    let file = File::open(config_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to open kernel config: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    let reader = BufReader::new(file);
    let mut config = HashMap::new();

    for line in reader.lines() {
        let line = line.map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read config line: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

        let line = line.trim();

        // Check for "# CONFIG_XXX is not set"
        if line.starts_with("# ") && line.ends_with(" is not set") {
            let config_name = line
                .trim_start_matches("# ")
                .trim_end_matches(" is not set");
            if REQUIRED_CONFIG_OPTIONS.contains(&config_name) {
                config.insert(config_name.to_string(), ConfigValue::NotSet);
            }
            continue;
        }

        // Check for CONFIG_XXX=y or CONFIG_XXX=m
        if let Some((key, value)) = line.split_once('=') {
            if REQUIRED_CONFIG_OPTIONS.contains(&key) {
                let config_value = match value {
                    "y" => ConfigValue::BuiltIn,
                    "m" => ConfigValue::Module,
                    _ => ConfigValue::NotSet,
                };
                config.insert(key.to_string(), config_value);
            }
        }
    }

    Ok(config)
}

/// Get module dependencies using modinfo command
fn get_module_deps_from_modinfo(module_path: &Path) -> Vec<String> {
    let output = Command::new("modinfo")
        .arg("-F")
        .arg("depends")
        .arg(module_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let deps_str = String::from_utf8_lossy(&output.stdout);
            deps_str
                .trim()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect()
        }
        _ => vec![],
    }
}

/// Find module path by name in the modules directory
fn find_module_path(modules_dir: &Path, module_name: &str) -> Option<PathBuf> {
    let ko_name = format!("{}.ko", module_name);
    let ko_xz_name = format!("{}.ko.xz", module_name);
    let ko_zst_name = format!("{}.ko.zst", module_name);

    find_file_recursive(modules_dir, &ko_name)
        .or_else(|| find_file_recursive(modules_dir, &ko_xz_name))
        .or_else(|| find_file_recursive(modules_dir, &ko_zst_name))
}

/// Recursively find a file by name
fn find_file_recursive(dir: &Path, filename: &str) -> Option<PathBuf> {
    if !dir.is_dir() {
        return None;
    }

    for entry in fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(found) = find_file_recursive(&path, filename) {
                return Some(found);
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some(filename) {
            return Some(path);
        }
    }

    None
}

/// Extract the file payload of an RPM into `output_dir`.
///
/// The RPM is parsed and its cpio payload decompressed in-process (gzip, zstd,
/// or xz) so extraction does not depend on the host.
fn extract_rpm(rpm_path: &Path, output_dir: &Path) -> NitroCliResult<()> {
    fs::create_dir_all(output_dir).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create output directory: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    let package = rpm::Package::open(rpm_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to read RPM: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    let compressor = package.metadata.get_payload_compressor().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to read RPM payload compressor: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    let content = std::io::Cursor::new(package.content);

    // Decompress the cpio payload using the matching decoder.
    let payload: Box<dyn BufRead> = match compressor {
        rpm::CompressionType::None => Box::new(BufReader::new(content)),
        rpm::CompressionType::Gzip => Box::new(BufReader::new(GzDecoder::new(content))),
        rpm::CompressionType::Zstd => Box::new(BufReader::new(
            zstd::stream::read::Decoder::new(content).map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to init zstd decoder: {e}"),
                    NitroCliErrorEnum::FileOperationFailure
                )
            })?,
        )),
        rpm::CompressionType::Xz => Box::new(BufReader::new(xz2::read::XzDecoder::new(content))),
        other => {
            return Err(new_nitro_cli_failure!(
                &format!("Unsupported RPM payload compression: {other:?}"),
                NitroCliErrorEnum::FileOperationFailure
            ));
        }
    };

    extract_cpio_payload(payload, output_dir)
}

/// Read a `newc` cpio stream and materialise its regular files under `dest`.
fn extract_cpio_payload(mut reader: Box<dyn BufRead>, dest: &Path) -> NitroCliResult<()> {
    let cpio_err = |e: std::io::Error| {
        new_nitro_cli_failure!(
            &format!("Failed to read RPM cpio payload: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    };

    loop {
        let mut entry = cpio::newc::Reader::new(reader).map_err(cpio_err)?;
        if entry.entry().is_trailer() {
            break;
        }

        // Normalise
        let mode = entry.entry().mode();
        let name = entry.entry().name().to_string();
        let rel = Path::new(&name);
        let rel = rel
            .strip_prefix("./")
            .or_else(|_| rel.strip_prefix("/"))
            .unwrap_or(rel);
        let out_path = dest.join(rel);

        let is_regular = mode & 0o170000 == 0o100000;
        if is_regular {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to create directory: {e}"),
                        NitroCliErrorEnum::FileOperationFailure
                    )
                })?;
            }
            let mut out = File::create(&out_path).map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to write extracted file: {e}"),
                    NitroCliErrorEnum::FileOperationFailure
                )
            })?;
            std::io::copy(&mut entry, &mut out).map_err(cpio_err)?;
        }

        reader = entry.finish().map_err(cpio_err)?;
    }

    Ok(())
}

/// Find kernel image in extracted RPM
fn find_kernel_image(extract_dir: &Path, arch: &str) -> NitroCliResult<PathBuf> {
    let boot_dir = extract_dir.join("lib/modules");

    // Find the kernel version directory
    let version_dir = fs::read_dir(&boot_dir)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read modules directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_dir())
        .map(|e| e.path())
        .ok_or_else(|| {
            new_nitro_cli_failure!(
                "No kernel version directory found",
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

    // Kernel image is typically in vmlinuz or vmlinux
    let image_name = match arch {
        "x86_64" => "vmlinuz",
        "aarch64" => "vmlinuz",
        _ => "vmlinuz",
    };

    let image_path = version_dir.join(image_name);
    if image_path.exists() {
        return Ok(image_path);
    }

    // Try alternate locations
    let boot_vmlinuz = extract_dir.join("boot").join(format!(
        "vmlinuz-{}",
        version_dir.file_name().unwrap().to_str().unwrap()
    ));
    if boot_vmlinuz.exists() {
        return Ok(boot_vmlinuz);
    }

    Err(new_nitro_cli_failure!(
        &format!("Kernel image not found in {}", extract_dir.display()),
        NitroCliErrorEnum::FileOperationFailure
    ))
}

/// Find kernel config in extracted RPM
fn find_kernel_config(extract_dir: &Path) -> NitroCliResult<PathBuf> {
    let boot_dir = extract_dir.join("lib/modules");

    // Find the kernel version directory
    let version_dir = fs::read_dir(&boot_dir)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read modules directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_dir())
        .map(|e| e.path())
        .ok_or_else(|| {
            new_nitro_cli_failure!(
                "No kernel version directory found",
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

    let config_path = version_dir.join("config");
    if config_path.exists() {
        return Ok(config_path);
    }

    // Try /boot/config-VERSION
    let version_name = version_dir.file_name().unwrap().to_str().unwrap();
    let boot_config = extract_dir
        .join("boot")
        .join(format!("config-{}", version_name));
    if boot_config.exists() {
        return Ok(boot_config);
    }

    Err(new_nitro_cli_failure!(
        "Kernel config not found",
        NitroCliErrorEnum::FileOperationFailure
    ))
}

/// Find modules directory in extracted RPM
fn find_modules_dir(extract_dir: &Path) -> NitroCliResult<PathBuf> {
    let modules_base = extract_dir.join("lib/modules");

    // Find the kernel version directory
    let version_dir = fs::read_dir(&modules_base)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read modules directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_dir())
        .map(|e| e.path())
        .ok_or_else(|| {
            new_nitro_cli_failure!(
                "No kernel version directory found",
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

    Ok(version_dir)
}

/// Decompress a module file, if compressed
fn decompress_module(src: &Path, dest: &Path) -> NitroCliResult<()> {
    let src_name = src.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if src_name.ends_with(".ko.xz") {
        let compressed = File::open(src).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to open module: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
        let mut decoder = xz2::read::XzDecoder::new(compressed);
        write_decompressed_module(&mut decoder, dest, "xz")?;
    } else if src_name.ends_with(".ko.zst") {
        let compressed = File::open(src).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to open module: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
        let mut decoder = zstd::stream::read::Decoder::new(compressed).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to init zstd decoder: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
        write_decompressed_module(&mut decoder, dest, "zstd")?;
    } else {
        // Uncompressed: just copy.
        fs::copy(src, dest).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to copy module: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }

    Ok(())
}

/// Stream a decompressed module from `reader` into `dest`.
fn write_decompressed_module(
    reader: &mut impl Read,
    dest: &Path,
    kind: &str,
) -> NitroCliResult<()> {
    let mut out = File::create(dest).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write decompressed module: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    std::io::copy(reader, &mut out).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("{kind} decompression failed: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    Ok(())
}

/// arm64 `Image` magic within a raw kernel image
const ARM64_IMAGE_MAGIC_OFFSET: usize = 56;
const ARM64_IMAGE_MAGIC: &[u8; 4] = b"ARM\x64";

/// Size of the EFI zboot header up to and including the compression-type field
const ZBOOT_HEADER_MIN_SIZE: usize = 0x38;

/// Produce the raw arm64 `Image` expected by the enclave VMM
fn extract_arm64_image(src: &Path, dest: &Path) -> NitroCliResult<()> {
    let data = fs::read(src).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to read kernel image: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    // Copy raw arm64 Image through unchanged
    if has_arm64_image_magic(&data) {
        fs::write(dest, &data).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write kernel image: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
        return Ok(());
    }

    // EFI zboot header as per linux: drivers/firmware/efi/libstub/zboot-header.S
    //   0x00 u32       "MZ" PE/COFF stub magic ('M','Z')
    //   0x04 u32       "zimg" zboot magic
    //   0x08 u32       payload_offset (LE)
    //   0x0c u32       payload_size   (LE)
    //   0x10 u64       reserved
    //   0x18 [u8;32]   compression type, NUL-terminated ASCII ("gzip")
    if data.len() < ZBOOT_HEADER_MIN_SIZE || &data[4..8] != b"zimg" {
        return Err(new_nitro_cli_failure!(
            "Kernel image is neither a raw arm64 Image nor an EFI zboot image",
            NitroCliErrorEnum::FileOperationFailure
        ));
    }

    let payload_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let payload_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
    let comp_type: String = data[0x18..0x38]
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();

    let payload_end = payload_offset.checked_add(payload_size).ok_or_else(|| {
        new_nitro_cli_failure!(
            "EFI zboot payload bounds overflow",
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    if payload_end > data.len() {
        return Err(new_nitro_cli_failure!(
            &format!(
                "EFI zboot payload (offset {payload_offset}, size {payload_size}) \
                 exceeds image size {}",
                data.len()
            ),
            NitroCliErrorEnum::FileOperationFailure
        ));
    }
    let payload = &data[payload_offset..payload_end];

    eprintln!("Unwrapping EFI zboot image (compression: {comp_type})...");

    let image = decompress_zboot_payload(&comp_type, payload)?;

    // Ensure the decompressed payload is a valid raw arm64 Image
    if !has_arm64_image_magic(&image) {
        return Err(new_nitro_cli_failure!(
            "Decompressed zboot payload is not a valid arm64 Image (missing magic)",
            NitroCliErrorEnum::FileOperationFailure
        ));
    }

    fs::write(dest, &image).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write decompressed kernel image: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    Ok(())
}

/// Decompress an EFI zboot payload, where Amazon Linux builds its zboot kernels with gzip
fn decompress_zboot_payload(comp_type: &str, payload: &[u8]) -> NitroCliResult<Vec<u8>> {
    if comp_type != "gzip" {
        return Err(new_nitro_cli_failure!(
            &format!("Unsupported EFI zboot compression type: '{comp_type}' (supported: gzip)"),
            NitroCliErrorEnum::FileOperationFailure
        ));
    }

    let mut image = Vec::new();
    GzDecoder::new(payload)
        .read_to_end(&mut image)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to decompress gzip zboot payload: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

    Ok(image)
}

/// Check if the buffer carries the arm64 `Image` header magic
fn has_arm64_image_magic(data: &[u8]) -> bool {
    data.len() >= ARM64_IMAGE_MAGIC_OFFSET + 4
        && &data[ARM64_IMAGE_MAGIC_OFFSET..ARM64_IMAGE_MAGIC_OFFSET + 4] == ARM64_IMAGE_MAGIC
}

/// Extract kernel binaries and required modules from an RPM
pub fn extract_kernel_binaries(
    rpm_path: &Path,
    output_dir: &Path,
    arch: &str,
) -> NitroCliResult<KernelExtractInfo> {
    // Create output directory
    fs::create_dir_all(output_dir).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create output directory: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    // Create temp directory for extraction
    let temp_dir = output_dir.join("_extract_temp");
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to clean temp directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }

    eprintln!("Extracting RPM...");
    extract_rpm(rpm_path, &temp_dir)?;

    // Find kernel image
    eprintln!("Locating kernel image...");
    let kernel_image_src = find_kernel_image(&temp_dir, arch)?;
    let kernel_image_name = match arch {
        "x86_64" => "bzImage",
        "aarch64" => "Image",
        _ => "vmlinuz",
    };
    let kernel_image_dest = output_dir.join(kernel_image_name);
    if arch == "aarch64" {
        // Generic Amazon Linux aarch64 kernels ship as an EFI zboot
        // self-decompressing PE image (vmlinuz), whereas the enclave VMM expects
        // a raw arm64 `Image`. Unwrap the container before packaging.
        extract_arm64_image(&kernel_image_src, &kernel_image_dest)?;
    } else {
        fs::copy(&kernel_image_src, &kernel_image_dest).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to copy kernel image: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }
    eprintln!("  Kernel image: {}", kernel_image_dest.display());

    // Find and copy kernel config
    eprintln!("Locating kernel config...");
    let kernel_config_src = find_kernel_config(&temp_dir)?;
    let kernel_config_dest = output_dir.join("config");
    fs::copy(&kernel_config_src, &kernel_config_dest).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to copy kernel config: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    eprintln!("  Kernel config: {}", kernel_config_dest.display());

    // Parse kernel config to determine which modules we need
    eprintln!("Parsing kernel config...");
    let config = parse_kernel_config(&kernel_config_dest)?;

    // Report config status
    let mut modules_needed: Vec<String> = vec![];
    for option in REQUIRED_CONFIG_OPTIONS {
        let value = config.get(*option).unwrap_or(&ConfigValue::NotSet);
        let status = match value {
            ConfigValue::BuiltIn => "built-in (y)",
            ConfigValue::Module => "module (m)",
            ConfigValue::NotSet => "not set",
        };
        eprintln!("  {}: {}", option, status);

        if *value == ConfigValue::Module {
            // Find corresponding module name
            if let Some((_, module_name)) = CONFIG_TO_MODULE.iter().find(|(cfg, _)| cfg == option) {
                modules_needed.push(module_name.to_string());
            }
        }
    }

    // Find modules directory
    let modules_dir = find_modules_dir(&temp_dir)?;

    // Create modules output directory
    let modules_output_dir = output_dir.join("modules");
    if !modules_needed.is_empty() {
        fs::create_dir_all(&modules_output_dir).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to create modules directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }

    // Extract required modules and their dependencies using modinfo
    eprintln!("Extracting required modules...");
    let mut extracted_modules: Vec<ModuleInfo> = vec![];
    let mut modules_to_process: Vec<String> = modules_needed.clone();
    let mut processed_modules: HashSet<String> = HashSet::new();

    while let Some(module_name) = modules_to_process.pop() {
        if processed_modules.contains(&module_name) {
            continue;
        }
        processed_modules.insert(module_name.clone());

        if let Some(module_src) = find_module_path(&modules_dir, &module_name) {
            let module_dest = modules_output_dir.join(format!("{}.ko", module_name));
            decompress_module(&module_src, &module_dest)?;

            // Get dependencies using modinfo on the extracted module
            let dependencies = get_module_deps_from_modinfo(&module_dest);

            eprintln!("  {} (deps: {:?})", module_name, dependencies);

            // Add dependencies to processing queue
            for dep in &dependencies {
                if !processed_modules.contains(dep) {
                    modules_to_process.push(dep.clone());
                }
            }

            extracted_modules.push(ModuleInfo {
                name: module_name.clone(),
                path: module_dest,
                dependencies,
            });
        } else {
            eprintln!("  Warning: Module {} not found", module_name);
        }
    }

    // Sort modules by name for consistent output
    extracted_modules.sort_by(|a, b| a.name.cmp(&b.name));

    // Create modules manifest
    let manifest_path = output_dir.join("modules.txt");
    let mut manifest = File::create(&manifest_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create modules manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    writeln!(manifest, "# Kernel modules extracted for Nitro Enclaves").map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    writeln!(
        manifest,
        "# Format: module_name: dependency1, dependency2, ..."
    )
    .map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    writeln!(manifest).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    // Write config status
    writeln!(manifest, "# Config options:").map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    for option in REQUIRED_CONFIG_OPTIONS {
        let value = config.get(*option).unwrap_or(&ConfigValue::NotSet);
        let status = match value {
            ConfigValue::BuiltIn => "y (built-in)",
            ConfigValue::Module => "m (module)",
            ConfigValue::NotSet => "not set",
        };
        writeln!(manifest, "#   {}={}", option, status).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write manifest: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }
    writeln!(manifest).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    // Write modules and dependencies
    if extracted_modules.is_empty() {
        writeln!(
            manifest,
            "# No modules needed - all required features are built-in"
        )
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write manifest: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    } else {
        writeln!(manifest, "# Extracted modules:").map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write manifest: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
        for module in &extracted_modules {
            if module.dependencies.is_empty() {
                writeln!(manifest, "{}", module.name).map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to write manifest: {e}"),
                        NitroCliErrorEnum::FileOperationFailure
                    )
                })?;
            } else {
                writeln!(
                    manifest,
                    "{}: {}",
                    module.name,
                    module.dependencies.join(", ")
                )
                .map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to write manifest: {e}"),
                        NitroCliErrorEnum::FileOperationFailure
                    )
                })?;
            }
        }
    }

    // Clean up temp directory
    fs::remove_dir_all(&temp_dir).ok();

    eprintln!("\nExtraction complete:");
    eprintln!("  Kernel image: {}", kernel_image_dest.display());
    eprintln!("  Kernel config: {}", kernel_config_dest.display());
    eprintln!("  Modules manifest: {}", manifest_path.display());
    if !extracted_modules.is_empty() {
        eprintln!("  Modules directory: {}", modules_output_dir.display());
        eprintln!("  Total modules: {}", extracted_modules.len());
    }

    Ok(KernelExtractInfo {
        kernel_image: kernel_image_dest,
        kernel_config: kernel_config_dest,
        modules: extracted_modules,
        modules_manifest: manifest_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    /// Build a buffer carrying the arm64 `Image` magic at the expected offset,
    /// followed by `tail` bytes of filler (so it stays incompressible) for the
    /// large-payload roundtrip
    fn fake_arm64_image_sized(tail: usize) -> Vec<u8> {
        let mut img = vec![0u8; 64];
        img[ARM64_IMAGE_MAGIC_OFFSET..ARM64_IMAGE_MAGIC_OFFSET + 4]
            .copy_from_slice(ARM64_IMAGE_MAGIC);
        let mut state: u32 = 0x1234_5678;
        img.reserve(tail);
        for _ in 0..tail {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            img.push((state >> 24) as u8);
        }
        img
    }

    fn fake_arm64_image() -> Vec<u8> {
        let mut img = vec![0u8; 64];
        img[ARM64_IMAGE_MAGIC_OFFSET..ARM64_IMAGE_MAGIC_OFFSET + 4]
            .copy_from_slice(ARM64_IMAGE_MAGIC);
        img.extend_from_slice(&[0xAB; 128]);
        img
    }

    /// gzip-compress `data` in-process, matching the kernel's zboot wrapper
    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Wrap a pre-compressed payload in an EFI zboot ("zimg") container
    fn wrap_zboot(comp_type: &str, payload: &[u8]) -> Vec<u8> {
        let payload_offset: u32 = ZBOOT_HEADER_MIN_SIZE as u32;
        let mut buf = vec![0u8; payload_offset as usize];
        buf[0..2].copy_from_slice(b"MZ");
        buf[4..8].copy_from_slice(b"zimg");
        buf[8..12].copy_from_slice(&payload_offset.to_le_bytes());
        buf[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        buf[0x18..0x18 + comp_type.len()].copy_from_slice(comp_type.as_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    fn write_temp(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("in");
        fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    fn run_extract(input: &[u8]) -> NitroCliResult<Vec<u8>> {
        let (_src_dir, src) = write_temp(input);
        let out_dir = tempfile::TempDir::new().unwrap();
        let dest = out_dir.path().join("Image");
        extract_arm64_image(&src, &dest)?;
        Ok(fs::read(&dest).unwrap())
    }

    #[test]
    fn arm64_magic_detection() {
        assert!(has_arm64_image_magic(&fake_arm64_image()));
        assert!(!has_arm64_image_magic(&[0u8; 64]));
        assert!(!has_arm64_image_magic(b"short"));
    }

    #[test]
    fn raw_image_passes_through() {
        let img = fake_arm64_image();
        assert_eq!(run_extract(&img).unwrap(), img);
    }

    #[test]
    fn zboot_gzip_unwraps_to_raw_image() {
        let img = fake_arm64_image();
        let payload = gzip_compress(&img);
        let out = run_extract(&wrap_zboot("gzip", &payload)).expect("gzip should unwrap");
        assert!(has_arm64_image_magic(&out), "missing magic");
        assert_eq!(out, img, "roundtrip mismatch");
    }

    #[test]
    fn zboot_large_payload_roundtrips() {
        // Real kernels are multi-MB; make sure the streaming decompressor
        // reassembles a large image byte-for-byte.
        let img = fake_arm64_image_sized(8 * 1024 * 1024);
        let payload = gzip_compress(&img);
        let out = run_extract(&wrap_zboot("gzip", &payload)).expect("large payload should unwrap");
        assert_eq!(out, img, "large-payload roundtrip mismatch");
    }

    #[test]
    fn unknown_container_is_rejected() {
        // No "zimg" magic and no arm64 Image magic.
        assert!(run_extract(&[0x55u8; 256]).is_err());
    }

    #[test]
    fn unsupported_compression_is_rejected() {
        let mut buf = vec![0u8; ZBOOT_HEADER_MIN_SIZE];
        buf[0..2].copy_from_slice(b"MZ");
        buf[4..8].copy_from_slice(b"zimg");
        buf[8..12].copy_from_slice(&(ZBOOT_HEADER_MIN_SIZE as u32).to_le_bytes());
        buf[12..16].copy_from_slice(&8u32.to_le_bytes());
        buf[0x18..0x18 + 7].copy_from_slice(b"invalid");
        buf.extend_from_slice(&[0u8; 8]);
        let err = run_extract(&buf).unwrap_err();
        assert!(format!("{err:?}").contains("invalid"));
    }

    #[test]
    fn truncated_zboot_header_is_rejected_not_panicked() {
        // Valid "zimg" magic but shorter than the header, must not panic
        let mut buf = vec![0u8; 33];
        buf[0..2].copy_from_slice(b"MZ");
        buf[4..8].copy_from_slice(b"zimg");
        assert!(run_extract(&buf).is_err());
    }

    #[test]
    fn payload_bounds_past_eof_is_rejected() {
        let mut buf = vec![0u8; ZBOOT_HEADER_MIN_SIZE];
        buf[0..2].copy_from_slice(b"MZ");
        buf[4..8].copy_from_slice(b"zimg");
        buf[8..12].copy_from_slice(&(ZBOOT_HEADER_MIN_SIZE as u32).to_le_bytes());
        buf[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // size past EOF
        buf[0x18..0x18 + 4].copy_from_slice(b"gzip");
        let err = run_extract(&buf).unwrap_err();
        assert!(format!("{err:?}").contains("exceeds image size"));
    }

    #[test]
    fn decompressed_without_image_magic_is_rejected() {
        // Valid gzip payload, but the decompressed bytes are not an arm64 Image
        let payload = gzip_compress(&[0u8; 128]);
        let err = run_extract(&wrap_zboot("gzip", &payload)).unwrap_err();
        assert!(format!("{err:?}").contains("not a valid arm64 Image"));
    }
}
