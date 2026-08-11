// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

//! Module for querying RPM repositories using the rpm-repository crate.

use rpm_repository::http::HttpRepositoryClient;
use rpm_repository::metadata::primary::Package;
use rpm_repository::RepositoryRootReader;
use semver::Version;

use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::new_nitro_cli_failure;

/// Mirror list URLs for Amazon Linux 2023
const AL2023_MIRROR_AARCH64: &str =
    "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/aarch64/mirror.list";
const AL2023_MIRROR_X86_64: &str =
    "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list";

/// Minimum kernel version to list (6.12 and later)
const MIN_KERNEL_VERSION: &str = "6.12.0";

/// Information about an RPM package
#[derive(Debug, Clone)]
pub struct RpmPackageInfo {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package release
    pub release: String,
    /// Package architecture
    pub arch: String,
    /// Location (href) of the RPM file in the repository
    pub location: String,
}

impl RpmPackageInfo {
    /// Get the RPM filename
    pub fn filename(&self) -> String {
        format!(
            "{}-{}-{}.{}.rpm",
            self.name, self.version, self.release, self.arch
        )
    }
}

impl std::fmt::Display for RpmPackageInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-{}-{}.{}",
            self.name, self.version, self.release, self.arch
        )
    }
}

/// Get the mirror list URL for the given architecture
fn get_mirror_list_url(arch: &str) -> NitroCliResult<&'static str> {
    match arch {
        "aarch64" => Ok(AL2023_MIRROR_AARCH64),
        "x86_64" => Ok(AL2023_MIRROR_X86_64),
        _ => Err(new_nitro_cli_failure!(
            &format!("Unsupported architecture: {arch}"),
            NitroCliErrorEnum::InvalidArgument
        )),
    }
}

/// Fetch the first mirror URL from the mirror list (blocking)
fn fetch_mirror_url(arch: &str) -> NitroCliResult<String> {
    let mirror_list_url = get_mirror_list_url(arch)?;

    let response = reqwest::blocking::get(mirror_list_url).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to fetch mirror list: {e}"),
            NitroCliErrorEnum::ReadFromDiskFailure
        )
    })?;

    let body = response.text().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to read mirror list response: {e}"),
            NitroCliErrorEnum::ReadFromDiskFailure
        )
    })?;

    body.lines()
        .next()
        .map(|s| s.trim().to_string())
        .ok_or_else(|| {
            new_nitro_cli_failure!(
                "Mirror list is empty",
                NitroCliErrorEnum::ReadFromDiskFailure
            )
        })
}

/// Check if a version string is >= minimum version (6.12)
fn is_version_at_least(version: &str, min_version: &str) -> bool {
    let parse_version = |v: &str| -> Option<Version> {
        let normalized = if v.matches('.').count() == 1 {
            format!("{v}.0")
        } else {
            v.to_string()
        };
        let parts: Vec<&str> = normalized.split('.').take(3).collect();
        let semver_str = parts.join(".");
        Version::parse(&semver_str).ok()
    };

    match (parse_version(version), parse_version(min_version)) {
        (Some(v), Some(min)) => v >= min,
        _ => false,
    }
}

/// Check if a package name is a main kernel package (not devel, headers, tools, etc.)
fn is_main_kernel_package(name: &str) -> bool {
    if !name.starts_with("kernel") {
        return false;
    }

    let excluded_suffixes = [
        "-devel",
        "-headers",
        "-tools",
        "-livepatch",
        "-libbpf",
        "-modules-extra",
        "-modules-extra-common",
        "-debuginfo",
        "-doc",
        "-cross-headers",
        "-abi-stablelists",
        "-selftests-internal",
    ];

    for suffix in &excluded_suffixes {
        if name.contains(suffix) {
            return false;
        }
    }

    true
}

/// Convert rpm-repository Package to our RpmPackageInfo
fn package_to_info(pkg: &Package) -> RpmPackageInfo {
    RpmPackageInfo {
        name: pkg.name.clone(),
        version: pkg.version.version.clone(),
        release: pkg.version.release.clone(),
        arch: pkg.arch.clone(),
        location: pkg.location.href.clone(),
    }
}

/// Filter packages to only include main kernel packages with version >= 6.12
fn filter_kernel_packages(packages: Vec<Package>) -> Vec<RpmPackageInfo> {
    let mut filtered: Vec<RpmPackageInfo> = packages
        .iter()
        .filter(|pkg| {
            is_main_kernel_package(&pkg.name)
                && is_version_at_least(&pkg.version.version, MIN_KERNEL_VERSION)
        })
        .map(package_to_info)
        .collect();

    // Sort by name and version
    filtered.sort_by(|a, b| match a.name.cmp(&b.name) {
        std::cmp::Ordering::Equal => a.version.cmp(&b.version),
        other => other,
    });

    filtered
}

/// Async implementation to fetch packages from repository
async fn fetch_packages_async(mirror_url: &str) -> NitroCliResult<Vec<Package>> {
    let client = HttpRepositoryClient::new(mirror_url).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create repository client: {e}"),
            NitroCliErrorEnum::ReadFromDiskFailure
        )
    })?;

    let metadata_reader = client.metadata_reader().await.map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to read repository metadata: {e}"),
            NitroCliErrorEnum::ReadFromDiskFailure
        )
    })?;

    let primary = metadata_reader.primary_packages().await.map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to fetch primary packages: {e}"),
            NitroCliErrorEnum::ReadFromDiskFailure
        )
    })?;

    Ok(primary.packages)
}

/// List kernel packages from Amazon Linux 2023 repository
pub fn list_kernel_packages(arch: &str) -> NitroCliResult<Vec<RpmPackageInfo>> {
    eprintln!("Fetching mirror list for {}...", arch);
    let mirror_url = fetch_mirror_url(arch)?;
    eprintln!("Using mirror: {}", mirror_url);

    eprintln!("Fetching repository metadata and packages...");
    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create tokio runtime: {e}"),
            NitroCliErrorEnum::ReadFromDiskFailure
        )
    })?;

    let packages = runtime.block_on(fetch_packages_async(&mirror_url))?;

    eprintln!("Filtering kernel packages...");
    let kernel_packages = filter_kernel_packages(packages);

    Ok(kernel_packages)
}

/// Find a kernel package by version string, or return the latest if no version specified
fn find_kernel_by_version(
    packages: &[RpmPackageInfo],
    version: Option<&str>,
) -> NitroCliResult<RpmPackageInfo> {
    if packages.is_empty() {
        return Err(new_nitro_cli_failure!(
            "No kernel packages found",
            NitroCliErrorEnum::InvalidArgument
        ));
    }

    // If no version specified, return the latest (last in sorted list)
    let version = match version {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(packages.last().unwrap().clone()),
    };

    // Try exact match first
    if let Some(pkg) = packages.iter().find(|p| p.version == version) {
        return Ok(pkg.clone());
    }

    // Try matching with version prefix
    let matches: Vec<_> = packages
        .iter()
        .filter(|p| p.version.starts_with(version))
        .collect();

    match matches.len() {
        0 => Err(new_nitro_cli_failure!(
            &format!("No kernel package found with version: {version}"),
            NitroCliErrorEnum::InvalidArgument
        )),
        1 => Ok(matches[0].clone()),
        _ => Ok((*matches.last().unwrap()).clone()),
    }
}

/// Download a kernel RPM from Amazon Linux 2023 repository
pub fn download_kernel(
    arch: &str,
    version: Option<&str>,
    output_dir: &str,
) -> NitroCliResult<std::path::PathBuf> {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    let packages = list_kernel_packages(arch)?;

    let package = match version {
        Some(v) if !v.is_empty() => {
            eprintln!("Finding kernel version {}...", v);
            find_kernel_by_version(&packages, Some(v))?
        }
        _ => {
            eprintln!("Selecting latest kernel version...");
            find_kernel_by_version(&packages, None)?
        }
    };

    eprintln!("Found: {}", package);

    // Get mirror URL again for download
    let mirror_url = fetch_mirror_url(arch)?;
    let rpm_url = format!("{}{}", mirror_url, package.location);
    eprintln!("Downloading from: {}", rpm_url);

    let response = reqwest::blocking::get(&rpm_url).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to download RPM: {e}"),
            NitroCliErrorEnum::ReadFromDiskFailure
        )
    })?;

    if !response.status().is_success() {
        return Err(new_nitro_cli_failure!(
            &format!("Failed to download RPM: HTTP {}", response.status()),
            NitroCliErrorEnum::ReadFromDiskFailure
        ));
    }

    let bytes = response.bytes().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to read RPM response: {e}"),
            NitroCliErrorEnum::ReadFromDiskFailure
        )
    })?;

    let output_path = Path::new(output_dir).join(package.filename());
    let mut file = File::create(&output_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create output file: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    file.write_all(&bytes).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write RPM file: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    eprintln!(
        "Downloaded {} ({} bytes)",
        output_path.display(),
        bytes.len()
    );

    Ok(output_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_version_at_least("6.12.0", "6.12.0"));
        assert!(is_version_at_least("6.12.5", "6.12.0"));
        assert!(is_version_at_least("6.13.0", "6.12.0"));
        assert!(is_version_at_least("7.0.0", "6.12.0"));
        assert!(!is_version_at_least("6.11.0", "6.12.0"));
        assert!(!is_version_at_least("6.1.0", "6.12.0"));
        assert!(!is_version_at_least("5.15.0", "6.12.0"));
    }

    #[test]
    fn test_version_comparison_short() {
        assert!(is_version_at_least("6.12", "6.12.0"));
        assert!(is_version_at_least("6.13", "6.12.0"));
        assert!(!is_version_at_least("6.11", "6.12.0"));
    }
}
