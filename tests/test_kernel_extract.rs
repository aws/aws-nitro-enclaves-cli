// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use std::path::{Path, PathBuf};
use std::process::Command;

use nitro_cli::kernel_extract::extract_kernel_binaries;

/// Architecture this test binary was compiled for.
const HOST_ARCH: &str = std::env::consts::ARCH;

/// Kernel version directory name placed under `lib/modules/`.
const FIXTURE_KVER: &str = "6.12.0-fake.al2023.x86_64";

/// Offset of the arm64 `Image` magic within a raw kernel image.
const ARM64_IMAGE_MAGIC_OFFSET: usize = 56;
const ARM64_IMAGE_MAGIC: &[u8; 4] = b"ARM\x64";

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn rpm_tooling_available() -> bool {
    have("rpmbuild") && have("rpm2cpio") && have("cpio")
}

/// Produce a kernel image blob valid for the host arch.
fn fixture_vmlinuz() -> Vec<u8> {
    if HOST_ARCH == "aarch64" {
        let mut img = vec![0u8; 64];
        img[ARM64_IMAGE_MAGIC_OFFSET..ARM64_IMAGE_MAGIC_OFFSET + 4]
            .copy_from_slice(ARM64_IMAGE_MAGIC);
        img.extend_from_slice(&[0xCD; 256]);
        img
    } else {
        b"FAKE-BZIMAGE-PAYLOAD-not-a-real-kernel".to_vec()
    }
}

/// Build a fixture kernel RPM from a fake `lib/modules/<kver>/` tree.
fn build_fixture_rpm(tree_root: &Path, config_body: &str, ko_relpaths: &[&str]) -> Option<PathBuf> {
    let topdir = tree_root.join("rpmbuild");
    let tree = tree_root.join("tree");
    let verdir = tree.join("lib/modules").join(FIXTURE_KVER);
    std::fs::create_dir_all(&verdir).unwrap();

    // Kernel config and image live directly in the version dir.
    std::fs::write(verdir.join("config"), config_body).unwrap();
    std::fs::write(verdir.join("vmlinuz"), fixture_vmlinuz()).unwrap();

    for rel in ko_relpaths {
        let ko = verdir.join(rel);
        std::fs::create_dir_all(ko.parent().unwrap()).unwrap();
        // Empty file: modinfo fails on it, so dependencies come back empty.
        std::fs::write(&ko, b"").unwrap();
    }

    for sub in ["SPECS", "BUILD", "BUILDROOT", "RPMS", "SRPMS", "SOURCES"] {
        std::fs::create_dir_all(topdir.join(sub)).unwrap();
    }

    let spec = format!(
        "Name: kernel-fixture\n\
         Version: 6.12.0\n\
         Release: fake\n\
         Summary: nitro-cli kernel extraction fixture\n\
         License: Apache-2.0\n\
         BuildArch: noarch\n\
         %global debug_package %{{nil}}\n\
         %description\n\
         Synthetic kernel package used only by the nitro-cli integration tests.\n\
         %install\n\
         mkdir -p %{{buildroot}}\n\
         cp -a {tree}/. %{{buildroot}}/\n\
         %files\n\
         /lib\n",
        tree = tree.display()
    );
    let spec_path = topdir.join("SPECS/kernel-fixture.spec");
    std::fs::write(&spec_path, spec).unwrap();

    let status = Command::new("rpmbuild")
        .arg("-bb")
        .arg("--define")
        .arg(format!("_topdir {}", topdir.display()))
        .arg(&spec_path)
        .status()
        .expect("failed to spawn rpmbuild");
    assert!(status.success(), "rpmbuild failed to build the fixture RPM");

    find_first_rpm(&topdir.join("RPMS"))
}

fn find_first_rpm(dir: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_first_rpm(&path) {
                return Some(found);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rpm") {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod test_kernel_extract {
    use super::*;

    #[test]
    fn extract_selects_module_configs() {
        if !rpm_tooling_available() {
            eprintln!(
                "skipping extract_selects_module_configs: rpmbuild/rpm2cpio/cpio not available"
            );
            return;
        }

        let scratch = tempfile::TempDir::new().unwrap();
        let config_body = "\
CONFIG_NSM=m
CONFIG_VIRTIO_VSOCKETS=m
CONFIG_VIRTIO_MMIO=m
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
";
        // .ko files in realistic subdirs to exercise the recursive search.
        let ko = &[
            "kernel/drivers/misc/nsm.ko",
            "kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko",
            "kernel/drivers/virtio/virtio_mmio.ko",
        ];
        let rpm =
            build_fixture_rpm(scratch.path(), config_body, ko).expect("fixture RPM not produced");

        let out = scratch.path().join("out");
        let info = extract_kernel_binaries(&rpm, &out, HOST_ARCH)
            .expect("extraction should succeed for a well-formed fixture RPM");

        // Kernel image: bzImage on x86_64, Image on aarch64.
        let expected_image = if HOST_ARCH == "aarch64" {
            "Image"
        } else {
            "bzImage"
        };
        assert_eq!(
            info.kernel_image.file_name().unwrap().to_str().unwrap(),
            expected_image
        );
        assert!(info.kernel_image.exists(), "kernel image was not written");
        assert!(info.kernel_config.exists(), "kernel config was not written");
        assert!(info.modules_manifest.exists(), "manifest was not written");

        // Exactly the three =m features, sorted by name.
        let mut names: Vec<&str> = info.modules.iter().map(|m| m.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["nsm", "virtio_mmio", "vmw_vsock_virtio_transport"],
            "module selection did not match the =m config options"
        );

        // Each selected module's .ko must be materialised.
        for m in &info.modules {
            assert!(
                m.path.exists(),
                "module {} .ko missing at {:?}",
                m.name,
                m.path
            );
        }

        // Manifest lists the extracted modules and the config status.
        let manifest = std::fs::read_to_string(&info.modules_manifest).unwrap();
        assert!(manifest.contains("nsm"));
        assert!(manifest.contains("virtio_mmio"));
        assert!(manifest.contains("vmw_vsock_virtio_transport"));
        assert!(manifest.contains("CONFIG_NSM"));
    }

    #[test]
    fn extract_all_builtin_yields_no_modules() {
        if !rpm_tooling_available() {
            eprintln!("skipping extract_all_builtin_yields_no_modules: rpm tooling not available");
            return;
        }

        let scratch = tempfile::TempDir::new().unwrap();
        let config_body = "\
CONFIG_NSM=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
";
        let rpm =
            build_fixture_rpm(scratch.path(), config_body, &[]).expect("fixture RPM not produced");

        let out = scratch.path().join("out");
        let info = extract_kernel_binaries(&rpm, &out, HOST_ARCH)
            .expect("extraction should succeed with an all-builtin config");

        assert!(
            info.modules.is_empty(),
            "built-in features must not yield modules"
        );
        let manifest = std::fs::read_to_string(&info.modules_manifest).unwrap();
        assert!(
            manifest.contains("No modules needed"),
            "manifest should note that all features are built-in"
        );
    }

    #[test]
    fn extract_missing_rpm_errors() {
        if !rpm_tooling_available() {
            eprintln!("skipping extract_missing_rpm_errors: rpm tooling not available");
            return;
        }
        let scratch = tempfile::TempDir::new().unwrap();
        let missing = scratch.path().join("invalid.rpm");
        let out = scratch.path().join("out");
        assert!(extract_kernel_binaries(&missing, &out, HOST_ARCH).is_err());
    }

    #[test]
    fn extract_malformed_rpm_errors() {
        if !rpm_tooling_available() {
            eprintln!("skipping extract_malformed_rpm_errors: rpm tooling not available");
            return;
        }
        let scratch = tempfile::TempDir::new().unwrap();
        let invalid = scratch.path().join("invalid.rpm");
        std::fs::write(&invalid, b"invalid RPM archive").unwrap();
        let out = scratch.path().join("out");
        assert!(extract_kernel_binaries(&invalid, &out, HOST_ARCH).is_err());
    }
}
