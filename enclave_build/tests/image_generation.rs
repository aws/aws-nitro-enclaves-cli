// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use enclave_build::Docker2Eif;
use std::fs::OpenOptions;
use std::process::Command;

/// Test the generated image is the same as the one generated using other tools
#[test]
fn test_image_generation() {
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("sample_eif.bin")
        .expect("Failed to create output file");

    let mut img = Docker2Eif::new(
        String::from("nc-vsock:test"),
        String::from("dev/ramfs/build/init"),
        String::from("../eif_utils/bzImage"),
        String::from("reboot=k panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"),
        String::from("dev/ramfs/linuxkit"),
        &mut output,
	".".to_string())
    .unwrap();

    img.create().unwrap();

    let status = Command::new("cmp")
        .arg("sample_eif.bin")
        .arg("test_data/sample_eif.bin")
        .status()
        .expect("command");
    assert!(status.success());
}
