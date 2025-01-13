// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::{Arg, ArgAction, ArgGroup, Command};
use std::fs::OpenOptions;

use aws_nitro_enclaves_image_format::generate_build_info;
use enclave_build::Docker2Eif;

fn main() {
    let matches = Command::new("Docker2Eif builder")
        .about("Generate consistent EIF image from a Docker image")
        .arg(
            Arg::new("docker_image")
                .short('t')
                .long("tag")
                .help("Docker image tag")
                .required(true),
        )
        .arg(
            Arg::new("init_path")
                .short('i')
                .long("init")
                .help("Path to a binary representing the init process for the enclave")
                .required(true),
        )
        .arg(
            Arg::new("nsm_path")
                .short('n')
                .long("nsm")
                .help("Path to the NitroSecureModule Kernel Driver")
                .required(true),
        )
        .arg(
            Arg::new("kernel_img_path")
                .short('k')
                .long("kernel")
                .help("Path to a bzImage/Image file for x86_64/aarch64 linux kernel")
                .required(true),
        )
        .arg(
            Arg::new("kernel_cfg_path")
                .long("kernel_config")
                .help("Path to a bzImage.config/Image.config file for x86_64/aarch64 linux kernel config")
                .required(true),
        )
        .arg(
            Arg::new("cmdline")
                .short('c')
                .long("cmdline")
                .help("Cmdline for kernel")
                .required(true),
        )
        .arg(
            Arg::new("linuxkit_path")
                .short('l')
                .long("linuxkit")
                .help("Linuxkit executable path")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file for EIF image")
                .required(true),
        )
        .arg(
            Arg::new("signing-certificate")
                .long("signing-certificate")
                .help("Specify the path to the signing certificate"),
        )
        .arg(
            Arg::new("private-key")
                .long("private-key")
                .help("Specify the path to the private-key"),
        )
        .arg(
            Arg::new("kms-key-id")
                .long("kms-key-id")
                .help("Specify unique id of the KMS key")
        )
        .arg(
            Arg::new("kms-key-region")
                .long("kms-key-region")
                .help("Specify region in which the KMS key resides")
                .requires("kms-key-id")
        )
        .group(
            ArgGroup::new("signing-key")
                .args(["kms-key-id", "private-key"])
                .multiple(false)
                .requires("signing-certificate")
        )
        .arg(
            Arg::new("build")
                .short('b')
                .long("build")
                .help("Build image from Dockerfile")
                .conflicts_with("pull"),
        )
        .arg(
            Arg::new("pull")
                .short('p')
                .long("pull")
                .help("Pull the Docker image before generating EIF")
                .action(ArgAction::SetTrue)
                .conflicts_with("build"),
        )
        .arg(
            Arg::new("image_name")
                .long("name")
                .help("Name for enclave image"),
        )
        .arg(
            Arg::new("image_version")
                .long("version")
                .help("Version of the enclave image"),
        )
        .arg(
            Arg::new("metadata")
                .long("metadata")
                .help("Path to JSON containing the custom metadata provided by the user"),
        )
        .get_matches();

    let docker_image = matches.get_one::<String>("docker_image").unwrap();
    let init_path = matches.get_one::<String>("init_path").unwrap();
    let nsm_path = matches.get_one::<String>("nsm_path").unwrap();
    let kernel_img_path = matches.get_one::<String>("kernel_img_path").unwrap();
    let kernel_cfg_path = matches.get_one::<String>("kernel_cfg_path").unwrap();
    let cmdline = matches.get_one::<String>("cmdline").unwrap();
    let linuxkit_path = matches.get_one::<String>("linuxkit_path").unwrap();
    let output = matches.get_one::<String>("output").unwrap();
    let signing_certificate = matches
        .get_one::<String>("signing-certificate")
        .map(String::from);
    let private_key = matches.get_one::<String>("private-key").map(String::from);
    let img_name = matches.get_one::<String>("image_name").map(String::from);
    let img_version = matches.get_one::<String>("image_version").map(String::from);
    let metadata = matches.get_one::<String>("metadata").map(String::from);
    let kms_key_id = matches.get_one::<String>("kms-key-id").map(String::from);
    let kms_key_region = matches
        .get_one::<String>("kms-key-region")
        .map(String::from);

    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output)
        .expect("Failed to create output file");

    let mut img = Docker2Eif::new(
        docker_image.to_string(),
        init_path.to_string(),
        nsm_path.to_string(),
        kernel_img_path.to_string(),
        cmdline.to_string(),
        linuxkit_path.to_string(),
        &mut output,
        ".".to_string(),
        &signing_certificate,
        &private_key,
        &kms_key_id,
        &kms_key_region,
        img_name,
        img_version,
        metadata,
        generate_build_info!(kernel_cfg_path).expect("Can not generate build info"),
    )
    .unwrap();

    if let Some(dockerfile_dir) = matches.get_one::<String>("build") {
        img.build_docker_image(dockerfile_dir.to_string()).unwrap();
    } else if matches.get_flag("pull") {
        img.pull_docker_image().unwrap();
    }

    img.create().unwrap();
}
