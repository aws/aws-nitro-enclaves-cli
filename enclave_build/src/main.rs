// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::{App, AppSettings, Arg};
use std::fs::OpenOptions;

use aws_nitro_enclaves_image_format::generate_build_info;
use enclave_build::Docker2Eif;

fn main() {
    let matches = App::new("Docker2Eif builder")
        .about("Generate consistent EIF image from a Docker image")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("docker_image")
                .short('t')
                .long("tag")
                .help("Docker image tag")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("init_path")
                .short('i')
                .long("init")
                .help("Path to a binary representing the init process for the enclave")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("nsm_path")
                .short('n')
                .long("nsm")
                .help("Path to the NitroSecureModule Kernel Driver")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("kernel_img_path")
                .short('k')
                .long("kernel")
                .help("Path to a bzImage/Image file for x86_64/aarch64 linux kernel")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("kernel_cfg_path")
                .long("kernel_config")
                .help("Path to a bzImage.config/Image.config file for x86_64/aarch64 linux kernel config")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("cmdline")
                .short('c')
                .long("cmdline")
                .help("Cmdline for kernel")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("linuxkit_path")
                .short('l')
                .long("linuxkit")
                .help("Linuxkit executable path")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .short('o')
                .long("output")
                .help("Output file for EIF image")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("signing-certificate")
                .long("signing-certificate")
                .help("Specify the path to the signing certificate")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("private-key")
                .long("private-key")
                .help("Specify the path to the private-key")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("build")
                .short('b')
                .long("build")
                .help("Build image from Dockerfile")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("pull")
                .short('p')
                .long("pull")
                .help("Pull the Docker image before generating EIF")
                .required(false)
                .conflicts_with("build"),
        )
        .arg(
            Arg::with_name("image_name")
                .long("name")
                .help("Name for enclave image")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("image_version")
                .long("version")
                .help("Version of the enclave image")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metadata")
                .long("metadata")
                .help("Path to JSON containing the custom metadata provided by the user.")
                .takes_value(true),
        )
        .get_matches();

    let docker_image = matches.value_of("docker_image").unwrap();
    let init_path = matches.value_of("init_path").unwrap();
    let nsm_path = matches.value_of("nsm_path").unwrap();
    let kernel_img_path = matches.value_of("kernel_img_path").unwrap();
    let kernel_cfg_path = matches.value_of("kernel_cfg_path").unwrap();
    let cmdline = matches.value_of("cmdline").unwrap();
    let linuxkit_path = matches.value_of("linuxkit_path").unwrap();
    let output = matches.value_of("output").unwrap();
    let signing_certificate = matches
        .value_of("signing_certificate")
        .map(|val| val.to_string());
    let private_key = matches
        .value_of("private_certificate")
        .map(|val| val.to_string());
    let img_name = matches.value_of("image_name").map(|val| val.to_string());
    let img_version = matches.value_of("image_version").map(|val| val.to_string());
    let metadata = matches.value_of("metadata").map(|val| val.to_string());

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
        img_name,
        img_version,
        metadata,
        generate_build_info!(kernel_cfg_path).expect("Can not generate build info"),
    )
    .unwrap();

    if matches.is_present("build") {
        let dockerfile_dir = matches.value_of("build").unwrap();
        img.build_docker_image(dockerfile_dir.to_string()).unwrap();
    } else if matches.is_present("pull") {
        img.pull_docker_image().unwrap();
    }

    img.create().unwrap();
}
