// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

#[cfg(test)]
mod tests {
    use nitro_cli::commands_parser::{
        BuildEnclavesArgs, DescribeEnclaveArgs, RunEnclavesArgs, TerminateEnclavesArgs,
    };
    use nitro_cli::utils::generate_enclave_id;
    use nitro_cli::utils::Console;
    use nitro_cli::{
        build_enclaves, build_from_docker, describe_enclaves, enclave_console, run_enclaves,
        terminate_enclaves,
    };
    use nitro_cli::{CID_TO_CONSOLE_PORT_OFFSET, VMADDR_CID_HYPERVISOR};
    use std::convert::TryInto;
    use tempfile::tempdir;

    const SAMPLE_DOCKER: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample";
    const ENCLAVE_SDK_DOCKER: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:enclave-sdk";

    pub const MAX_BOOT_TIMEOUT_SEC: u64 = 9;

    use std::convert::TryFrom;
    use std::time::Duration;

    fn setup_env() {
        if let Err(_) = std::env::var("NITRO_CLI_BLOBS") {
            let home = std::env::var("HOME").unwrap();
            std::env::set_var("NITRO_CLI_BLOBS", format!("{}/.nitro_cli/prebuilt", home));
        }
    }

    #[test]
    fn build_enclaves_invalid_uri() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-devel".to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
        };

        assert_eq!(build_enclaves(args).is_err(), true);
    }

    #[test]
    fn build_enclaves_simple_image() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
        };

        let measurements = build_from_docker(&args.docker_uri, &args.docker_dir, &args.output)
            .expect("Docker build failed")
            .1;
        assert_eq!(
            measurements.get("PCR0").unwrap(),
            "c9b8700292f8a1190270359c2f010f96f49216c38089bcc49f4b96841d7cc360430ad7c0eb7a840ffdc70b8465b8284c"
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            "cc0749fddbb889480234b93192ae55609c91dd415028ce3474d26d363c61722b87e0ce86086782c649e14d9629467c2b"
        );
        assert_eq!(
            measurements.get("PCR2").unwrap(),
            "7f661d8929cfc7b5d5a87a9f2548adf4de80bda5354284ae82c34f63e04a6220c5e852503bea378224dcb58619cc62b3"
        );
    }

    #[test]
    fn build_hello_world() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: "hello-world:latest".to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
        };

        build_from_docker(&args.docker_uri, &args.docker_dir, &args.output)
            .expect("Docker build failed");
    }

    #[test]
    fn build_enclaves_enclave_sdk() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: ENCLAVE_SDK_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
        };

        let measurements = build_from_docker(&args.docker_uri, &args.docker_dir, &args.output)
            .expect("Docker build failed")
            .1;
        assert_eq!(
            measurements.get("PCR0").unwrap(),
            "7f43e4bf78806fb629b6c5297986fd8a33da83d4c4c22bdd18338f890a09a8fb00e33df94e6253862ce9af87af234c41"
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            "cc0749fddbb889480234b93192ae55609c91dd415028ce3474d26d363c61722b87e0ce86086782c649e14d9629467c2b"
        );
        assert_eq!(
            measurements.get("PCR2").unwrap(),
            "964f18254b4168518161df05bcec57edca87ff36d19704ef258ef2a72011e5efa6d36e1cadf140e34d5cdb1886fadbb0"
        );
    }

    #[test]
    fn run_describe_terminate_simple_docker_image() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let build_args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
        )
        .expect("Docker build failed");

        let args = RunEnclavesArgs {
            enclave_cid: Some(17),
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 64,
            debug_mode: Some(true),
        };
        run_describe_terminate(args);
    }

    #[test]
    fn run_describe_terminate_enclave_sdk_docker_image() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let build_args = BuildEnclavesArgs {
            docker_uri: ENCLAVE_SDK_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
        )
        .expect("Docker build failed");

        let args = RunEnclavesArgs {
            enclave_cid: Some(29),
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 1024,
            debug_mode: Some(true),
        };
        run_describe_terminate(args);
    }

    fn run_describe_terminate(args: RunEnclavesArgs) {
        setup_env();
        let req_enclave_cid = args.enclave_cid.clone();
        let req_mem_size = args.memory_mib.clone();
        let req_nr_cpus: u64 = args.cpu_count.unwrap().try_into().unwrap();
        let debug_mode = args.debug_mode.clone();
        let enclave_cid = run_enclaves(args).expect("Run enclaves failed");
        if let Some(req_enclave_cid) = req_enclave_cid {
            assert_eq!(req_enclave_cid, enclave_cid);
        }

        let cid_copy = enclave_cid;

        let console = Console::new_nonblocking(
            VMADDR_CID_HYPERVISOR,
            u32::try_from(cid_copy).unwrap() + CID_TO_CONSOLE_PORT_OFFSET,
        )
        .expect("Failed to connect to the console");
        let mut buffer: Vec<u8> = Vec::new();
        let duration: Duration = Duration::from_secs(MAX_BOOT_TIMEOUT_SEC);
        console
            .read_to_buffer(&mut buffer, duration)
            .expect("Failed to check that the enclave booted");

        let contents = String::from_utf8(buffer).unwrap();
        let boot = contents.contains("Run /init as init process");

        assert_eq!(boot, true);

        let replies = describe_enclaves(DescribeEnclaveArgs {}).expect("Describe enclaves failed");
        let reply = replies[0];
        let flags = reply.flags_to_string();

        assert_eq!({ reply.enclave_cid }, enclave_cid);
        assert_eq!(reply.mem_size / 1024 / 1024, req_mem_size);
        assert_eq!({ reply.nr_cpus }, req_nr_cpus);
        assert_eq!(reply.state_to_string(), "RUNNING");
        match debug_mode {
            Some(true) => assert_eq!(flags, "DEBUG_MODE"),
            _ => assert_eq!(flags, "NONE"),
        };
        let enclave_id = generate_enclave_id(reply.slot_uid).expect("Describe enclaves failed");

        let terminate_args = TerminateEnclavesArgs { enclave_id };
        terminate_enclaves(terminate_args).expect("Terminate enclaves failed");

        let replies = describe_enclaves(DescribeEnclaveArgs {}).expect("Describe enclaves failed");
        assert_eq!(replies.len(), 0);
    }

    #[test]
    fn build_run_describe_terminate_simple_eif_image() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let build_args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 64,
            debug_mode: Some(true),
        };

        run_describe_terminate(run_args);
    }

    #[test]
    fn console_without_debug_mode() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let build_args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: Some(false),
        };

        let enclave_cid = run_enclaves(run_args).expect("Run enclaves failed");

        let replies = describe_enclaves(DescribeEnclaveArgs {}).expect("Describe enclaves failed");
        let reply = replies[0];
        let enclave_id = generate_enclave_id(reply.slot_uid).expect("Describe enclaves failed");

        assert_eq!(enclave_console(enclave_cid).is_err(), true);

        let terminate_args = TerminateEnclavesArgs { enclave_id };
        terminate_enclaves(terminate_args).expect("Terminate enclaves failed");
    }

    #[test]
    fn run_describe_terminate_simple_docker_image_loop() {
        for _ in 0..5 {
            run_describe_terminate_simple_docker_image();
        }
    }

    #[test]
    fn run_describe_terminate_loop() {
        for _ in 0..3 {
            run_describe_terminate_enclave_sdk_docker_image();
            run_describe_terminate_simple_docker_image();
            run_describe_terminate_enclave_sdk_docker_image();
        }
    }
}
