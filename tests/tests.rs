// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use nitro_cli::common::commands_parser::{
        BuildEnclavesArgs, RunEnclavesArgs, TerminateEnclavesArgs,
    };
    use nitro_cli::common::json_output::{DescribeEifInfo, EnclaveDescribeInfo};
    use nitro_cli::enclave_proc::commands::{describe_enclaves, run_enclaves, terminate_enclaves};
    use nitro_cli::enclave_proc::resource_manager::NE_ENCLAVE_DEBUG_MODE;
    use nitro_cli::enclave_proc::utils::{
        flags_to_string, generate_enclave_id, get_enclave_describe_info,
    };
    use nitro_cli::utils::Console;
    use nitro_cli::{build_enclaves, build_from_docker, describe_eif, enclave_console};
    use nitro_cli::{CID_TO_CONSOLE_PORT_OFFSET, VMADDR_CID_HYPERVISOR};
    use std::convert::TryInto;
    use std::fs::OpenOptions;
    use std::io::Write;
    use tempfile::tempdir;

    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509Name, X509};

    // Remote Docker image
    const SAMPLE_DOCKER: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample";
    // Local Docker image
    const COMMAND_EXECUTER_DOCKER: &str = "command_executer:eif";

    pub const MAX_BOOT_TIMEOUT_SEC: u64 = 9;

    use std::convert::TryFrom;
    use std::time::Duration;

    fn setup_env() {
        if std::env::var("NITRO_CLI_BLOBS").is_err() {
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
            signing_certificate: None,
            private_key: None,
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
            signing_certificate: None,
            private_key: None,
        };

        let measurements = build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
        )
        .expect("Docker build failed")
        .1;
        assert_eq!(
            measurements.get("PCR0").unwrap(),
            "93a8a6a775cd1e1ab8b6121d1b0ce08e99e0976dabfa40663fa8ea9633421305de18c8f95aa2b82d3feb918fe912c838"
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            "c35e620586e91ed40ca5ce360eedf77ba673719135951e293121cb3931220b00f87b5a15e94e25c01fecd08fc9139342"
        );
        assert_eq!(
            measurements.get("PCR2").unwrap(),
            "52528ebeccf82b21cea3f3a9d055f1bb3d18254d77dcda2bbd7f39cecd96b7eea842913800cc1b0bc261b7ad1b83be90"
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
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
        )
        .expect("Docker build failed");
    }

    #[test]
    fn build_enclaves_command_executer() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: COMMAND_EXECUTER_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
        )
        .expect("Docker build failed");
    }

    fn generate_signing_cert_and_key(cert_path: &str, key_path: &str) {
        let ec_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = EcKey::generate(&ec_group).unwrap();
        let pkey = PKey::from_ec_key(key.clone()).unwrap();

        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "aws.nitro-enclaves")
            .unwrap();
        let name = name.build();

        let before = Asn1Time::days_from_now(0).unwrap();
        let after = Asn1Time::days_from_now(365).unwrap();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder.set_not_before(&before).unwrap();
        builder.set_not_after(&after).unwrap();
        builder.sign(&pkey, MessageDigest::sha384()).unwrap();

        let cert = builder.build();

        let mut key_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(key_path)
            .unwrap();
        key_file
            .write_all(&key.private_key_to_pem().unwrap())
            .unwrap();

        let mut cert_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(cert_path)
            .unwrap();
        cert_file.write_all(&cert.to_pem().unwrap()).unwrap();
    }

    #[test]
    fn build_enclaves_signed_simple_image() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        let eif_path = format!("{}/test.eif", dir_path);
        let cert_path = format!("{}/cert.pem", dir_path);
        let key_path = format!("{}/key.pem", dir_path);
        generate_signing_cert_and_key(&cert_path, &key_path);

        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path,
            signing_certificate: Some(cert_path),
            private_key: Some(key_path),
        };

        let measurements = build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
        )
        .expect("Docker build failed")
        .1;
        assert_eq!(
            measurements.get("PCR0").unwrap(),
            "93a8a6a775cd1e1ab8b6121d1b0ce08e99e0976dabfa40663fa8ea9633421305de18c8f95aa2b82d3feb918fe912c838"
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            "c35e620586e91ed40ca5ce360eedf77ba673719135951e293121cb3931220b00f87b5a15e94e25c01fecd08fc9139342"
        );
        assert_eq!(
            measurements.get("PCR2").unwrap(),
            "52528ebeccf82b21cea3f3a9d055f1bb3d18254d77dcda2bbd7f39cecd96b7eea842913800cc1b0bc261b7ad1b83be90"
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
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
        )
        .expect("Docker build failed");

        let args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 64,
            debug_mode: Some(true),
            enclave_name: None,
        };
        run_describe_terminate(args);
    }

    #[test]
    fn run_describe_terminate_signed_enclave_image() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        let eif_path = format!("{}/test.eif", dir_path);
        let cert_path = format!("{}/cert.pem", dir_path);
        let key_path = format!("{}/key.pem", dir_path);
        generate_signing_cert_and_key(&cert_path, &key_path);

        setup_env();
        let build_args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path,
            signing_certificate: Some(cert_path),
            private_key: Some(key_path),
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
        )
        .expect("Docker build failed");

        let args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 256,
            debug_mode: Some(true),
            enclave_name: None,
        };
        run_describe_terminate(args);
    }

    #[test]
    fn run_describe_terminate_command_executer_docker_image() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let build_args = BuildEnclavesArgs {
            docker_uri: COMMAND_EXECUTER_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
        )
        .expect("Docker build failed");

        let args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 2046,
            debug_mode: Some(true),
            enclave_name: None,
        };
        run_describe_terminate(args);
    }

    fn run_describe_terminate(args: RunEnclavesArgs) {
        setup_env();
        let req_enclave_cid = args.enclave_cid.clone();
        let req_mem_size = args.memory_mib.clone();
        let req_nr_cpus: u64 = args.cpu_count.unwrap().try_into().unwrap();
        let debug_mode = args.debug_mode.clone();
        let mut enclave_manager = run_enclaves(&args, None)
            .expect("Run enclaves failed")
            .enclave_manager;
        let enclave_cid = enclave_manager.get_console_resources_enclave_cid().unwrap();
        let enclave_flags = enclave_manager
            .get_console_resources_enclave_flags()
            .unwrap();
        if let Some(req_enclave_cid) = req_enclave_cid {
            assert_eq!(req_enclave_cid, enclave_cid);
        }

        match debug_mode {
            Some(true) => assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, NE_ENCLAVE_DEBUG_MODE),
            _ => assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, 0),
        };

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
        let boot = contents.contains("nsm: loading out-of-tree module");

        assert_eq!(boot, true);

        let info = get_enclave_describe_info(&enclave_manager).unwrap();
        let replies: Vec<EnclaveDescribeInfo> = vec![info];
        let reply = &replies[0];
        let flags = &reply.flags;

        assert_eq!({ reply.enclave_cid }, enclave_cid);
        assert_eq!(reply.memory_mib, req_mem_size);
        assert_eq!({ reply.cpu_count }, req_nr_cpus);
        assert_eq!(reply.state, "RUNNING");
        match debug_mode {
            Some(true) => assert_eq!(flags, "DEBUG_MODE"),
            _ => assert_eq!(flags, "NONE"),
        };
        let _enclave_id = generate_enclave_id(0).expect("Describe enclaves failed");

        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");

        let info = get_enclave_describe_info(&enclave_manager).unwrap();

        assert_eq!(info.enclave_cid, 0);
        assert_eq!(info.cpu_count, 0);
        assert_eq!(info.memory_mib, 0);
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
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: Some(true),
            enclave_name: None,
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
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: Some(false),
            enclave_name: None,
        };

        let mut enclave_manager = run_enclaves(&run_args, None)
            .expect("Run enclaves failed")
            .enclave_manager;
        let enclave_cid = enclave_manager.get_console_resources_enclave_cid().unwrap();
        let enclave_flags = enclave_manager
            .get_console_resources_enclave_flags()
            .unwrap();

        match run_args.debug_mode {
            Some(true) => assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, NE_ENCLAVE_DEBUG_MODE),
            _ => assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, 0),
        };

        let info = get_enclave_describe_info(&enclave_manager).unwrap();
        let replies: Vec<EnclaveDescribeInfo> = vec![info];
        let _reply = &replies[0];

        assert_eq!(enclave_console(enclave_cid, None).is_err(), true);

        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");
    }

    #[test]
    fn console_multiple_connect() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let build_args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: Some(true),
            enclave_name: None,
        };

        let mut enclave_manager = run_enclaves(&run_args, None)
            .expect("Run enclaves failed")
            .enclave_manager;
        let enclave_cid = enclave_manager.get_console_resources_enclave_cid().unwrap();
        let enclave_flags = enclave_manager
            .get_console_resources_enclave_flags()
            .unwrap();

        match run_args.debug_mode {
            Some(true) => assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, NE_ENCLAVE_DEBUG_MODE),
            _ => assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, 0),
        };

        let info = get_enclave_describe_info(&enclave_manager).unwrap();
        let replies: Vec<EnclaveDescribeInfo> = vec![info];
        let _reply = &replies[0];

        for _ in 0..3 {
            let console = Console::new(
                VMADDR_CID_HYPERVISOR,
                u32::try_from(enclave_cid).unwrap() + CID_TO_CONSOLE_PORT_OFFSET,
            )
            .expect("Failed to connect to the console");

            drop(console);

            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");
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
            run_describe_terminate_command_executer_docker_image();
            run_describe_terminate_simple_docker_image();
            run_describe_terminate_signed_enclave_image();
            run_describe_terminate_command_executer_docker_image();
            run_describe_terminate_signed_enclave_image();
        }
    }

    #[test]
    fn build_run_save_pcrs_describe() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
        )
        .expect("Docker build failed")
        .1;

        setup_env();
        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 64,
            debug_mode: Some(true),
            enclave_name: None,
        };
        let run_result = run_enclaves(&run_args, None).expect("Run enclaves failed");
        let mut enclave_manager = run_result.enclave_manager;
        let mut pcr_thread = run_result.pcr_thread;

        assert!(pcr_thread.is_some());

        enclave_manager
            .set_measurements(
                pcr_thread
                    .take()
                    .unwrap()
                    .join()
                    .expect("Failed to join thread.")
                    .expect("Failed to save PCRs."),
            )
            .expect("Failed to set measurements inside enclave handle.");

        get_enclave_describe_info(&enclave_manager).unwrap();
        let build_info = enclave_manager.get_measurements().unwrap();

        assert_eq!(
            build_info.measurements.get(&"PCR0".to_string()).unwrap(),
            "93a8a6a775cd1e1ab8b6121d1b0ce08e99e0976dabfa40663fa8ea9633421305de18c8f95aa2b82d3feb918fe912c838"
        );
        assert_eq!(
            build_info.measurements.get(&"PCR1".to_string()).unwrap(),
            "c35e620586e91ed40ca5ce360eedf77ba673719135951e293121cb3931220b00f87b5a15e94e25c01fecd08fc9139342"
        );
        assert_eq!(
            build_info.measurements.get(&"PCR2".to_string()).unwrap(),
            "52528ebeccf82b21cea3f3a9d055f1bb3d18254d77dcda2bbd7f39cecd96b7eea842913800cc1b0bc261b7ad1b83be90"
        );

        let _enclave_id = generate_enclave_id(0).expect("Describe enclaves failed");
        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");
    }

    #[test]
    fn build_describe_simple_eif() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
            signing_certificate: None,
            private_key: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
        )
        .expect("Docker build failed");

        let eif_info = describe_eif(args.output).unwrap();

        assert_eq!(eif_info.version, 3);
        assert_eq!(eif_info.is_signed, false);
        assert!(eif_info.cert_info.is_none());
    }

    #[test]
    fn build_describe_signed_simple_eif() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        let eif_path = format!("{}/test.eif", dir_path);
        let cert_path = format!("{}/cert.pem", dir_path);
        let key_path = format!("{}/key.pem", dir_path);
        generate_signing_cert_and_key(&cert_path, &key_path);

        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path,
            signing_certificate: Some(cert_path),
            private_key: Some(key_path),
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
        )
        .expect("Docker build failed");

        let eif_info = describe_eif(args.output).unwrap();

        assert_eq!(eif_info.version, 3);
        assert_eq!(eif_info.is_signed, true);
        assert!(eif_info.cert_info.is_some());
    }
}
