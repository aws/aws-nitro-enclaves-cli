// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use nitro_cli::common::commands_parser::{
        BuildEnclavesArgs, RunEnclavesArgs, TerminateEnclavesArgs,
    };
    use nitro_cli::common::json_output::EnclaveDescribeInfo;
    use nitro_cli::enclave_proc::commands::{describe_enclaves, run_enclaves, terminate_enclaves};
    use nitro_cli::enclave_proc::resource_manager::NE_ENCLAVE_DEBUG_MODE;
    use nitro_cli::enclave_proc::utils::{
        flags_to_string, generate_enclave_id, get_enclave_describe_info,
    };
    use nitro_cli::utils::{Console, PcrType};
    use nitro_cli::{
        build_enclaves, build_from_docker, describe_eif, enclave_console, get_file_pcr,
        new_enclave_name,
    };
    use nitro_cli::{CID_TO_CONSOLE_PORT_OFFSET, VMADDR_CID_HYPERVISOR};
    use serde_json::json;
    use std::convert::TryInto;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use tempfile::{tempdir, TempDir};

    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509Name, X509};

    // Remote Docker image
    const SAMPLE_DOCKER: &str = "public.ecr.aws/aws-nitro-enclaves/hello:v1";

    #[cfg(target_arch = "x86_64")]
    mod sample_docker_pcrs {
        /// PCR0
        pub const IMAGE_PCR: &str = "7f3287dd1c4dbc49513abfaabc7f6afe79ab8269743c0c4ee55bb9e92d4f0a36f0cae7c0356d0bfec78b59b4d20c689c";
        /// PCR1
        pub const KERNEL_PCR: &str = "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f";
        /// PCR2
        pub const APP_PCR: &str = "dd61366a5424eea46f60c4e9d59e6c645a46420ccf962550ee1f3c109d230f88ec23667617aeaac425a1f50fe8e384d7";
    }

    #[cfg(target_arch = "aarch64")]
    mod sample_docker_pcrs {
        /// PCR0
        pub const IMAGE_PCR: &str = "b32a774b09fff4324a6405dacf3f5aa462a75e554e3a563ee64708abd585456bb480fdf70b2e2c2ab9ec205717bc690e";
        /// PCR1
        pub const KERNEL_PCR: &str = "5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16";
        /// PCR2
        pub const APP_PCR: &str = "9397173aa14e47fe087e8aeb63928a233db048e290830de6ce2041f4580f83b599c48432467601bed8a4883e9d94ff10";
    }

    // Local Docker image
    const COMMAND_EXECUTER_DOCKER: &str = "command_executer:eif";

    pub const MAX_BOOT_TIMEOUT_SEC: u64 = 9;

    use std::convert::TryFrom;
    use std::time::Duration;

    fn setup_env() {
        if std::env::var("NITRO_CLI_BLOBS").is_err() {
            std::env::set_var("NITRO_CLI_BLOBS", "/usr/share/nitro_enclaves/blobs");
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
            img_name: None,
            img_version: None,
            metadata: None,
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        let measurements = build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed")
        .1;
        assert_eq!(
            measurements.get("PCR0").unwrap(),
            sample_docker_pcrs::IMAGE_PCR
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            sample_docker_pcrs::KERNEL_PCR
        );
        assert_eq!(
            measurements.get("PCR2").unwrap(),
            sample_docker_pcrs::APP_PCR
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        let measurements = build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed")
        .1;

        assert_eq!(
            measurements.get("PCR0").unwrap(),
            sample_docker_pcrs::IMAGE_PCR
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            sample_docker_pcrs::KERNEL_PCR
        );
        assert_eq!(
            measurements.get("PCR2").unwrap(),
            sample_docker_pcrs::APP_PCR
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
            &build_args.img_name,
            &build_args.img_version,
            &build_args.metadata,
        )
        .expect("Docker build failed");

        let args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
            &build_args.img_name,
            &build_args.img_version,
            &build_args.metadata,
        )
        .expect("Docker build failed");

        let args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 256,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
            &build_args.img_name,
            &build_args.img_version,
            &build_args.metadata,
        )
        .expect("Docker build failed");

        let args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 2046,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
        };
        run_describe_terminate(args);
    }

    fn run_describe_terminate(args: RunEnclavesArgs) {
        setup_env();
        let req_enclave_cid = args.enclave_cid;
        let req_mem_size = args.memory_mib;
        let req_nr_cpus: u64 = args.cpu_count.unwrap().try_into().unwrap();
        let debug_mode = args.debug_mode;
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

        if debug_mode {
            assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, NE_ENCLAVE_DEBUG_MODE);
        } else {
            assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, 0);
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
        let boot = contents.contains("nsm: loading out-of-tree module");

        assert_eq!(boot, true);

        let info = get_enclave_describe_info(&enclave_manager, false).unwrap();
        let replies: Vec<EnclaveDescribeInfo> = vec![info];
        let reply = &replies[0];
        let flags = &reply.flags;

        assert_eq!({ reply.enclave_cid }, enclave_cid);
        assert_eq!(reply.memory_mib, req_mem_size);
        assert_eq!({ reply.cpu_count }, req_nr_cpus);
        assert_eq!(reply.state, "RUNNING");
        if debug_mode {
            assert_eq!(flags, "DEBUG_MODE");
        } else {
            assert_eq!(flags, "NONE");
        }
        let _enclave_id = generate_enclave_id(0).expect("Describe enclaves failed");

        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");

        let info = get_enclave_describe_info(&enclave_manager, false).unwrap();

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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
            &build_args.img_name,
            &build_args.img_version,
            &build_args.metadata,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
            &build_args.img_name,
            &build_args.img_version,
            &build_args.metadata,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: false,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
        };

        let mut enclave_manager = run_enclaves(&run_args, None)
            .expect("Run enclaves failed")
            .enclave_manager;
        let enclave_cid = enclave_manager.get_console_resources_enclave_cid().unwrap();
        let enclave_flags = enclave_manager
            .get_console_resources_enclave_flags()
            .unwrap();

        if run_args.debug_mode {
            assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, NE_ENCLAVE_DEBUG_MODE);
        } else {
            assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, 0);
        };

        let info = get_enclave_describe_info(&enclave_manager, false).unwrap();
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &build_args.docker_uri,
            &build_args.docker_dir,
            &build_args.output,
            &build_args.signing_certificate,
            &build_args.private_key,
            &build_args.img_name,
            &build_args.img_version,
            &build_args.metadata,
        )
        .expect("Docker build failed");

        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: build_args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
        };

        let mut enclave_manager = run_enclaves(&run_args, None)
            .expect("Run enclaves failed")
            .enclave_manager;
        let enclave_cid = enclave_manager.get_console_resources_enclave_cid().unwrap();
        let enclave_flags = enclave_manager
            .get_console_resources_enclave_flags()
            .unwrap();

        if run_args.debug_mode {
            assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, NE_ENCLAVE_DEBUG_MODE);
        } else {
            assert_eq!(enclave_flags & NE_ENCLAVE_DEBUG_MODE, 0);
        }

        let info = get_enclave_describe_info(&enclave_manager, false).unwrap();
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed");

        setup_env();
        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
        };
        let run_result = run_enclaves(&run_args, None).expect("Run enclaves failed");
        let mut enclave_manager = run_result.enclave_manager;
        let mut describe_thread = run_result.describe_thread;

        assert!(describe_thread.is_some());

        let thread_result = describe_thread
            .take()
            .unwrap()
            .join()
            .expect("Failed to join thread.")
            .expect("Failed to save PCRs.");

        enclave_manager
            .set_measurements(thread_result.measurements)
            .expect("Failed to set measurements inside enclave handle.");

        get_enclave_describe_info(&enclave_manager, false).unwrap();
        let build_info = enclave_manager.get_measurements().unwrap();
        let measurements = build_info.measurements;

        assert_eq!(
            measurements.get("PCR0").unwrap(),
            sample_docker_pcrs::IMAGE_PCR
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            sample_docker_pcrs::KERNEL_PCR
        );
        assert_eq!(
            measurements.get("PCR2").unwrap(),
            sample_docker_pcrs::APP_PCR
        );

        let _enclave_id = generate_enclave_id(0).expect("Describe enclaves failed");
        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");
    }

    fn create_metadata_json(dir: &TempDir) {
        let file_path = dir.path().join("meta.json");
        let mut meta_file = File::create(file_path).unwrap();
        let content = json!({
            "AppVersion": "3.2",
            "TestField": "Some info",
            "CustomField": "Added by user",
        });
        let json_bytes = serde_json::to_vec(&content).unwrap();
        meta_file.write_all(&json_bytes[..]).unwrap();
    }

    #[test]
    fn build_with_metadata_run_describe() {
        let dir = tempdir().unwrap();
        create_metadata_json(&dir);
        let eif_path = dir.path().join("test.eif");
        let meta_path = dir.path().join("meta.json");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
            signing_certificate: None,
            private_key: None,
            img_name: Some("TestName".to_string()),
            img_version: Some("1.0".to_string()),
            metadata: Some(meta_path.to_str().unwrap().to_string()),
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed");

        setup_env();
        let run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("testName".to_string()),
        };
        let run_result = run_enclaves(&run_args, None).expect("Run enclaves failed");
        let mut enclave_manager = run_result.enclave_manager;
        let mut describe_thread = run_result.describe_thread;

        assert!(describe_thread.is_some());

        let thread_result = describe_thread
            .take()
            .unwrap()
            .join()
            .expect("Failed to join thread.")
            .expect("Failed to save PCRs.");

        enclave_manager
            .set_measurements(thread_result.measurements)
            .expect("Failed to set measurements inside enclave handle.");
        let metadata = thread_result.metadata.expect("Failed to fetch metadata");
        enclave_manager
            .set_metadata(metadata.clone())
            .expect("Failed to set metadata inside enclave handle.");

        assert_eq!(metadata.build_info.img_os, "Linux");
        assert_eq!(metadata.build_info.build_tool, env!("CARGO_PKG_NAME"));
        assert_eq!(
            metadata.build_info.build_tool_version,
            env!("CARGO_PKG_VERSION")
        );

        assert_eq!(
            *metadata
                .docker_info
                .get("RepoTags")
                .unwrap()
                .get(0)
                .unwrap(),
            json!("public.ecr.aws/aws-nitro-enclaves/hello:v1")
        );

        assert_eq!(
            *metadata.custom_info.get("AppVersion").unwrap(),
            json!("3.2")
        );
        assert_eq!(
            *metadata.custom_info.get("TestField").unwrap(),
            json!("Some info")
        );
        assert_eq!(
            *metadata.custom_info.get("CustomField").unwrap(),
            json!("Added by user")
        );

        let _enclave_id = generate_enclave_id(0).expect("Describe enclaves failed");
        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");
    }

    #[test]
    fn build_run_default_enclave_name() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: SAMPLE_DOCKER.to_string(),
            docker_dir: None,
            output: eif_path.to_str().unwrap().to_string(),
            signing_certificate: None,
            private_key: None,
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed");

        setup_env();
        let mut run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: args.output,
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: true,
            attach_console: false,
            enclave_name: None,
        };
        let names = Vec::new();
        run_args.enclave_name =
            Some(new_enclave_name(run_args.clone(), names).expect("Failed to set new name."));
        let run_result = run_enclaves(&run_args, None).expect("Run enclaves failed");
        let mut enclave_manager = run_result.enclave_manager;

        get_enclave_describe_info(&enclave_manager, false).unwrap();
        let enclave_name = enclave_manager.enclave_name.clone();

        // Assert that EIF name has been set
        assert_eq!(enclave_name, "test");

        terminate_enclaves(&mut enclave_manager, None).expect("Terminate enclaves failed");
    }

    #[test]
    fn new_enclave_names() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");

        let mut run_args = RunEnclavesArgs {
            enclave_cid: None,
            eif_path: eif_path.to_str().unwrap().to_string(),
            cpu_ids: None,
            cpu_count: Some(2),
            memory_mib: 128,
            debug_mode: true,
            attach_console: false,
            enclave_name: Some("enclaveName".to_string()),
        };
        let mut names = Vec::new();
        let name =
            new_enclave_name(run_args.clone(), names.clone()).expect("Failed to set new name.");
        names.push(name);

        run_args.enclave_name = Some("enclaveNameOther".to_string());
        let name =
            new_enclave_name(run_args.clone(), names.clone()).expect("Failed to set new name.");
        names.push(name);

        run_args.enclave_name = Some("enclaveName".to_string());
        let name =
            new_enclave_name(run_args.clone(), names.clone()).expect("Failed to set new name.");
        names.push(name);

        run_args.enclave_name = Some("enclaveName".to_string());
        let name = new_enclave_name(run_args, names.clone()).expect("Failed to set new name.");
        names.push(name);

        assert_eq!(
            names,
            vec![
                "enclaveName",
                "enclaveNameOther",
                "enclaveName_1",
                "enclaveName_2"
            ]
        );
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed");

        let eif_info = describe_eif(args.output).unwrap();

        assert_eq!(eif_info.version, 4);
        assert_eq!(eif_info.is_signed, false);
        assert!(eif_info.cert_info.is_none());
        assert!(eif_info.crc_check);
        assert!(eif_info.sign_check.is_none());
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
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed");

        let eif_info = describe_eif(args.output).unwrap();

        assert_eq!(eif_info.version, 4);
        assert_eq!(eif_info.is_signed, true);
        assert!(eif_info.cert_info.is_some());
        assert!(eif_info.crc_check);
        assert!(eif_info.sign_check.unwrap());
    }

    #[test]
    fn get_certificate_pcr() {
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
            signing_certificate: Some(cert_path.clone()),
            private_key: Some(key_path),
            img_name: None,
            img_version: None,
            metadata: None,
        };

        build_from_docker(
            &args.docker_uri,
            &args.docker_dir,
            &args.output,
            &args.signing_certificate,
            &args.private_key,
            &args.img_name,
            &args.img_version,
            &args.metadata,
        )
        .expect("Docker build failed");

        // Describe EIF and get PCR8
        let eif_info = describe_eif(args.output).unwrap();
        // Hash signing certificate and verify that PCR8 is the same (identifying the certificate)
        let pcr = get_file_pcr(cert_path, PcrType::SigningCertificate).unwrap();

        assert_eq!(
            eif_info
                .build_info
                .measurements
                .get(&"PCR8".to_string())
                .unwrap(),
            pcr.get(&"PCR8".to_string()).unwrap(),
        );
    }
}
