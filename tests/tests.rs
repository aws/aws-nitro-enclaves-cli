// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use enclave_api::common::json_output::EnclaveDescribeInfo;
    use enclave_api::enclave_proc::resource_manager::EnclaveState;
    use enclave_api::{Enclave, EnclaveConf, EnclaveCpuConfig, EnclaveFlags};
    use nitro_cli::commands_parser::{BuildEnclavesArgs, RunEnclavesArgs, TerminateEnclavesArgs};
    use nitro_cli::utils::Console;
    use nitro_cli::{build_enclaves, build_from_docker, enclave_console};
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

    const SAMPLE_DOCKER: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample";
    const ENCLAVE_SDK_DOCKER: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:enclave-sdk";

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
            "d94e68dc2dba3e703fb7dd44c94418372c2c1c311e53f30bd24efebb951edaaa002b346da8b11419aa35eb1a5269a8ab"
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            "aca6e62ffbf5f7deccac452d7f8cee1b94048faf62afc16c8ab68c9fed8c38010c73a669f9a36e596032f0b973d21895"
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
    fn build_enclaves_enclave_sdk() {
        let dir = tempdir().unwrap();
        let eif_path = dir.path().join("test.eif");
        setup_env();
        let args = BuildEnclavesArgs {
            docker_uri: ENCLAVE_SDK_DOCKER.to_string(),
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
            "8eac6906e2a0b9963f0591c5e69e5cbbdfd845d68c7e3685b73dad0fb06673dc22c2c02d22d047ee8bb15fc6e1f85a24"
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            "aca6e62ffbf5f7deccac452d7f8cee1b94048faf62afc16c8ab68c9fed8c38010c73a669f9a36e596032f0b973d21895"
        );
        assert_eq!(
            measurements.get("PCR2").unwrap(),
            "bd60ceba51d463a519545688123a91fd88b798405034b1dae256bfc3559d9e48b3be63b073ebcb9e0aa506235774d514"
        );
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
            "d94e68dc2dba3e703fb7dd44c94418372c2c1c311e53f30bd24efebb951edaaa002b346da8b11419aa35eb1a5269a8ab"
        );
        assert_eq!(
            measurements.get("PCR1").unwrap(),
            "aca6e62ffbf5f7deccac452d7f8cee1b94048faf62afc16c8ab68c9fed8c38010c73a669f9a36e596032f0b973d21895"
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

        let conf = EnclaveConf {
            cid: None,
            eif_path: build_args.output,
            cpu_conf: EnclaveCpuConfig::Count(2),
            mem_size: 256,
            flags: EnclaveFlags::DEBUG_MODE,
        };
        run_describe_terminate(conf);
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

        let conf = EnclaveConf {
            cid: None,
            eif_path: build_args.output,
            cpu_conf: EnclaveCpuConfig::Count(2),
            mem_size: 256,
            flags: EnclaveFlags::DEBUG_MODE,
        };
        run_describe_terminate(conf);
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

        let conf = EnclaveConf {
            cid: None,
            eif_path: build_args.output,
            cpu_conf: EnclaveCpuConfig::Count(2),
            mem_size: 1024,
            flags: EnclaveFlags::DEBUG_MODE,
        };
        run_describe_terminate(conf);
    }

    fn run_describe_terminate(conf: EnclaveConf) {
        setup_env();
        let enclave = Enclave::run(conf.clone()).expect("Running enclave failed");
        if let Some(req_enclave_cid) = conf.cid {
            assert_eq!(req_enclave_cid, enclave.get_enclave_cid());
        }

        let console = Console::new_nonblocking(
            VMADDR_CID_HYPERVISOR,
            u32::try_from(enclave.get_enclave_cid()).unwrap() + CID_TO_CONSOLE_PORT_OFFSET,
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

        let mut info = Enclave::describe(enclave.get_enclave_id().to_string())
            .expect("Describe enclaves failed");
        if let Some(conf_cid) = conf.cid {
            assert_eq!(info.get_enclave_cid(), conf_cid);
        }
        assert!(info.get_memory_size() >= conf.mem_size);
        match conf.cpu_conf {
            EnclaveCpuConfig::List(v) => assert_eq!(
                info.get_cpu_ids()
                    .iter()
                    .zip(v.iter())
                    .filter(|&(a, b)| a == b)
                    .count(),
                v.len()
            ),
            EnclaveCpuConfig::Count(n) => assert_eq!(info.get_cpu_count(), n as u64),
        };
        if let EnclaveState::Running = info.get_state() {
        } else {
            panic!("Enclave not running.");
        }
        assert_eq!(info.get_flags(), conf.flags);

        info.terminate().expect("Terminate enclaves failed");
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

        let conf = EnclaveConf {
            cid: None,
            eif_path: build_args.output,
            cpu_conf: EnclaveCpuConfig::Count(2),
            mem_size: 128,
            flags: EnclaveFlags::DEBUG_MODE,
        };

        run_describe_terminate(conf);
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

        let conf = EnclaveConf {
            cid: None,
            eif_path: build_args.output,
            cpu_conf: EnclaveCpuConfig::Count(2),
            mem_size: 128,
            flags: EnclaveFlags::NONE,
        };

        let mut enclave = Enclave::run(conf.clone()).expect("Run enclave failed");
        let enclave_cid = enclave.get_enclave_cid();

        let _info = Enclave::describe(enclave.get_enclave_id()).expect("Describe enclave failed");
        assert_eq!(enclave_console(enclave_cid).is_err(), true);

        enclave.terminate().expect("Terminate enclaves failed");
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

        let conf = EnclaveConf {
            cid: None,
            eif_path: build_args.output,
            cpu_conf: EnclaveCpuConfig::Count(2),
            mem_size: 128,
            flags: EnclaveFlags::DEBUG_MODE,
        };

        let mut enclave = Enclave::run(conf.clone()).expect("Run enclave failed");
        let enclave_cid = enclave.get_enclave_cid();

        let _info = Enclave::describe(enclave.get_enclave_id()).expect("Describe enclave failed");

        for _ in 0..3 {
            let console = Console::new(
                VMADDR_CID_HYPERVISOR,
                u32::try_from(enclave_cid).unwrap() + CID_TO_CONSOLE_PORT_OFFSET,
            )
            .expect("Failed to connect to the console");

            drop(console);

            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        enclave.terminate().expect("Terminate enclaves failed");
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
            run_describe_terminate_signed_enclave_image();
            run_describe_terminate_enclave_sdk_docker_image();
            run_describe_terminate_signed_enclave_image();
        }
    }
}
