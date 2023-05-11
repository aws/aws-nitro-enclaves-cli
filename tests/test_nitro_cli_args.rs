// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

#[cfg(test)]
mod test_nitro_cli_args {
    use clap::{App, AppSettings, Arg, SubCommand};
    use nitro_cli::create_app;

    #[test]
    fn terminate_enclave_enclave_id_arg_is_required() {
        let app = create_app!();
        let args = vec!["nitro cli", "terminate-enclave"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn terminate_enclave_enclave_id_takes_value() {
        let app = create_app!();
        let args = vec!["nitro cli", "terminate-enclave", "--enclave-id"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn terminate_enclave_enclave_id_takes_one_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "terminate-enclave",
            "--enclave-id",
            "i-1234_enc123",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn terminate_enclave_enclave_id_takes_multiple_values() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "terminate-enclave",
            "--enclave-id",
            "1234",
            "135",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn terminate_enclave_name() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "terminate-enclave",
            "--enclave-name",
            "testName",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn terminate_enclave_name_is_required() {
        let app = create_app!();
        let args = vec!["nitro cli", "terminate-enclave", "--enclave-name"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn terminate_enclave_name_takes_multiple_values() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "terminate-enclave",
            "--enclave-name",
            "name1",
            "name2",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn describe_enclaves_correct_command() {
        let app = create_app!();
        let args = vec!["nitro cli", "describe-enclaves"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn describe_enclaves_request_metadata_correct() {
        let app = create_app!();
        let args = vec!["nitro cli", "describe-enclaves", "--metadata"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn describe_eif_correct_command() {
        let app = create_app!();
        let args = vec!["nitro cli", "describe-eif", "--eif-path", "dir/image.eif"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn describe_eif_without_path_arg() {
        let app = create_app!();
        let args = vec!["nitro cli", "describe-eif", "--eif-path"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn console_without_enclave_id_arg_is_required() {
        let app = create_app!();
        let args = vec!["nitro cli", "console"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn console_enclave_id_takes_value() {
        let app = create_app!();
        let args = vec!["nitro cli", "console", "--enclave-id"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn console_correct_command() {
        let app = create_app!();
        let args = vec!["nitro cli", "console", "--enclave-id", "i-1234_enc123"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn console_enclave_id_takes_one_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "console",
            "--enclave-id",
            "i-1234_enc123",
            "135",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn console_enclave_name() {
        let app = create_app!();
        let args = vec!["nitro cli", "console", "--enclave-name", "testName"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn console_enclave_name_is_required() {
        let app = create_app!();
        let args = vec!["nitro cli", "console", "--enclave-name"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn console_enclave_name_takes_multiple_values() {
        let app = create_app!();
        let args = vec!["nitro cli", "console", "--enclave-name", "name1", "name2"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn console_correct_disconnect_timeout_command() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "console",
            "--enclave-id",
            "i-1234_enc123",
            "--disconnect-timeout",
            "10",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn console_correct_disconnect_timeout_command_with_name() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "console",
            "--enclave-name",
            "testName",
            "--disconnect-timeout",
            "10",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn console_disconnect_timeout_takes_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "console",
            "--enclave-id",
            "i-1234_enc123",
            "--disconnect-timeout",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn build_enclave_docker_uri_arg_is_required() {
        let app = create_app!();
        let args = vec!["nitro cli", "build-enclave", "--output-file", "image.eif"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn build_enclave_docker_dir_arg_is_not_required() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "build-enclave",
            "--docker-uri",
            "dkr.ecr.us-east-1.amazonaws.com/stronghold-develss",
            "--output-file",
            "image.eif",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn build_enclave_output_arg_is_required() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "build-enclave",
            "--docker-uri",
            "dkr.ecr.us-east-1.amazonaws.com/stronghold-develss",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn build_enclave_correct_command() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "build-enclave",
            "--docker-uri",
            "dkr.ecr.us-east-1.amazonaws.com/stronghold-develss",
            "--docker-dir",
            "dir/",
            "--output-file",
            "image.eif",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn build_signed_enclave_correct_command() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "build-enclave",
            "--docker-uri",
            "dkr.ecr.us-east-1.amazonaws.com/stronghold-develss",
            "--docker-dir",
            "dir/",
            "--output-file",
            "image.eif",
            "--signing-certificate",
            "cert.pem",
            "--private-key",
            "key.pem",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn build_enclave_with_metadata_correct_command() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "build-enclave",
            "--docker-uri",
            "dkr.ecr.us-east-1.amazonaws.com/stronghold-develss",
            "--docker-dir",
            "dir/",
            "--output-file",
            "image.eif",
            "--name",
            "TestName",
            "--version",
            "4.0",
            "--metadata",
            "meta.json",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn build_enclave_with_metadata_file_is_required() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "build-enclave",
            "--docker-uri",
            "dkr.ecr.us-east-1.amazonaws.com/stronghold-develss",
            "--docker-dir",
            "dir/",
            "--output-file",
            "image.eif",
            "--name",
            "TestName",
            "--version",
            "4.0",
            "--metadata",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_correct_command_with_eif_path() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "10001",
            "--memory",
            "512",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
            "1234",
            "--debug-mode",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn run_enclave_cpu_ids_arg_is_required() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--memory",
            "512",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
            "12345",
            "--debug-mode",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_cpu_ids_takes_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "--memory",
            "512",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
            "12345",
            "--debug-mode",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_cpu_ids_takes_multiple_values() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "10001",
            "--memory",
            "512",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
            "12345",
            "--debug-mode",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn run_enclave_memory_arg_is_required() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
            "12345",
            "--debug-mode",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_memory_takes_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "--memory",
            "--eif-path",
            "dir/image.eif",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_enclave_cid_takes_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "--memory",
            "512",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_console_does_not_take_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "--memory",
            "512",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
            "12345",
            "--debug-mode",
            "123",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_console_eif_path_is_required() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "--memory",
            "512",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_eif_path_takes_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "10001",
            "--memory",
            "512",
            "--eif-path",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_config_does_not_take_value() {
        let app = create_app!();
        let args = vec!["nitro cli", "run-enclave", "--config"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_config_takes_multiple_values() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--config",
            "config1.json",
            "config2.json",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_try_to_overwrite_config() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--config",
            "config.json",
            "--cpu-count",
            "2",
            "--memory",
            "1024",
            "--eif-path",
            "dir/image.eif",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn run_enclave_correct_command_with_name() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "10001",
            "--memory",
            "512",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
            "1234",
            "--debug-mode",
            "--enclave-name",
            "testName",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn run_enclave_name_takes_value() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "run-enclave",
            "--cpu-ids",
            "10000",
            "10001",
            "--memory",
            "512",
            "--eif-path",
            "dir/image.eif",
            "--enclave-cid",
            "1234",
            "--debug-mode",
            "--enclave-name",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn pcr_input_takes_value() {
        let app = create_app!();
        let args = vec!["nitro cli", "pcr", "--input"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn pcr_certificate_takes_value() {
        let app = create_app!();
        let args = vec!["nitro cli", "pcr", "--signing-certificate"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn pcr_conflicting_arguments() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "pcr",
            "--signing-certificate",
            "cert.pem",
            "--input",
            "test.bin",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn pcr_certificate_correct() {
        let app = create_app!();
        let args = vec!["nitro cli", "pcr", "--signing-certificate", "cert.pem"];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn sign_eif_pkey_correct() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "sign-eif",
            "--signing-certificate",
            "cert.pem",
            "--private-key",
            "key.pem",
            "--eif-path",
            "image.eif",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn sign_eif_kms_correct() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "sign-eif",
            "--signing-certificate",
            "cert.pem",
            "--kms-key-arn",
            "a23f54c8-b2ce-1a5c-a2db-f444a5b3d22d",
            "--kms-key-region",
            "eu-west-1",
            "--eif-path",
            "image.eif",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn sign_eif_kms_no_region_correct() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "sign-eif",
            "--signing-certificate",
            "cert.pem",
            "--kms-key-arn",
            "a23f54c8-b2ce-1a5c-a2db-f444a5b3d22d",
            "--eif-path",
            "image.eif",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn sign_eif_conflicting_arguments() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "sign-eif",
            "--signing-certificate",
            "cert.pem",
            "--private-key",
            "key.pem",
            "--kms-key-arn",
            "a23f54c8-b2ce-1a5c-a2db-f444a5b3d22d",
            "--eif-path",
            "image.eif",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }

    #[test]
    fn build_kms_signed_enclave_correct_command() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "build-enclave",
            "--docker-uri",
            "dkr.ecr.us-east-1.amazonaws.com/stronghold-develss",
            "--docker-dir",
            "dir/",
            "--output-file",
            "image.eif",
            "--signing-certificate",
            "cert.pem",
            "--kms-key-arn",
            "a23f54c8-b2ce-1a5c-a2db-f444a5b3d22d",
            "--kms-key-region",
            "eu-west-1",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), false)
    }

    #[test]
    fn build_kms_signed_enclave_conflicting_arguments() {
        let app = create_app!();
        let args = vec![
            "nitro cli",
            "build-enclave",
            "--docker-uri",
            "dkr.ecr.us-east-1.amazonaws.com/stronghold-develss",
            "--docker-dir",
            "dir/",
            "--output-file",
            "image.eif",
            "--signing-certificate",
            "cert.pem",
            "--kms-key-arn",
            "a23f54c8-b2ce-1a5c-a2db-f444a5b3d22d",
            "--kms-key-region",
            "eu-west-1",
            "--private-key",
            "key.pem",
        ];

        assert_eq!(app.get_matches_from_safe(args).is_err(), true)
    }
}
