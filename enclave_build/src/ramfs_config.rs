// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::io::Write;
use tempfile::NamedTempFile;

#[derive(Debug, Serialize, Deserialize)]
struct BootstrapRamfsTemplate {
    files: (DirTemplate, FileTemplate, FileTemplate),
}

#[derive(Debug, Serialize, Deserialize)]
struct CustomerRamfsTemplate {
    prefix: String,
    init: Vec<String>,
    files: (
        DirTemplate,
        DirTemplate,
        DirTemplate,
        DirTemplate,
        DirTemplate,
        DirTemplate,
        FileTemplate,
        FileTemplate,
    ),
}

#[derive(Debug, Serialize, Deserialize)]
struct FileTemplate {
    path: String,
    source: String,
    mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DirTemplate {
    path: String,
    directory: bool,
    mode: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RamfsConfigError {
    TempfileError,
}

pub struct RamfsConfigGenerator {
    docker_image: String,
    init_path: String,
    nsm_path: String,
    cmd_path: String,
    env_path: String,
}

impl RamfsConfigGenerator {
    pub fn new(
        docker_image: String,
        init_path: String,
        nsm_path: String,
        cmd_path: String,
        env_path: String,
    ) -> Self {
        RamfsConfigGenerator {
            docker_image,
            init_path,
            nsm_path,
            cmd_path,
            env_path,
        }
    }

    pub fn get_bootstrap_ramfs(&self) -> Result<NamedTempFile, RamfsConfigError> {
        let ramfs = BootstrapRamfsTemplate {
            files: (
                DirTemplate {
                    path: String::from("dev"),
                    directory: true,
                    mode: String::from("0755"),
                },
                FileTemplate {
                    path: String::from("init"),
                    source: self.init_path.clone(),
                    mode: String::from("0755"),
                },
                FileTemplate {
                    path: String::from("nsm.ko"),
                    source: self.nsm_path.clone(),
                    mode: String::from("0755"),
                },
            ),
        };

        let config = serde_json::to_string(&ramfs);

        let mut file = NamedTempFile::new().map_err(|_| RamfsConfigError::TempfileError)?;

        file.write_all(config.unwrap().as_bytes())
            .map_err(|_| RamfsConfigError::TempfileError)?;

        Ok(file)
    }

    pub fn get_customer_ramfs(&self) -> Result<NamedTempFile, RamfsConfigError> {
        let ramfs = CustomerRamfsTemplate {
            prefix: "rootfs/".to_string(),
            init: vec![self.docker_image.clone()],
            // Each directory must stay under rootfs, as expected by init
            files: (
                DirTemplate {
                    path: String::from("rootfs/dev"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/run"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/sys"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/var"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/proc"),
                    directory: true,
                    mode: String::from("0755"),
                },
                DirTemplate {
                    path: String::from("rootfs/tmp"),
                    directory: true,
                    mode: String::from("0755"),
                },
                FileTemplate {
                    path: String::from("cmd"),
                    source: self.cmd_path.clone(),
                    mode: String::from("0644"),
                },
                FileTemplate {
                    path: String::from("env"),
                    source: self.env_path.clone(),
                    mode: String::from("0644"),
                },
            ),
        };

        let config = serde_json::to_string(&ramfs);

        let mut file = NamedTempFile::new().map_err(|_| RamfsConfigError::TempfileError)?;

        file.write_all(config.unwrap().as_bytes())
            .map_err(|_| RamfsConfigError::TempfileError)?;

        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    /// Test the ramfs config files (JSON, which linuxkit reads as YAML)
    #[test]
    fn test_ramfs() {
        let config_generator = RamfsConfigGenerator::new(
            String::from("docker_image"),
            String::from("path_to_init"),
            String::from("path_to_nsm"),
            String::from("path_to_cmd"),
            String::from("path_to_env"),
        );

        let mut bootstrap_data = String::new();
        let bootstrap_ramfs = config_generator.get_bootstrap_ramfs().unwrap();
        let mut bootstrap_ramfs = File::open(bootstrap_ramfs.path()).unwrap();
        bootstrap_ramfs.read_to_string(&mut bootstrap_data).unwrap();
        assert_eq!(
            bootstrap_data,
            r#"{"files":[{"path":"dev","directory":true,"mode":"0755"},{"path":"init","source":"path_to_init","mode":"0755"},{"path":"nsm.ko","source":"path_to_nsm","mode":"0755"}]}"#
        );

        let mut customer_data = String::new();
        let customer_ramfs = config_generator.get_customer_ramfs().unwrap();
        let mut customer_ramfs = File::open(customer_ramfs.path()).unwrap();
        customer_ramfs.read_to_string(&mut customer_data).unwrap();
        assert_eq!(
            customer_data,
            r#"{"prefix":"rootfs/","init":["docker_image"],"files":[{"path":"rootfs/dev","directory":true,"mode":"0755"},{"path":"rootfs/run","directory":true,"mode":"0755"},{"path":"rootfs/sys","directory":true,"mode":"0755"},{"path":"rootfs/var","directory":true,"mode":"0755"},{"path":"rootfs/proc","directory":true,"mode":"0755"},{"path":"rootfs/tmp","directory":true,"mode":"0755"},{"path":"cmd","source":"path_to_cmd","mode":"0644"},{"path":"env","source":"path_to_env","mode":"0644"}]}"#
        );
    }
}
