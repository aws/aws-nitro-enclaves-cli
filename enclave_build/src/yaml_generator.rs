// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::io::Write;
use tempfile::NamedTempFile;

#[derive(Debug, Serialize, Deserialize)]
struct BootstrapRamfsTemplate {
    files: (DirTemplate, FileTemplate),
}

#[derive(Debug, Serialize, Deserialize)]
struct CustomerRamfsTemplate {
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

#[derive(Debug, PartialEq)]
pub enum YamlGeneratorError {
    TempfileError,
}

pub struct YamlGenerator {
    docker_image: String,
    init_path: String,
    cmd_path: String,
    env_path: String,
}

impl YamlGenerator {
    pub fn new(
        docker_image: String,
        init_path: String,
        cmd_path: String,
        env_path: String,
    ) -> Self {
        YamlGenerator {
            docker_image,
            init_path,
            cmd_path,
            env_path,
        }
    }

    pub fn get_bootstrap_ramfs(&self) -> Result<NamedTempFile, YamlGeneratorError> {
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
            ),
        };

        let yaml = serde_yaml::to_string(&ramfs);

        let mut file = NamedTempFile::new().map_err(|_| YamlGeneratorError::TempfileError)?;

        file.write_all(yaml.unwrap().as_bytes())
            .map_err(|_| YamlGeneratorError::TempfileError)?;

        Ok(file)
    }

    pub fn get_customer_ramfs(&self) -> Result<NamedTempFile, YamlGeneratorError> {
        let ramfs = CustomerRamfsTemplate {
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

        let yaml = serde_yaml::to_string(&ramfs);

        let mut file = NamedTempFile::new().map_err(|_| YamlGeneratorError::TempfileError)?;

        file.write_all(yaml.unwrap().as_bytes())
            .map_err(|_| YamlGeneratorError::TempfileError)?;

        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Test YAML config files are the same as the ones written by hand
    #[test]
    fn test_ramfs() {
        let yaml_generator = YamlGenerator::new(
            String::from("hello-world:latest"),
            String::from("build/init"),
            String::from("build/cmd"),
            String::from("build/env"),
        );

        let bootstrap_ramfs = yaml_generator.get_bootstrap_ramfs().unwrap();
        let customer_ramfs = yaml_generator.get_customer_ramfs().unwrap();

        let status = Command::new("cmp")
            .arg(bootstrap_ramfs.path().to_str().unwrap())
            .arg("test_data/linuxkit.yml")
            .status()
            .expect("command");
        assert!(status.success());

        let status = Command::new("cmp")
            .arg(customer_ramfs.path().to_str().unwrap())
            .arg("test_data/default.yml")
            .status()
            .expect("command");
        assert!(status.success());
    }
}
