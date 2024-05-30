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
pub enum YamlGeneratorError {
    TempfileError,
}

pub struct YamlGenerator {
    docker_image: String,
    init_path: String,
    nsm_path: String,
    cmd_path: String,
    env_path: String,
}

impl YamlGenerator {
    pub fn new(
        docker_image: String,
        init_path: String,
        nsm_path: String,
        cmd_path: String,
        env_path: String,
    ) -> Self {
        YamlGenerator {
            docker_image,
            init_path,
            nsm_path,
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
                FileTemplate {
                    path: String::from("nsm.ko"),
                    source: self.nsm_path.clone(),
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
    use std::fs::File;
    use std::io::Read;

    /// Test YAML config files are the same as the ones written by hand
    #[test]
    fn test_ramfs() {
        let yaml_generator = YamlGenerator::new(
            String::from("docker_image"),
            String::from("path_to_init"),
            String::from("path_to_nsm"),
            String::from("path_to_cmd"),
            String::from("path_to_env"),
        );

        let mut bootstrap_data = String::new();
        let bootstrap_ramfs = yaml_generator.get_bootstrap_ramfs().unwrap();
        let mut bootstrap_ramfs = File::open(bootstrap_ramfs.path()).unwrap();
        bootstrap_ramfs.read_to_string(&mut bootstrap_data).unwrap();
        assert_eq!(
            bootstrap_data,
            "---\
             \nfiles:\
             \n  - path: dev\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: init\
             \n    source: path_to_init\
             \n    mode: \"0755\"\
             \n  - path: nsm.ko\
             \n    source: path_to_nsm\
             \n    mode: \"0755\"\
             \n\
             "
        );

        let mut customer_data = String::new();
        let customer_ramfs = yaml_generator.get_customer_ramfs().unwrap();
        let mut customer_ramfs = File::open(customer_ramfs.path()).unwrap();
        customer_ramfs.read_to_string(&mut customer_data).unwrap();
        assert_eq!(
            customer_data,
            "---\
             \nprefix: rootfs/\
             \ninit:\
             \n  - docker_image\
             \nfiles:\
             \n  - path: rootfs/dev\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/run\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/sys\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/var\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/proc\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: rootfs/tmp\
             \n    directory: true\
             \n    mode: \"0755\"\
             \n  - path: cmd\
             \n    source: path_to_cmd\
             \n    mode: \"0644\"\
             \n  - path: env\
             \n    source: path_to_env\
             \n    mode: \"0644\"\
             \n\
             "
        );
    }
}
