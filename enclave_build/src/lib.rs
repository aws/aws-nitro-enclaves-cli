// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::path::Path;
use std::process::Command;

mod docker;
mod yaml_generator;
use docker::DockerUtil;
use eif_utils::EifBuilder;
use sha2::Digest;
use std::collections::BTreeMap;
use yaml_generator::YamlGenerator;

pub struct Docker2Eif<'a> {
    docker_image: String,
    docker: DockerUtil,
    init_path: String,
    kernel_img_path: String,
    cmdline: String,
    linuxkit_path: String,
    artifacts_prefix: String,
    output: &'a mut File,
}

#[derive(Debug, PartialEq)]
pub enum Docker2EifError {
    DockerError,
    DockerfilePathError,
    ImagePullError,
    InitPathError,
    KernelPathError,
    LinuxkitExecError,
    LinuxkitPathError,
    ArtifactsPrefixError,
    RamfsError,
    RemoveFileError,
}

impl<'a> Docker2Eif<'a> {
    pub fn new(
        docker_image: String,
        init_path: String,
        kernel_img_path: String,
        cmdline: String,
        linuxkit_path: String,
        output: &'a mut File,
        artifacts_prefix: String,
    ) -> Result<Self, Docker2EifError> {
        let docker = DockerUtil::new(docker_image.clone());

        if !Path::new(&init_path).is_file() {
            return Err(Docker2EifError::InitPathError);
        } else if !Path::new(&kernel_img_path).is_file() {
            return Err(Docker2EifError::KernelPathError);
        } else if !Path::new(&linuxkit_path).is_file() {
            return Err(Docker2EifError::LinuxkitPathError);
        } else if !Path::new(&artifacts_prefix).is_dir() {
            return Err(Docker2EifError::ArtifactsPrefixError);
        }

        Ok(Docker2Eif {
            docker_image,
            docker,
            init_path,
            kernel_img_path,
            cmdline,
            linuxkit_path,
            output,
            artifacts_prefix,
        })
    }

    pub fn pull_docker_image(&self) -> Result<(), Docker2EifError> {
        self.docker.pull_image().map_err(|e| {
            eprintln!("Docker error: {:?}", e);
            Docker2EifError::DockerError
        })?;

        Ok(())
    }

    pub fn build_docker_image(&self, dockerfile_dir: String) -> Result<(), Docker2EifError> {
        if !Path::new(&dockerfile_dir).is_dir() {
            return Err(Docker2EifError::DockerfilePathError);
        }
        self.docker.build_image(dockerfile_dir).map_err(|e| {
            eprintln!("Docker error: {:?}", e);
            Docker2EifError::DockerError
        })?;

        Ok(())
    }

    pub fn create(&mut self) -> Result<BTreeMap<String, String>, Docker2EifError> {
        let (cmd_file, env_file) = self.docker.load().map_err(|e| {
            eprintln!("Docker error: {:?}", e);
            Docker2EifError::DockerError
        })?;

        let yaml_generator = YamlGenerator::new(
            self.docker_image.clone(),
            self.init_path.clone(),
            cmd_file.path().to_str().unwrap().to_string(),
            env_file.path().to_str().unwrap().to_string(),
        );

        let ramfs_config_file = yaml_generator.get_bootstrap_ramfs().map_err(|e| {
            eprintln!("Ramfs error: {:?}", e);
            Docker2EifError::RamfsError
        })?;
        let ramfs_with_rootfs_config_file = yaml_generator.get_customer_ramfs().map_err(|e| {
            eprintln!("Ramfs error: {:?}", e);
            Docker2EifError::RamfsError
        })?;

        let bootstrap_ramfs = format!("{}/bootstrap-initrd.img", self.artifacts_prefix);
        let customer_ramfs = format!("{}/customer-initrd.img", self.artifacts_prefix);

        Command::new(&self.linuxkit_path)
            .args(&[
                "build",
                "-name",
                bootstrap_ramfs.split("-").next().unwrap(),
                "-format",
                "kernel+initrd",
                ramfs_config_file.path().to_str().unwrap(),
            ])
            .output()
            .map_err(|_| Docker2EifError::LinuxkitExecError)?;

        // Prefix the docker image filesystem, as expected by init
        Command::new(&self.linuxkit_path)
            .args(&[
                "build",
                "-name",
                customer_ramfs.split("-").next().unwrap(),
                "-format",
                "kernel+initrd",
                "-prefix",
                "rootfs/",
                ramfs_with_rootfs_config_file.path().to_str().unwrap(),
            ])
            .output()
            .map_err(|_| Docker2EifError::LinuxkitExecError)?;

        let mut build = EifBuilder::new(
            &Path::new(&self.kernel_img_path),
            self.cmdline.clone(),
            sha2::Sha384::new(),
        );
        build.add_ramdisk(Path::new(&bootstrap_ramfs));
        build.add_ramdisk(Path::new(&customer_ramfs));
        build.write_to(self.output);
        Ok(build.boot_measurement())
    }
}
