// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::too_many_arguments)]

use std::fs::File;
use std::path::Path;
use std::process::Command;

mod docker;
mod image;
mod pull;
mod yaml_generator;

use aws_nitro_enclaves_image_format::defs::{EifBuildInfo, EifIdentityInfo, EIF_HDR_ARCH_ARM64};
use aws_nitro_enclaves_image_format::utils::identity::parse_custom_metadata;
use aws_nitro_enclaves_image_format::utils::{EifBuilder, SignEnclaveInfo};
use docker::DockerUtil;
use serde_json::json;
use sha2::Digest;
use std::collections::BTreeMap;
use thiserror::Error;
use yaml_generator::{YamlGenerator, YamlGeneratorError};

pub const DEFAULT_TAG: &str = "1.0";

#[derive(Debug, Error)]
pub enum EnclaveBuildError {
    #[error("Docker error: `{0}`")]
    DockerError(String),
    #[error("Invalid path: `{0}`")]
    PathError(String),
    #[error("Image pull error: `{0}`")]
    ImagePullError(String),
    #[error("Container image build error: `{0}`")]
    ImageBuildError(String),
    #[error("Image inspect failed: `{0:?}`")]
    ImageInspectError(shiplift::Error),
    #[error("Linuxkit error: `{0}`")]
    LinuxKitError(String),
    #[error("File operation error: `{0:?}`")]
    FileError(std::io::Error),
    #[error("Ramfs error: `{0:?}`")]
    RamfsError(YamlGeneratorError),
    #[error("Signature error: `{0}`")]
    SignError(String),
    #[error("Metadata error: `{0}`")]
    MetadataError(String),
    #[error("Unsupported architecture")]
    UnsupportedArchError,
    #[error("Getting image detail failed: `{0}`")]
    ImageDetailError(String),
    #[error("Container image operation failed")]
    ImageOperationError,
    #[error("Failed to convert image to EIF")]
    ImageConvertError,
    #[error("Hashing error: `{0}`")]
    HashingError(String),
    #[error("Serde error: `{0:?}`")]
    SerdeError(serde_json::Error),
    #[error("Error while parsing credentials: `{0}`")]
    CredentialsError(String),
    #[error("Image cache initialization error: `{0:?}`")]
    CacheInitError(std::io::Error),
    #[error("Cache store operation failed: `{0:?}`")]
    CacheStoreError(std::io::Error),
    #[error("Cache entry not found or has wrong: `{0:?}`")]
    CacheMissError(String),
    #[error("Manifest missing or wrong format")]
    ConfigError,
    #[error("Manifest missing or wrong format")]
    ManifestError,
    #[error("Failed to extract expressions from image: `{0}`")]
    ExtractError(String),
    #[error("Image entrypoint missing or unsupported")]
    EntrypointError,
    #[error("Runtime creation failed")]
    RuntimeError,
    #[error("EIF build error: `{0}`")]
    OtherError(String),
}

pub type Result<T> = std::result::Result<T, EnclaveBuildError>;

pub struct Docker2Eif<'a> {
    docker_image: String,
    docker: DockerUtil,
    init_path: String,
    nsm_path: String,
    kernel_img_path: String,
    cmdline: String,
    linuxkit_path: String,
    artifacts_prefix: String,
    output: &'a mut File,
    sign_info: Option<SignEnclaveInfo>,
    img_name: Option<String>,
    img_version: Option<String>,
    metadata_path: Option<String>,
    build_info: EifBuildInfo,
}

impl<'a> Docker2Eif<'a> {
    pub fn new(
        docker_image: String,
        init_path: String,
        nsm_path: String,
        kernel_img_path: String,
        cmdline: String,
        linuxkit_path: String,
        output: &'a mut File,
        artifacts_prefix: String,
        certificate_path: &Option<String>,
        key_path: &Option<String>,
        img_name: Option<String>,
        img_version: Option<String>,
        metadata_path: Option<String>,
        build_info: EifBuildInfo,
    ) -> Result<Self> {
        let docker = DockerUtil::new(docker_image.clone());
        let blob_paths = Vec::from([&init_path, &nsm_path, &kernel_img_path, &linuxkit_path]);

        blob_paths.iter().try_for_each(|path| {
            if !Path::new(path).is_file() {
                return Err(EnclaveBuildError::PathError(path.to_string()));
            }
            Ok(())
        })?;

        if !Path::new(&artifacts_prefix).is_dir() {
            return Err(EnclaveBuildError::PathError(artifacts_prefix));
        }

        if let Some(ref path) = metadata_path {
            if !Path::new(path).is_file() {
                return Err(EnclaveBuildError::PathError(path.to_string()));
            }
        }

        let sign_info = match (certificate_path, key_path) {
            (None, None) => None,
            (Some(cert_path), Some(key_path)) => Some(
                SignEnclaveInfo::new(cert_path, key_path).map_err(EnclaveBuildError::SignError)?,
            ),
            _ => {
                return Err(EnclaveBuildError::SignError(
                    "Invalid signing arguments".to_string(),
                ))
            }
        };

        Ok(Docker2Eif {
            docker_image,
            docker,
            init_path,
            nsm_path,
            kernel_img_path,
            cmdline,
            linuxkit_path,
            output,
            artifacts_prefix,
            sign_info,
            img_name,
            img_version,
            metadata_path,
            build_info,
        })
    }

    pub fn pull_docker_image(&self) -> Result<()> {
        self.docker.pull_image()?;

        Ok(())
    }

    pub fn build_docker_image(&self, dockerfile_dir: String) -> Result<()> {
        if !Path::new(&dockerfile_dir).is_dir() {
            return Err(EnclaveBuildError::PathError(dockerfile_dir));
        }
        self.docker.build_image(dockerfile_dir)?;

        Ok(())
    }

    fn generate_identity_info(&self) -> Result<EifIdentityInfo> {
        let docker_info = self.docker.inspect_image()?;

        let uri_split: Vec<&str> = self.docker_image.split(':').collect();
        if uri_split.is_empty() {
            return Err(EnclaveBuildError::ImageDetailError(
                "Wrong image name specified".to_string(),
            ));
        }

        // Image hash is used by default in case image version is not provided.
        // It's taken from JSON generated by `docker inspect` and a bit fragile.
        // May be later we should change it to fetching this data
        // from a specific struct and not JSON
        let img_hash = docker_info
            .get("Id")
            .and_then(|val| val.as_str())
            .and_then(|str| str.strip_prefix("sha256:"))
            .ok_or_else(|| {
                EnclaveBuildError::MetadataError(
                    "Image info must contain string Id field".to_string(),
                )
            })?;

        let img_name = self
            .img_name
            .clone()
            .unwrap_or_else(|| uri_split[0].to_string());
        let img_version = self
            .img_version
            .clone()
            .unwrap_or_else(|| img_hash.to_string());

        let mut custom_info = json!(null);
        if let Some(ref path) = self.metadata_path {
            custom_info = parse_custom_metadata(path).map_err(EnclaveBuildError::MetadataError)?
        }

        Ok(EifIdentityInfo {
            img_name,
            img_version,
            build_info: self.build_info.clone(),
            docker_info,
            custom_info,
        })
    }

    pub fn create(&mut self) -> Result<BTreeMap<String, String>> {
        let (cmd_file, env_file) = self.docker.load()?;

        let yaml_generator = YamlGenerator::new(
            self.docker_image.clone(),
            self.init_path.clone(),
            self.nsm_path.clone(),
            cmd_file.path().to_str().unwrap().to_string(),
            env_file.path().to_str().unwrap().to_string(),
        );

        let ramfs_config_file = yaml_generator.get_bootstrap_ramfs().map_err(|e| {
            eprintln!("Ramfs error: {:?}", e);
            EnclaveBuildError::RamfsError(e)
        })?;
        let ramfs_with_rootfs_config_file = yaml_generator.get_customer_ramfs().map_err(|e| {
            eprintln!("Ramfs error: {:?}", e);
            EnclaveBuildError::RamfsError(e)
        })?;

        let bootstrap_ramfs = format!("{}/bootstrap-initrd.img", self.artifacts_prefix);
        let customer_ramfs = format!("{}/customer-initrd.img", self.artifacts_prefix);

        let output = Command::new(&self.linuxkit_path)
            .args(&[
                "build",
                "-name",
                &bootstrap_ramfs,
                "-format",
                "kernel+initrd",
                ramfs_config_file.path().to_str().unwrap(),
            ])
            .output()
            .map_err(|e| EnclaveBuildError::LinuxKitError(format!("{:?}", e)))?;
        if !output.status.success() {
            eprintln!(
                "Linuxkit reported an error while creating the bootstrap ramfs: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(EnclaveBuildError::LinuxKitError(format!(
                "{:?}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Prefix the docker image filesystem, as expected by init
        let output = Command::new(&self.linuxkit_path)
            .args(&[
                "build",
                "-docker",
                "-name",
                &customer_ramfs,
                "-format",
                "kernel+initrd",
                "-prefix",
                "rootfs/",
                ramfs_with_rootfs_config_file.path().to_str().unwrap(),
            ])
            .output()
            .map_err(|e| EnclaveBuildError::LinuxKitError(format!("{:?}", e)))?;
        if !output.status.success() {
            eprintln!(
                "Linuxkit reported an error while creating the customer ramfs: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(EnclaveBuildError::LinuxKitError(format!(
                "{:?}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let arch = self.docker.architecture()?;

        let flags = match arch.as_str() {
            docker::DOCKER_ARCH_ARM64 => EIF_HDR_ARCH_ARM64,
            docker::DOCKER_ARCH_AMD64 => 0,
            _ => {
                return Err(EnclaveBuildError::UnsupportedArchError);
            }
        };

        let mut build = EifBuilder::new(
            Path::new(&self.kernel_img_path),
            self.cmdline.clone(),
            self.sign_info.clone(),
            sha2::Sha384::new(),
            flags,
            self.generate_identity_info()?,
        );

        // Linuxkit adds -initrd.img sufix to the file names.
        let bootstrap_ramfs = format!("{}-initrd.img", bootstrap_ramfs);
        let customer_ramfs = format!("{}-initrd.img", customer_ramfs);

        build.add_ramdisk(Path::new(&bootstrap_ramfs));
        build.add_ramdisk(Path::new(&customer_ramfs));

        Ok(build.write_to(self.output))
    }
}
