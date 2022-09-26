// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::path::Path;
use std::process::Command;

mod cache;
mod docker;
mod image;
mod image_manager;
mod pull;
mod yaml_generator;

use aws_nitro_enclaves_image_format::defs::{EifBuildInfo, EifIdentityInfo, EIF_HDR_ARCH_ARM64};
use aws_nitro_enclaves_image_format::utils::identity::parse_custom_metadata;
use aws_nitro_enclaves_image_format::utils::{EifBuilder, SignEnclaveInfo};
use serde_json::json;
use sha2::Digest;
use std::collections::BTreeMap;
use thiserror::Error;
use yaml_generator::{YamlGenerator, YamlGeneratorError};

pub const DEFAULT_TAG: &str = "1.0";

#[derive(Debug, Error)]
pub enum EnclaveBuildError {
    #[error("Docker error: `{0:?}`")]
    DockerError(String),
    #[error("Invalid path: `{0}`")]
    PathError(String),
    #[error("Image pull error: `{0}`")]
    ImagePullError(String),
    #[error("Image inspect failed")]
    ImageInspectError,
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

pub struct BlobsArgs {
    pub init_path: String,
    pub nsm_path: String,
    pub kernel_img_path: String,
    pub cmdline: String,
    pub linuxkit_path: String,
    pub artifacts_prefix: String,
}

pub struct SignArgs {
    pub certificate_path: Option<String>,
    pub key_path: Option<String>,
}

pub struct MetadataArgs {
    pub img_name: Option<String>,
    pub img_version: Option<String>,
    pub metadata_path: Option<String>,
    pub build_info: EifBuildInfo,
}

pub struct SourceArgs {
    pub docker_image: Option<String>,
    pub docker_dir: Option<String>,
    pub oci_image: Option<String>,
}

pub struct Docker2Eif<'a> {
    /// This field can be any struct that implements the 'ImageManager' trait.
    image_manager: Box<dyn image_manager::ImageManager>,
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
    /// If the 'docker_dir' argument is Some (i.e. --docker-dir flag is used), the docker daemon will
    /// always be used to build the image locally and store it in the docker cache.
    ///
    /// If the 'oci_image' argument is Some (i.e. the --image-uri flag is used) and the '--docker-dir'
    /// flag is not used, pull and cache the image without using the docker daemon.
    pub fn new(
        sources: SourceArgs,
        blobs: BlobsArgs,
        output: &'a mut File,
        signature: SignArgs,
        metadata: MetadataArgs,
    ) -> Result<Self> {
        // The flags usage was already validated by the commands parser, so now just check if the docker daemon
        // should be used or not
        let image_manager: Box<dyn image_manager::ImageManager> = match (
            &sources.docker_image,
            &sources.docker_dir,
            &sources.oci_image,
        ) {
            // If the --docker-uri flag is used then the docker client is required either for pulling the image or
            // for building it locally from the supplied Dockerfile in case --docker-dir is used too
            (Some(docker_image), _, _) => {
                Box::new(crate::docker::DockerImageManager::new(docker_image))
            }
            // In all other valid cases, do not use docker
            (_, _, Some(oci_image)) => {
                Box::new(crate::image_manager::OciImageManager::new(oci_image))
            }
            (_, _, _) => {
                return Err(EnclaveBuildError::ImageDetailError(
                    "Image directory or URI missing".to_string(),
                ))
            }
        };

        if !Path::new(&blobs.init_path).is_file() {
            return Err(EnclaveBuildError::PathError("init path".to_string()));
        } else if !Path::new(&blobs.nsm_path).is_file() {
            return Err(EnclaveBuildError::PathError("nsm path".to_string()));
        } else if !Path::new(&blobs.kernel_img_path).is_file() {
            return Err(EnclaveBuildError::PathError("kernel path".to_string()));
        } else if !Path::new(&blobs.linuxkit_path).is_file() {
            return Err(EnclaveBuildError::PathError("linuxkit path".to_string()));
        } else if !Path::new(&blobs.artifacts_prefix).is_dir() {
            return Err(EnclaveBuildError::PathError("artifacts prefix".to_string()));
        }

        if let Some(ref path) = metadata.metadata_path {
            if !Path::new(path).is_file() {
                return Err(EnclaveBuildError::PathError("metadata path".to_string()));
            }
        }

        let sign_info = match (signature.certificate_path, signature.key_path) {
            (None, None) => None,
            (Some(cert_path), Some(key_path)) => Some(
                SignEnclaveInfo::new(&cert_path, &key_path)
                    .map_err(EnclaveBuildError::SignError)?,
            ),
            _ => {
                return Err(EnclaveBuildError::SignError(
                    "Invalid signing arguments".to_string(),
                ))
            }
        };

        Ok(Docker2Eif {
            image_manager,
            init_path: blobs.init_path,
            nsm_path: blobs.nsm_path,
            kernel_img_path: blobs.kernel_img_path,
            cmdline: blobs.cmdline,
            linuxkit_path: blobs.linuxkit_path,
            output,
            artifacts_prefix: blobs.artifacts_prefix,
            sign_info,
            img_name: metadata.img_name,
            img_version: metadata.img_version,
            metadata_path: metadata.metadata_path,
            build_info: metadata.build_info,
        })
    }

    pub fn pull_image(&mut self) -> Result<()> {
        self.image_manager.pull_image()?;

        Ok(())
    }

    pub fn build_docker_image(&self, dockerfile_dir: String) -> Result<()> {
        if !Path::new(&dockerfile_dir).is_dir() {
            return Err(EnclaveBuildError::PathError("Dockerfile path".to_string()));
        }
        self.image_manager.build_image(dockerfile_dir)?;

        Ok(())
    }

    fn generate_identity_info(&mut self) -> Result<EifIdentityInfo> {
        let docker_info = self.image_manager.inspect_image()?;

        let uri_split: Vec<&str> = self.image_manager.image_name().split(':').collect();
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
        let (cmd_file, env_file) = self.image_manager.load()?;

        let yaml_generator = YamlGenerator::new(
            self.image_manager.image_name().clone(),
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
            return Err(EnclaveBuildError::LinuxKitError(format!(
                "Linuxkit reported an error while creating the bootstrap ramfs: {:?}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // If the docker daemon should be used, then call linuxkit with the '-docker' flag, which
        // makes linuxkit search the image in the docker cache first.
        // Otherwise, do not add the flag and let it pull the images itself, without docker.
        if self.image_manager.use_docker() {
            // Prefix the docker image filesystem, as expected by init
            let output = Command::new(&self.linuxkit_path)
                .args(&[
                    "build",
                    // Use the docker daemon to first check if the image is in the docker cache
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
                return Err(EnclaveBuildError::LinuxKitError(format!(
                    "Linuxkit reported an error while creating the customer ramfs: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else {
            // In this case, linuxkit pulls the image itself
            let output = Command::new(&self.linuxkit_path)
                .args(&[
                    "build",
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
                return Err(EnclaveBuildError::LinuxKitError(format!(
                    "Linuxkit reported an error while creating the customer ramfs: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        }

        let arch = self.image_manager.architecture()?;

        let flags = match arch.as_str() {
            docker::DOCKER_ARCH_ARM64 => EIF_HDR_ARCH_ARM64,
            docker::DOCKER_ARCH_AMD64 => 0,
            _ => {
                return Err(EnclaveBuildError::UnsupportedArchError);
            }
        };

        let eif_info = self.generate_identity_info()?;

        let mut build = EifBuilder::new(
            Path::new(&self.kernel_img_path),
            self.cmdline.clone(),
            self.sign_info.clone(),
            sha2::Sha384::new(),
            flags,
            eif_info,
        );

        // Linuxkit adds -initrd.img sufix to the file names.
        let bootstrap_ramfs = format!("{}-initrd.img", bootstrap_ramfs);
        let customer_ramfs = format!("{}-initrd.img", customer_ramfs);

        build.add_ramdisk(Path::new(&bootstrap_ramfs));
        build.add_ramdisk(Path::new(&customer_ramfs));

        Ok(build.write_to(self.output))
    }
}
