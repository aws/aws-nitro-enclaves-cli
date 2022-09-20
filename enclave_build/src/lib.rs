// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::too_many_arguments)]

use std::fs::File;
use std::path::Path;
use std::process::Command;

mod docker;
mod image;
mod image_manager;
mod pull;
mod storage;
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
    #[error("Image storage initialization error: `{0:?}`")]
    OciStorageInit(std::io::Error),
    #[error("Image store operation failed: `{0:?}`")]
    OciStorageStore(std::io::Error),
    #[error("Storage entry not found or has wrong: `{0:?}`")]
    OciStorageNotFound(String),
    #[error("Storage has the wrong structure: `{0:?}`")]
    OciStorageMalformed(String),
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

#[allow(dead_code)]
enum ImageType {
    Docker,
    Oci,
}

pub struct Docker2Eif<'a> {
    /// This field can be any struct that implements the 'ImageManager' trait.
    image_manager: Box<dyn image_manager::ImageManager>,
    image_type: ImageType,
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
    /// Decide on the type of image and build method of the EIF from based on build arguments.
    /// The presence of `--docker-uri` alone or along `--docker-dir` prompts the usage of the Docker daemon.
    pub fn new(
        docker_image: Option<String>,
        docker_dir: Option<String>,
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
        let blob_paths = Vec::from([&init_path, &nsm_path, &kernel_img_path, &linuxkit_path]);
        let image_type;

        // The flags usage was already validated by the commands parser, so now just check if the docker daemon
        // should be used or not
        let image_manager: Box<dyn image_manager::ImageManager> = match (&docker_image, &docker_dir)
        {
            // Docker directory present so try to build from Dockerfile
            (Some(docker_image), Some(docker_dir)) => {
                image_type = ImageType::Docker;
                Box::new(crate::docker::DockerImageManager::from_dockerfile(
                    docker_image,
                    docker_dir,
                )?)
            }
            // If the --docker-uri flag is used then the docker client is required either for pulling the image or
            // for building it locally from the supplied Dockerfile in case --docker-dir is used too
            (Some(docker_image), _) => {
                image_type = ImageType::Docker;
                Box::new(crate::docker::DockerImageManager::new(docker_image)?)
            }
            // TODO: add cases for --oci-image and --oci-archive when arguments are introduced
            (_, _) => {
                return Err(EnclaveBuildError::ImageDetailError(
                    "Image directory or URI missing".to_string(),
                ))
            }
        };

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
            image_manager,
            image_type,
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

    fn create_ramfs(&self, args: Vec<&str>) -> Result<()> {
        let output = Command::new(&self.linuxkit_path)
            .args(args)
            .output()
            .map_err(|e| EnclaveBuildError::LinuxKitError(format!("{:?}", e)))?;
        if !output.status.success() {
            return Err(EnclaveBuildError::LinuxKitError(format!(
                "Linuxkit reported an error while creating ramfs: {:?}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    pub fn create(&mut self) -> Result<BTreeMap<String, String>> {
        let (cmd_file, env_file) = self.image_manager.extract_expressions()?;

        let yaml_generator = YamlGenerator::new(
            self.image_manager.image_name().to_string(),
            self.init_path.clone(),
            self.nsm_path.clone(),
            cmd_file.path().to_str().unwrap().to_string(),
            env_file.path().to_str().unwrap().to_string(),
        );

        let ramfs_config_file = yaml_generator.get_bootstrap_ramfs().map_err(|e| {
            eprintln!("Ramfs error: {e:?}");
            EnclaveBuildError::RamfsError(e)
        })?;
        let ramfs_with_rootfs_config_file = yaml_generator.get_customer_ramfs().map_err(|e| {
            eprintln!("Ramfs error: {e:?}");
            EnclaveBuildError::RamfsError(e)
        })?;

        let bootstrap_ramfs = format!("{}/bootstrap-initrd.img", self.artifacts_prefix);
        let customer_ramfs = format!("{}/customer-initrd.img", self.artifacts_prefix);

        // Create the bootstrap ramfs
        self.create_ramfs(
            [
                "build",
                "-name",
                &bootstrap_ramfs,
                "-format",
                "kernel+initrd",
                ramfs_config_file.path().to_str().unwrap(),
            ]
            .to_vec(),
        )?;

        // If the docker daemon should be used, then call linuxkit with the '-docker' flag, which
        // makes linuxkit search the image in the docker cache first.
        // Otherwise, do not add the flag and let it pull the images itself, without docker.
        match self.image_type {
            ImageType::Docker => {
                // Prefix the docker image filesystem, as expected by init
                self.create_ramfs(
                    [
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
                    ]
                    .to_vec(),
                )?;
            }
            ImageType::OCI => {
                // In this case, linuxkit pulls the image itself
                self.create_ramfs(
                    [
                        "build",
                        "-name",
                        &customer_ramfs,
                        "-format",
                        "kernel+initrd",
                        "-prefix",
                        "rootfs/",
                        ramfs_with_rootfs_config_file.path().to_str().unwrap(),
                    ]
                    .to_vec(),
                )?;
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
        let bootstrap_ramfs = format!("{bootstrap_ramfs}-initrd.img");
        let customer_ramfs = format!("{customer_ramfs}-initrd.img");

        build.add_ramdisk(Path::new(&bootstrap_ramfs));
        build.add_ramdisk(Path::new(&customer_ramfs));

        Ok(build.write_to(self.output))
    }
}
