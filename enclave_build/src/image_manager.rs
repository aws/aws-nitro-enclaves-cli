// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use std::convert::TryFrom;

use log::warn;
use oci_distribution::Reference;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

use crate::image::ImageDetails;
use crate::storage::OciStorage;
use crate::{EnclaveBuildError, Result};

/// Trait which provides an interface for handling an image (OCI or Docker)
pub trait ImageManager {
    fn image_name(&self) -> &str;
    /// Inspects the image and returns its metadata in the form of a JSON Value
    fn inspect_image(&self) -> Result<serde_json::Value>;
    /// Returns the architecture of the image
    fn architecture(&self) -> Result<String>;
    /// Returns two temp files containing the CMD and ENV expressions extracted from the image
    fn extract_expressions(&self) -> Result<(NamedTempFile, NamedTempFile)>;
}

pub struct OciImageManager {
    /// Name of the container image.
    image_name: String,
    /// Image details needed for inspect and extract commands operations
    image_details: ImageDetails,
}

impl OciImageManager {
    /// When calling this constructor, it also tries to initialize the storage at the default path.
    /// If this fails, the ImageManager is still created, but the 'storage' field is set to 'None'.
    pub fn new(image_name: &str) -> Result<Self> {
        // Add the default ":latest" tag if the image tag is missing
        let image_name = normalize_tag(image_name)?;

        // The docker daemon is not used, so a local storage needs to be created
        let storage = match OciStorage::get_default_root_path().map_err(|err| warn!("{:?}", err)) {
            Ok(root_path) => {
                // Try to create/read the storage. If the storage could not be created, log the error
                OciStorage::new(&root_path)
                    .map_err(|err| warn!("{:?}", err))
                    .ok()
            }
            Err(_) => None,
        };

        let act = Self::fetch_image_details(&image_name, storage);

        let runtime = Runtime::new().map_err(|_| EnclaveBuildError::RuntimeError)?;
        let image_details = runtime
            .block_on(act)
            .map_err(|_| EnclaveBuildError::RuntimeError)?;

        Ok(Self {
            image_name,
            image_details,
        })
    }

    /// Returns a struct containing image metadata.
    ///
    /// If the image is stored correctly, the function tries to fetch the image from the storage.
    ///
    /// If the image is not stored or a storage was not created (the 'storage' field is None),
    /// it pulls the image, stores it (if the 'storage' field is not None) and returns its metadata.
    ///
    /// If the pull succeeded but the store operation failed, it returns the pulled image metadata.
    async fn fetch_image_details(
        image_name: &str,
        mut storage: Option<OciStorage>,
    ) -> Result<ImageDetails> {
        let local_storage = storage.as_mut();

        let image_details = if let Some(storage) = local_storage {
            // Try to fetch the image from the storage
            storage.fetch_image_details(image_name)
        } else {
            Err(EnclaveBuildError::OciStorageNotFound(
                "Local storage missing".to_string(),
            ))
        };

        // If the fetching failed, pull it from remote and store it
        match image_details {
            Ok(details) => Ok(details),
            Err(err) => {
                warn!("Fetching from storage failed: {}", err);
                // The image is not stored, so try to pull and then store it
                let image_data = crate::pull::pull_image_data(image_name).await?;

                // If the store operation fails, discard error and proceed with getting the details
                if let Some(local_storage) = storage.as_mut() {
                    local_storage
                        .store_image_data(image_name, &image_data)
                        .map_err(|err| warn!("Failed to store image: {:?}", err))
                        .ok();
                }

                // Get the image metadata from the pulled struct
                ImageDetails::build_details(image_name, &image_data)
            }
        }
    }
}

/// Adds the default ":latest" tag to an image if it is untagged
fn normalize_tag(image_name: &str) -> Result<String> {
    let image_ref = Reference::try_from(image_name).map_err(|err| {
        EnclaveBuildError::ImageBuildError(format!("Invalid image name format: {}", err))
    })?;

    match image_ref.tag() {
        Some(_) => Ok(image_name.to_string()),
        None => Ok(format!("{}:latest", image_name)),
    }
}

impl ImageManager for OciImageManager {
    fn image_name(&self) -> &str {
        &self.image_name
    }

    /// Inspect the image and return its description as a JSON String.
    fn inspect_image(&self) -> Result<serde_json::Value> {
        // Serialize to a serde_json::Value
        serde_json::to_value(&self.image_details).map_err(EnclaveBuildError::SerdeError)
    }

    /// Extracts the CMD and ENV expressions from the image and returns them each in a
    /// temporary file
    fn extract_expressions(&self) -> Result<(NamedTempFile, NamedTempFile)> {
        self.image_details.extract_expressions()
    }

    /// Returns architecture information of the image.
    fn architecture(&self) -> Result<String> {
        Ok(format!("{}", self.image_details.config().architecture()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    use sha2::Digest;

    use super::{normalize_tag, OciImageManager};

    #[cfg(target_arch = "x86_64")]
    const SAMPLE_IMAGE: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample-server-x86_64";
    #[cfg(target_arch = "aarch64")]
    const SAMPLE_IMAGE: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample-server-aarch64";
    #[cfg(target_arch = "x86_64")]
    const IMAGE_HASH: &str =
        "sha256:03e42b437a0d900e2c6e2f7f4b65d818adfea6dbadfaad30027af42a68c5c183";
    #[cfg(target_arch = "aarch64")]
    const IMAGE_HASH: &str =
        "sha256:1405e46c329b17bf4bb6eb9ff97d2a6085a8055948e9ffeb4e3227ea6b024e39";

    #[tokio::test]
    async fn test_fetch_storage_missing() {
        let image_details =
            OciImageManager::fetch_image_details(&normalize_tag(SAMPLE_IMAGE).unwrap(), None)
                .await
                .unwrap();

        let config_string = image_details.config().to_string().unwrap();
        let config_hash = format!(
            "sha256:{:x}",
            sha2::Sha256::digest(config_string.as_bytes())
        );

        assert_eq!(&config_hash, IMAGE_HASH);
    }

    #[tokio::test]
    async fn test_fetch_from_storage() {
        let (_root_path, storage) = crate::storage::tests::setup_temp_storage();

        let image_details = OciImageManager::fetch_image_details(
            &normalize_tag(crate::image::tests::TEST_IMAGE_NAME).unwrap(),
            Some(storage),
        )
        .await
        .unwrap();

        let config_string = image_details.config().to_string().unwrap();
        let config_hash = format!(
            "sha256:{:x}",
            sha2::Sha256::digest(config_string.as_bytes())
        );

        assert_eq!(
            config_hash,
            "sha256:44445ae0eab6eead16f7546a10ee41eb2869145ca9260d78700fba095da646b7"
        );
    }

    #[tokio::test]
    async fn test_create_manager() {
        let image_manager = OciImageManager::new(SAMPLE_IMAGE).unwrap();

        assert_eq!(image_manager.image_name, SAMPLE_IMAGE);

        let config_string = image_manager.image_details.config().to_string().unwrap();
        let config_hash = format!(
            "sha256:{:x}",
            sha2::Sha256::digest(config_string.as_bytes())
        );

        assert_eq!(&config_hash, IMAGE_HASH);
    }

    /// Test extracted configuration is as expected
    #[tokio::test]
    async fn test_config() {
        #[cfg(target_arch = "x86_64")]
        let image_manager = OciImageManager::new(
            "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample-server-x86_64",
        ).unwrap();
        #[cfg(target_arch = "aarch64")]
        let mut image_manager = OciImageManager::new(
            "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample-server-aarch64",
        ).await.unwrap();

        let (cmd_file, env_file) = image_manager.extract_expressions().unwrap();
        let mut cmd_file = File::open(cmd_file.path()).unwrap();
        let mut env_file = File::open(env_file.path()).unwrap();

        let mut cmd = String::new();
        cmd_file.read_to_string(&mut cmd).unwrap();
        assert_eq!(
            cmd,
            "/bin/sh\n\
             -c\n\
             ./vsock-sample server --port 5005\n"
        );

        let mut env = String::new();
        env_file.read_to_string(&mut env).unwrap();
        assert_eq!(
            env,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        );
    }
}
