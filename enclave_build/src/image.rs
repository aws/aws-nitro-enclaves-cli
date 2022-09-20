// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{EnclaveBuildError, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::Read;

use sha2::Digest;

use oci_distribution::{client::ImageData, Reference};
use oci_spec::image::ImageConfiguration;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
/// Struct representing the image metadata, like the image ID (hash) and config.
pub struct ImageDetails {
    /// The reference of an image, e.g. "docker.io/library/hello-world:latest".
    // Use a String, since the oci_distribution::Reference struct does not implement
    // Serialize/Deserialize
    pub uri: String,
    /// The image ID, calculated as the SHA256 digest hash of the image config.
    #[serde(rename = "Id")]
    pub hash: String,
    /// The image config.
    pub config: ImageConfiguration,
}

impl ImageDetails {
    pub fn new<S: AsRef<str>>(image_uri: S, image_hash: S, config: ImageConfiguration) -> Self {
        Self {
            uri: image_uri.as_ref().to_string(),
            hash: image_hash.as_ref().to_string(),
            config,
        }
    }

    /// Try to build an ImageDetails struct from an oci_distribution ImageData struct.
    //
    // The oci_distribution ImageData struct does not contain the image name or reference, so this
    // must be additionally passed to the function as well.
    pub fn from<S: AsRef<str>>(image_name: S, image_data: &ImageData) -> Result<Self> {
        // Get the config JSON String from the pulled image
        let config_json = String::from_utf8(image_data.config.data.clone())
            .map_err(|err| EnclaveBuildError::ImageDetailError(format!("{:?}", err)))?;

        // Calculate the image hash as the digest of the image config, as specified in the OCI image spec
        // https://github.com/opencontainers/image-spec/blob/main/config.md
        let image_hash = format!("sha256:{:x}", sha2::Sha256::digest(config_json.as_bytes()));

        let image_ref = build_image_reference(&image_name)?;

        Ok(Self {
            uri: image_ref.whole(),
            hash: image_hash,
            config: deserialize_from_reader(config_json.as_bytes())?,
        })
    }
}

/// Calculates the image ID (or image hash) as the SHA256 digest of the image config.
///
/// This method is described in the OCI image spec.
///
/// https://github.com/opencontainers/image-spec/blob/main/config.md
pub fn image_hash<R: Read>(mut image_config: R) -> Result<String> {
    let mut config_bytes = Vec::new();
    image_config.read_to_end(&mut config_bytes).map_err(|err| {
        EnclaveBuildError::HashingError(format!("Failed to calculate image hash: {:?}", err))
    })?;

    let hash = format!("{:x}", sha2::Sha256::digest(&config_bytes));

    Ok(hash)
}

/// For example, "hello-world" image has reference "docker.io/library/hello-world:latest".
///
/// This function uses the implementation from oci_distribution.
pub fn build_image_reference<S: AsRef<str>>(image_name: S) -> Result<Reference> {
    let image_ref = image_name.as_ref().parse().map_err(|err| {
        EnclaveBuildError::ImageDetailError(format!("Failed to find image reference: {:?}", err))
    })?;

    Ok(image_ref)
}

pub fn deserialize_from_reader<R: Read, T: DeserializeOwned>(reader: R) -> Result<T> {
    let deserialized_obj =
        serde_json::from_reader(reader).map_err(EnclaveBuildError::SerdeError)?;

    Ok(deserialized_obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IMAGE_NAME: &str = "hello-world";

    const TEST_IMAGE_HASH: &str =
        "9f5747c1f734cb78bf90123f791324f2a75c75863f1b94a91051702aa87e9511";

    #[test]
    fn test_calculate_image_hash() {
        let calc_image_hash = image_hash(crate::cache::tests::TEST_CONFIG.as_bytes())
            .expect("failed to calculate image hash");

        assert_eq!(calc_image_hash, TEST_IMAGE_HASH);
    }

    #[test]
    fn test_from_image_data() {
        // Use the mock image data from the cache.rs module
        let mock_image_data = crate::cache::tests::build_image_data();

        let image_details = ImageDetails::from(TEST_IMAGE_NAME, &mock_image_data)
            .expect("failed to build an ImageDetails struct from ImageData");

        let test_image_uri =
            build_image_reference(TEST_IMAGE_NAME).expect("failed to determine image reference");
        let test_image_config: oci_spec::image::ImageConfiguration =
            deserialize_from_reader(mock_image_data.config.data.as_slice())
                .expect("failed to deserialize to ImageConfiguration struct");
        let test_image_details = ImageDetails::new(
            test_image_uri.whole(),
            format!("sha256:{}", TEST_IMAGE_HASH),
            test_image_config,
        );

        assert_eq!(image_details, test_image_details);
    }
}
