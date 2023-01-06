// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
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
    uri: String,
    /// The image ID, calculated as the SHA256 digest hash of the image config.
    id: String,
    /// The image config.
    config: ImageConfiguration,
}

impl ImageDetails {
    pub fn new(image_uri: String, image_hash: String, config: ImageConfiguration) -> Self {
        Self {
            uri: image_uri,
            id: image_hash,
            config,
        }
    }

    /// Try to build an ImageDetails struct from an oci_distribution ImageData struct.
    //
    // The oci_distribution ImageData struct does not contain the image name or reference, so this
    // must be additionally passed to the function as well.
    pub fn build_details(image_name: &str, image_data: &ImageData) -> Result<Self> {
        // Calculate the image hash as the digest of the image config, as specified in the OCI image spec
        // https://github.com/opencontainers/image-spec/blob/main/config.md
        let image_hash = format!("sha256:{:x}", sha2::Sha256::digest(&image_data.config.data));

        let image_ref = build_image_reference(image_name)?;

        Ok(Self {
            uri: image_ref.whole(),
            id: image_hash,
            config: deserialize_from_reader(image_data.config.data.as_slice())?,
        })
    }

    pub fn config(&self) -> &ImageConfiguration {
        &self.config
    }
}

/// URIs that are missing a domain will be converted to a reference using the Docker defaults.
/// For example, "hello-world" image has reference "docker.io/library/hello-world:latest".
///
/// This function uses the implementation from oci_distribution.
pub fn build_image_reference(image_name: &str) -> Result<Reference> {
    let image_ref = image_name.parse().map_err(|err| {
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
pub mod tests {
    use super::*;
    use oci_distribution::{
        client::{Config, ImageLayer},
        manifest::OciImageManifest,
    };

    /// Name of the custom image to be used for testing the cache.
    /// This image will not be pulled from remote.
    pub const TEST_IMAGE_NAME: &str = "hello-world";

    /// The manifest.json of the image used for testing.
    pub const TEST_MANIFEST: &str = r#"
    {
        "schemaVersion":2,
        "mediaType":"application/vnd.docker.distribution.manifest.v2+json",
        "config":{
            "mediaType":"application/vnd.docker.container.image.v1+json",
            "digest":"sha256:9f5747c1f734cb78bf90123f791324f2a75c75863f1b94a91051702aa87e9511",
            "size":1469
        },
        "layers":[
            {
                "mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest":"sha256:1aed4d8555515c961bffea900d5e7f1c1e4abf0f6da250d8bf15843106e0533b",
                "size":12
            },
            {
                "mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest":"sha256:3df75539dda4c512db688b3f1d86184c0d7b99cbea1eb87dec8385a2651ac1f3",
                "size":12
            }
        ]
    }
    "#;

    /// The config.json file of the hello-world image used for testing
    pub const TEST_CONFIG: &str = r##"
    {
        "architecture": "amd64",
        "config": {
          "Hostname": "",
          "Domainname": "",
          "User": "",
          "AttachStdin": false,
          "AttachStdout": false,
          "AttachStderr": false,
          "Tty": false,
          "OpenStdin": false,
          "StdinOnce": false,
          "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
          ],
          "Cmd": [
            "/hello"
          ],
          "Image": "sha256:b9935d4e8431fb1a7f0989304ec86b3329a99a25f5efdc7f09f3f8c41434ca6d",
          "Volumes": null,
          "WorkingDir": "",
          "Entrypoint": null,
          "OnBuild": null,
          "Labels": null
        },
        "container": "8746661ca3c2f215da94e6d3f7dfdcafaff5ec0b21c9aff6af3dc379a82fbc72",
        "container_config": {
          "Hostname": "8746661ca3c2",
          "Domainname": "",
          "User": "",
          "AttachStdin": false,
          "AttachStdout": false,
          "AttachStderr": false,
          "Tty": false,
          "OpenStdin": false,
          "StdinOnce": false,
          "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
          ],
          "Cmd": [
            "/bin/sh",
            "-c",
            "#(nop) ",
            "CMD [\"/hello\"]"
          ],
          "Image": "sha256:b9935d4e8431fb1a7f0989304ec86b3329a99a25f5efdc7f09f3f8c41434ca6d",
          "Volumes": null,
          "WorkingDir": "",
          "Entrypoint": null,
          "OnBuild": null,
          "Labels": {}
        },
        "created": "2021-09-23T23:47:57.442225064Z",
        "docker_version": "20.10.7",
        "history": [
          {
            "created": "2021-09-23T23:47:57.098990892Z",
            "created_by": "/bin/sh -c #(nop) COPY file:50563a97010fd7ce1ceebd1fa4f4891ac3decdf428333fb2683696f4358af6c2 in / "
          },
          {
            "created": "2021-09-23T23:47:57.442225064Z",
            "created_by": "/bin/sh -c #(nop)  CMD [\"/hello\"]",
            "empty_layer": true
          }
        ],
        "os": "linux",
        "rootfs": {
          "type": "layers",
          "diff_ids": [
            "sha256:e07ee1baac5fae6a26f30cabfe54a36d3402f96afda318fe0a96cec4ca393359"
          ]
        }
    }
    "##;

    /// The hash of the test image calculated as the SHA256 digest of the image config
    pub const TEST_IMAGE_HASH: &str =
        "9f5747c1f734cb78bf90123f791324f2a75c75863f1b94a91051702aa87e9511";

    // Simple layers used for testing
    pub const TEST_LAYER_1: &str = "Hello World 1";
    pub const TEST_LAYER_2: &str = "Hello World 2";

    /// Builds a mock ImageData struct in order to avoid pulling it from remote.
    pub fn build_image_data() -> ImageData {
        // Use mock image layer bytes
        let image_layer_bytes_1 = TEST_LAYER_1.as_bytes().to_vec();
        let image_layer_bytes_2 = TEST_LAYER_2.as_bytes().to_vec();
        let layer_1 = ImageLayer::new(image_layer_bytes_1, "".to_string(), None);
        let layer_2 = ImageLayer::new(image_layer_bytes_2, "".to_string(), None);

        // Use the config.json for testing
        let config_json = TEST_CONFIG.to_string();
        let config_obj = Config::new(config_json.as_bytes().to_vec(), "".to_string(), None);

        // Use the test manifest JSON
        let mut manifest_json = TEST_MANIFEST.to_string();
        manifest_json = manifest_json.replace("\n", "");
        manifest_json = manifest_json.replace(" ", "");
        let manifest_obj: OciImageManifest =
            serde_json::from_str(&manifest_json).expect("Test manifest JSON parsing error");

        let image_data = ImageData {
            layers: vec![layer_1, layer_2],
            digest: None,
            config: config_obj,
            manifest: Some(manifest_obj),
        };

        image_data
    }

    #[test]
    fn test_from_image_data() {
        let mock_image_data = build_image_data();

        let image_hash = format!(
            "sha256:{:x}",
            sha2::Sha256::digest(&mock_image_data.config.data)
        );
        assert_eq!(image_hash, format!("sha256:{}", TEST_IMAGE_HASH));

        let image_details = ImageDetails::build_details(TEST_IMAGE_NAME, &mock_image_data)
            .expect("failed to build image details from ImageData");

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
