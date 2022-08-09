// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use oci_distribution::{Client, Reference};
use oci_distribution::client::{ImageLayer};
use oci_distribution::client::ClientProtocol;
use oci_distribution::client::ImageData;

use serde_json::Value;

use crate::cache_manager::{CacheManager};

#[derive(Debug, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum ExtractError {
    ImageError(String),
    ManifestError(String),
    LayerError(String),
    ConfigError(String),
    EnvCmdError(String),
    ImageHashError(String),
}

/// Builds a client which uses the protocol given as parameter
/// Client required for the https://github.com/krustlet/oci-distribution library
pub fn build_client(protocol: ClientProtocol) -> Client {
    let client_config = oci_distribution::client::ClientConfig {
        protocol,
        ..Default::default()
    };
    Client::new(client_config)
}

/// Contains the logic for the extraction of image data from an ImageData struct to be stored later
/// in the local cache
pub struct ExtractLogic {}

impl ExtractLogic {
    /// Extract the image itself (the layers) as a raw array of bytes
    pub fn extract_image(image_data: &ImageData) -> Result<Vec<u8>, ExtractError> {
        let image_bytes = image_data.clone()
            .layers
            .into_iter()
            .next()
            .map(|layer| layer.data)
            .expect("No data found.");

        match image_bytes.len() {
            0 => Err(ExtractError::ImageError("Failed to extract the image file.".to_string())),
            _ => Ok(image_bytes)
        }
    }

    /// Extract the layers as an array of ImageLayer structs
    pub fn extract_layers(image_data: &ImageData) -> Result<Vec<ImageLayer>, ExtractError> {
        match image_data.layers.len() {
            0 => Err(ExtractError::LayerError("Failed to extract the layers of the image.".to_string())),
            _ => Ok(image_data.layers.clone())
        }
    }

    /// Extract the manifest of an image as a JSON string
    pub fn extract_manifest_json(image_data: &ImageData) -> Result<String, ExtractError> {
        match &image_data.manifest {
            Some(image_manifest) => Ok(serde_json::to_string(&image_manifest).unwrap()),
            None => Err(ExtractError::ManifestError("Failed to extract the manifest from the image data.".to_string()))
        }
    }

    /// Extract the configuration file of an image as a JSON string
    pub fn extract_config_json(image_data: &ImageData) -> Result<String, ExtractError> {
        match String::from_utf8(image_data.config.data.clone()) {
            Ok(config_json) => Ok(config_json),
            Err(err) => Err(ExtractError::ConfigError(format!("Failed to extract the config JSON
                from the image data: {}", err)))
        }
    }

    /// Extract the ENV expressions from an image
    pub fn extract_env_expressions(image_data: &ImageData) -> Result<Vec<String>, ExtractError> {
        let config_string = String::from_utf8(image_data.config.data.clone())
            .map_err(|err| ExtractError::EnvCmdError(format!(
                "Failed to extract 'ENV' expressions: {:?}", err)))?;

        // Try to parse the JSON
        let json_object: Value = serde_json::from_str(config_string.as_str()).unwrap();
        let config_obj = json_object.get("container_config")
            .ok_or_else( || ExtractError::EnvCmdError(
                "'container config' field is missing in the configuration JSON.".to_string()))?;
        let env_obj = config_obj.get("Env")
            .ok_or_else(|| ExtractError::EnvCmdError(
                "'Env' field is missing in the configuration JSON.".to_string()))?;

        match env_obj.as_array() {
            None => Err(ExtractError::EnvCmdError("Failed to extract ENV expressions from image.".to_string())),
            Some(env_array) => {
                let env_strings: Vec<String> = env_array.iter().map(|json_value| json_value.to_string()).collect();
                Ok(env_strings)
            }
        }
    }

    /// Extract the CMD expressions from an image
    pub fn extract_cmd_expressions(image_data: &ImageData) -> Result<Vec<String>, ExtractError> {
        let config_string = String::from_utf8(image_data.config.data.clone())
            .map_err(|err| ExtractError::EnvCmdError(format!(
                "Failed to extract 'CMD' expressions: {:?}", err)))?;

        // Try to parse the JSON
        let json_object: Value = serde_json::from_str(config_string.as_str()).map_err(|err|
            ExtractError::EnvCmdError(format!("Failed to extract CMD expressions from an image: {:?}", err)))?;

        let config_obj = json_object.get("container_config")
            .ok_or_else(|| ExtractError::EnvCmdError(
                "'container config' field is missing in the configuration JSON.".to_string()))?;
        let cmd_obj = config_obj.get("Cmd")
            .ok_or_else(|| ExtractError::EnvCmdError(
                "'Cmd' field is missing in the configuration JSON.".to_string()))?;

        match cmd_obj.as_array() {
            None => Err(ExtractError::EnvCmdError("Failed to extract CMD expressions from image.".to_string())),
            Some(cmd_array) => {
                let cmd_strings: Vec<String> = cmd_array.iter().map(|json_value| json_value.to_string()).collect();
                Ok(cmd_strings)
            }
        }
    }

    /// Extract the image hash (digest) from an image
    pub fn extract_image_hash(image_data: &ImageData) -> Result<String, ExtractError> {
        // Extract the config JSON from the image
        let config_json = ExtractLogic::extract_config_json(image_data)
            .map_err(|err| ExtractError::ImageHashError(format!("{:?}", err)))?;

        // Try to parse the JSON for the image hash
        let json_object: Value = serde_json::from_str(config_json.as_str()).map_err(|err|
            ExtractError::EnvCmdError(format!("Failed to extract the image hash: {:?}", err)))?;

        let config_obj = json_object.get("config").ok_or_else(|| ExtractError::EnvCmdError(
            "'config' field is missing in the configuration JSON.".to_string()))?;

        let string = config_obj.get("Image").ok_or_else(|| ExtractError::EnvCmdError(
            "'Image' field is missing in the configuration JSON.".to_string()))?.to_string();

        // In the JSON, the hash is represented as "sha256: {HASH}"
        let arr: Vec<&str> = string.split(':').collect();
        
        let hash = arr.get(1).ok_or_else(|| ExtractError::EnvCmdError(
            "Failed to extract the image hash.".to_string()))?;

        let mut res = hash.to_string();
        // Eliminate the last '"' character
        res.pop();

        Ok(res)
    }
}

/// Wrapper struct which represents an image
/// 
/// reference: The image URI
/// data: The image data (layers, config etc.)
pub struct Image {
    reference: Reference,
    data: ImageData
}

impl Image {
    pub fn new(reference: Reference, data: ImageData) -> Image {
        Self { reference, data }
    }

    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    pub fn data(&self) -> &ImageData {
        &self.data
    }

    /// Builds a docker image reference from the image name given as parameter
    /// The image reference struct is from https://github.com/krustlet/oci-distribution library
    pub fn build_image_reference(img_full_name: &str) -> Reference {
        img_full_name.parse().expect("Not a valid image reference")
    }

    pub fn get_image_name_from_ref(image_ref: &Reference) -> String {
        image_ref.repository().split('/').collect::<Vec<&str>>().get(1).unwrap().to_string()
    }

    /// Returns the digest hash of an image by looking first in the cache,
    /// then trying to extract it from an ImageData struct
    pub fn get_image_hash(image: &Image, cache_manager: &CacheManager) -> Result<String, ExtractError> {
        let image_hash = match cache_manager.get_image_hash_from_cache(&image.reference().whole()) {
            Some(aux) => Ok(aux),
            None => match ExtractLogic::extract_image_hash(image.data()) {
                Ok(aux) => Ok(aux),
                Err(err) => Err(ExtractError::ImageHashError(format!("{:?}", err)))
            }
        };

        image_hash.map_err(|err| ExtractError::ImageHashError(format!("{:?}", err)))
    }
}
