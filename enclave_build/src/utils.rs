
use oci_distribution::{Client, Reference};
use oci_distribution::client::{ImageLayer};
use oci_distribution::client::ClientProtocol;
use oci_distribution::client::ImageData;

use serde_json::Value;
use serde::{Serialize, Deserialize};

#[derive(Debug, PartialEq)]
pub enum ExtractError {
    ImageExtractError(String),
    ManifestExtractError(String),
    LayerExtractError(String),
    ConfigExtractError(String),
    EnvCmdExtractError(String),
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

/// Builds a docker image reference from the image name given as parameter
/// The image reference struct is from https://github.com/krustlet/oci-distribution library
pub fn build_image_reference(img_full_name: &String) -> Reference {
    img_full_name.parse().expect("Not a valid image reference")
}

pub fn get_image_name_from_ref(image_ref: &Reference) -> String {
    image_ref.repository().split("/").collect::<Vec<&str>>().get(1).unwrap().to_string()
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
            0 => Err(ExtractError::ImageExtractError("No image data found".to_string())),
            _ => Ok(image_bytes)
        }
    }

    /// Extract the layers as an array of ImageLayer structs
    pub fn extract_layers(image_data: &ImageData) -> Result<Vec<ImageLayer>, ExtractError> {
        match image_data.layers.len() {
            0 => Err(ExtractError::LayerExtractError("Layers not found.".to_string())),
            _ => Ok(image_data.layers.clone())
        }
    }

    /// Extract the manifest of an image as a JSON string
    pub fn extract_manifest_json(image_data: &ImageData) -> Result<String, ExtractError> {
        match &image_data.manifest {
            Some(image_manifest) => Ok(serde_json::to_string(&image_manifest).unwrap()),
            None => Err(ExtractError::ManifestExtractError("No manifest found.".to_string()))
        }
    }

    /// Extract the configuration file of an image as a JSON string
    pub fn extract_config_json(image_data: &ImageData) -> Result<String, ExtractError> {
        match String::from_utf8(image_data.config.data.clone()) {
            Ok(config_json) => Ok(config_json),
            Err(err) => Err(ExtractError::ConfigExtractError(format!("Cannot extract manifest: {}", err)))
        }
    }

    /// Extract the ENV expressions from an image
    pub fn extract_env_expressions(image_data: &ImageData) -> Result<Vec<String>, ExtractError> {
        let config_string = String::from_utf8(image_data.config.data.clone())
            .expect("Failed to convert config data bytes to string.");

        // Try to parse the JSON
        let json_object: Value = serde_json::from_str(config_string.as_str()).unwrap();
        let config_obj = json_object.get("container_config").expect("'container config' field is missing");
        let env_obj = config_obj.get("Env").expect("'Env' field is missing");

        match env_obj.as_array() {
            None => Err(ExtractError::EnvCmdExtractError("Failed to extract ENV expressions from image.".to_string())),
            Some(env_array) => {
                let env_strings: Vec<String> = env_array.into_iter().map(|json_value| json_value.to_string()).collect();
                Ok(env_strings)
            }
        }
    }

    /// Extract the CMD expressions from an image
    pub fn extract_cmd_expressions(image_data: &ImageData) -> Result<Vec<String>, ExtractError> {
        let config_string = String::from_utf8(image_data.config.data.clone())
            .expect("Failed to convert config data bytes to string");

        // Try to parse the JSON
        let json_object: Value = serde_json::from_str(config_string.as_str()).unwrap();
        let config_obj = json_object.get("container_config").expect("'container_config' field is missing");
        let cmd_obj = config_obj.get("Cmd").expect("'Cmd' field is missing");

        match cmd_obj.as_array() {
            None => Err(ExtractError::EnvCmdExtractError("Failed to extract CMD expressions from image".to_string())),
            Some(cmd_array) => {
                let cmd_strings: Vec<String> = cmd_array.into_iter().map(|json_value| json_value.to_string()).collect();
                Ok(cmd_strings)
            }
        }
    }
}
