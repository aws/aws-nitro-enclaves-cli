// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::path::Path;

use oci_distribution::{
    client::{Client, ClientConfig, ClientProtocol, ImageData},
    secrets::RegistryAuth,
};

use crate::{
    image::{self, deserialize_from_reader},
    EnclaveBuildError, Result,
};

/// Number of accepted image layer media types.
pub const ACCEPTED_MEDIA_TYPES_COUNT: u32 = 3;
/// Accepted image layer media types.
pub const ACCEPTED_MEDIA_TYPES: [&str; ACCEPTED_MEDIA_TYPES_COUNT as usize] = [
    oci_distribution::manifest::WASM_LAYER_MEDIA_TYPE,
    oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
    oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
];

/// Builds a client which uses the protocol given as parameter.
///
/// Client required for the https://github.com/krustlet/oci-distribution library API.
///
/// By default, the client pulls the image matching the current running architecture.
pub fn build_client(protocol: ClientProtocol) -> Client {
    let client_config = ClientConfig {
        protocol,
        ..Default::default()
    };
    Client::new(client_config)
}

/// Checks the DOCKER_CONFIG env variable for the path to the docker config file
///
/// If DOCKER_CONFIG is not set, try to get the config file from the default path
/// {XDG_RUNTIME_DIR}/containers/auth.json or {HOME}/.docker/config.json in a Podman-like behavior
fn get_docker_config_file() -> Result<File> {
    if let Ok(file) = std::env::var("DOCKER_CONFIG") {
        let config_path = Path::new(&file);
        match File::open(config_path) {
            Ok(file) => {
                return Ok(file);
            }
            Err(e) => {
                eprintln!("Could not get credentials from $DOCKER_CONFIG: {:?}", e);
            }
        };
    }

    if let Ok(xdg_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let default_config_path = format!("{}/containers/auth.json", xdg_dir);
        let config_path = Path::new(&default_config_path);
        match File::open(config_path) {
            Ok(file) => {
                return Ok(file);
            }
            Err(e) => {
                eprintln!(
                    "Could not get credentials from $XDG_RUNTIME_DIR/containers/auth.json: {:?}",
                    e
                );
            }
        };
    }

    if let Ok(home_dir) = std::env::var("HOME") {
        let docker_config_path = format!("{}/.docker/config.json", home_dir);
        let config_path = Path::new(&docker_config_path);
        match File::open(config_path) {
            Ok(file) => {
                return Ok(file);
            }
            Err(e) => {
                eprintln!(
                    "Could not get credentials from $HOME/.docker/config.json: {:?}",
                    e
                );
            }
        };
    }

    Err(EnclaveBuildError::FileError(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Config file not present",
    )))
}

/// Returns the Docker credentials by reading from the Docker config.json file.
///
/// The assumed format of the file is:\
/// {\
///        "auths": {\
///            "https://index.docker.io/v1/": {\
///                    "auth": "<token_string>"\
///            }\
///        }\
/// }
pub fn parse_credentials() -> Result<RegistryAuth> {
    let config_file = get_docker_config_file()?;

    let config_json: serde_json::Value = deserialize_from_reader(&config_file).map_err(|err| {
        EnclaveBuildError::CredentialsError(format!("JSON was not well-formatted: {:?}", err))
    })?;

    let auths = config_json.get("auths").ok_or_else(|| {
        EnclaveBuildError::CredentialsError("Could not find auths key in config JSON".to_string())
    })?;

    if let serde_json::Value::Object(auths) = auths {
        for registry_auths in auths.values() {
            let auth = registry_auths
                .get("auth")
                .ok_or_else(|| {
                    EnclaveBuildError::CredentialsError(
                        "Could not find auth key in config JSON".to_string(),
                    )
                })?
                .to_string();

            let auth = auth.replace('"', "");
            // Decode the auth token
            let decoded = base64::decode(&auth).map_err(|err| {
                EnclaveBuildError::CredentialsError(format!(
                    "Invalid Base64 encoding for auth: {}",
                    err
                ))
            })?;
            let decoded = std::str::from_utf8(&decoded).map_err(|err| {
                EnclaveBuildError::CredentialsError(format!(
                    "Invalid utf8 encoding for auth: {}",
                    err
                ))
            })?;

            // Try to get the username and the password
            if let Some(index) = decoded.rfind(':') {
                let (username, after_user) = decoded.split_at(index);
                let (_, password) = after_user.split_at(1);

                return Ok(RegistryAuth::Basic(
                    username.to_string(),
                    password.to_string(),
                ));
            }
        }
    }

    // If the auth token is missing, return error
    Err(EnclaveBuildError::CredentialsError(
        "Credentials not found.".to_string(),
    ))
}

/// Determines the authentication for interacting with the remote registry.
pub fn registry_auth() -> RegistryAuth {
    match parse_credentials() {
        Ok(registry_auth) => {
            let (user, pass) = if let RegistryAuth::Basic(user, pass) = registry_auth {
                (user, pass)
            } else {
                (String::new(), String::new())
            };
            RegistryAuth::Basic(user, pass)
        }
        Err(err) => {
            eprintln!("Credentials error: {:?}, performing anonymous pull.", err);
            RegistryAuth::Anonymous
        }
    }
}

/// Pulls an image (all blobs - layers, manifest and config) from a Docker remote registry.
pub async fn pull_image_data<S: AsRef<str>>(image_name: S) -> Result<ImageData> {
    // Build the client required for the pulling - uses HTTPS protocol
    let mut client = build_client(ClientProtocol::Https);

    let image_ref = image::build_image_reference(image_name)
        .map_err(|err| EnclaveBuildError::ImagePullError(err.to_string()))?;

    let auth = registry_auth();

    // Pull from remote an ImageData struct containing the layers, manifest and configuration files
    client
        .pull(&image_ref, &auth, ACCEPTED_MEDIA_TYPES.to_vec())
        .await
        .map_err(|err| EnclaveBuildError::ImagePullError(err.to_string()))
}
