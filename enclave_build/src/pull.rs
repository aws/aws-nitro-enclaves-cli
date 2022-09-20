// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use std::fs::File;
use std::path::Path;
use url::Url;

use oci_distribution::{
    client::{Client, ClientConfig, ClientProtocol, ImageData},
    secrets::RegistryAuth,
};

use crate::{
    image::{self, deserialize_from_reader},
    EnclaveBuildError, Result,
};

/// Number of accepted image layer media types.
pub const ACCEPTED_MEDIA_TYPES_COUNT: usize = 3;
/// Accepted image layer media types.
pub const ACCEPTED_MEDIA_TYPES: [&str; ACCEPTED_MEDIA_TYPES_COUNT] = [
    oci_distribution::manifest::WASM_LAYER_MEDIA_TYPE,
    oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
    oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
];
/// Sequence of environment variables and config file paths to try parsing: (env, path)
pub const CONFIG_ENV_PATHS: [(&str, &str); 3] = [
    ("DOCKER_CONFIG", ""),
    ("XDG_RUNTIME_DIR", "containers/auth.json"),
    ("HOME", ".docker/config.json"),
];

/// Builds a client which uses the protocol given as parameter.
///
/// Client required for the https://github.com/krustlet/oci-distribution library API.
///
/// By default, the client pulls the image matching the current running architecture.
fn build_client(protocol: ClientProtocol) -> Client {
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
    for (env, path) in CONFIG_ENV_PATHS {
        if let Ok(env_val) = std::env::var(env) {
            let mut config_path = Path::new(&env_val).to_owned();
            if !path.is_empty() {
                config_path = config_path.join(path);
            }
            match File::open(&config_path) {
                Ok(file) => {
                    return Ok(file);
                }
                Err(e) => {
                    eprintln!("Could not get credentials from {:?}: {}", config_path, e);
                    continue;
                }
            }
        }
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
fn parse_credentials(image_name: &str) -> Result<RegistryAuth> {
    let host = if let Ok(uri) = Url::parse(image_name) {
        uri.host().map(|s| s.to_string())
    } else {
        // Some Docker URIs don't have the protocol included, so just use
        // a dummy one to trick Url that it's a properly defined Uri.
        let uri = format!("dummy://{}", image_name);
        if let Ok(uri) = Url::parse(&uri) {
            uri.host().map(|s| s.to_string())
        } else {
            None
        }
    };

    if let Some(registry_domain) = host {
        let config_file = get_docker_config_file()?;

        let config_json: serde_json::Value =
            deserialize_from_reader(&config_file).map_err(|err| {
                EnclaveBuildError::CredentialsError(format!(
                    "JSON was not well-formatted: {:?}",
                    err
                ))
            })?;

        let auths = config_json.get("auths").ok_or_else(|| {
            EnclaveBuildError::CredentialsError(
                "Could not find auths key in config JSON".to_string(),
            )
        })?;

        if let serde_json::Value::Object(auths) = auths {
            for (registry_name, registry_auths) in auths {
                if !registry_name.to_string().contains(&registry_domain) {
                    continue;
                }

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
    }

    // If the auth token is missing, return error
    Err(EnclaveBuildError::CredentialsError(
        "Credentials not found.".to_string(),
    ))
}

/// Determines the authentication for interacting with the remote registry.
fn registry_auth(image_name: &str) -> RegistryAuth {
    match parse_credentials(image_name) {
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
pub async fn pull_image_data(image_name: &str) -> Result<ImageData> {
    // Build the client required for the pulling - uses HTTPS protocol
    let mut client = build_client(ClientProtocol::Https);

    let image_ref = image::build_image_reference(image_name)
        .map_err(|err| EnclaveBuildError::ImagePullError(err.to_string()))?;

    let auth = registry_auth(image_name);

    // Pull from remote an ImageData struct containing the layers, manifest and configuration files
    client
        .pull(&image_ref, &auth, ACCEPTED_MEDIA_TYPES.to_vec())
        .await
        .map_err(|err| EnclaveBuildError::ImagePullError(err.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;
    use serde_json::{json, Value};
    use sha2::Digest;
    use vmm_sys_util::tempfile::TempFile;

    #[cfg(target_arch = "x86_64")]
    const SAMPLE_IMAGE: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample-server-x86_64";
    #[cfg(target_arch = "aarch64")]
    const SAMPLE_IMAGE: &str =
        "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample-server-aarch64";
    #[cfg(target_arch = "x86_64")]
    const IMAGE_HASH: &str =
        "sha256:d63f69841675f849534670141c0f7106f1f2faa5d4bf02ea8f144bd3ca292f80";
    #[cfg(target_arch = "aarch64")]
    const IMAGE_HASH: &str =
        "sha256:0af5126ba4d02a5b64c831bce95a8aa98e20b0ed9ea60174dae19000de813a6c";

    const IMAGE_REG: &str = "667861386598.dkr.ecr.us-east-1.amazonaws.com";
    const TEST_USER: &str = "test_username";
    const TEST_PASS: &str = "test_password";

    fn generate_valid_credential_json() -> Value {
        let credentials = TEST_USER.to_string() + ":" + TEST_PASS;
        let encoded_token = base64::encode(credentials);

        json!({
            "auths": {
                IMAGE_REG: {
                    "auth": encoded_token
                }
            }
        })
    }

    fn generate_credential_json_missing_auth() -> Value {
        json!({
            "auths": {
                IMAGE_REG: {},
                "reg1": {
                    "auth": "token1"
                },
                "reg2":  {
                    "auth": "token2"
                },
            }
        })
    }

    fn generate_credential_json_invalid_encoding() -> Value {
        json!({
            "auths": {
                IMAGE_REG: {
                    "auth": "not_base64"
                },
            }
        })
    }

    fn generate_credential_json_invalid_reg() -> Value {
        let credentials = TEST_USER.to_string() + ":" + TEST_PASS;
        let encoded_token = base64::encode(credentials);

        json!({
            "auths": {
                "https://index.docker.io/v1/": {
                    "auth": encoded_token
                }
            }
        })
    }

    fn create_auth_file(content: &Value) -> TempFile {
        let auth_file = TempFile::new().unwrap();
        let json_bytes = serde_json::to_vec(content).unwrap();
        auth_file.as_file().write_all(&json_bytes[..]).unwrap();

        auth_file
    }

    /// Extract username from the base64 encoded credential token. Password can't be known
    #[test]
    fn test_parsing_credentials() {
        let auth_content = generate_valid_credential_json();
        let tmp_file = create_auth_file(&auth_content);
        let config_path = tmp_file.as_path();
        std::env::set_var("DOCKER_CONFIG", config_path);

        let uri = SAMPLE_IMAGE;

        let credentials = parse_credentials(uri).unwrap();

        if let RegistryAuth::Basic(username, password) = credentials {
            assert_eq!(username, TEST_USER);
            assert_eq!(password, TEST_PASS);
        } else {
            unreachable!();
        }
    }

    /// Test different credential parsing errors
    fn test_parsing_failure(content: &Value) {
        let tmp_file = create_auth_file(&content);
        let config_path = tmp_file.as_path();
        std::env::set_var("DOCKER_CONFIG", config_path);

        let uri = SAMPLE_IMAGE;

        let credentials = parse_credentials(uri);

        match credentials {
            Err(EnclaveBuildError::CredentialsError(_)) => assert!(true),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_parsing_credentials_missing_auth() {
        let auth_content = generate_credential_json_missing_auth();
        test_parsing_failure(&auth_content);
    }

    #[test]
    fn test_parsing_credentials_invalid_encoding() {
        let auth_content = generate_credential_json_invalid_encoding();
        test_parsing_failure(&auth_content);
    }

    #[test]
    fn test_parsing_credentials_invalid_reg() {
        let auth_content = generate_credential_json_invalid_reg();
        test_parsing_failure(&auth_content);
    }

    /// Tests credential file fallback. The testing environment will save the credentials by performing
    /// `docker login` meaning that the credential file will be the last option
    #[test]
    fn test_get_config_file() {
        let mut config_file = get_docker_config_file().unwrap();

        let mut content = String::new();
        config_file.read_to_string(&mut content).unwrap();

        let home_env = std::env::var("HOME").unwrap();
        let home_path = Path::new(&home_env);
        let expected_path = home_path.join(".docker/config.json");
        let mut expected_file = File::open(expected_path).unwrap();

        let mut expected_content = String::new();
        expected_file.read_to_string(&mut expected_content).unwrap();

        assert_eq!(content, expected_content);
    }

    /// Pull image from private registry and validate config hash
    #[tokio::test]
    async fn test_pull() {
        std::env::set_var("DOCKER_CONFIG", "/root/.docker/config.json");

        let uri = SAMPLE_IMAGE;

        let image_data = pull_image_data(uri).await.unwrap();
        let image_hash = format!("sha256:{:x}", sha2::Sha256::digest(&image_data.config.data));

        assert_eq!(image_hash, IMAGE_HASH.to_string());
    }

    /// Test failing authentication and failing anonymous pull
    #[tokio::test]
    async fn test_pull_invalid_uri() {
        std::env::set_var("DOCKER_CONFIG", "/root/.docker/config.json");
        let uri = "invalid/registry:invalid_image";

        let image_data = pull_image_data(uri).await;
        match image_data {
            Err(EnclaveBuildError::ImagePullError(_)) => assert!(true),
            _ => unreachable!(),
        }
    }
}
