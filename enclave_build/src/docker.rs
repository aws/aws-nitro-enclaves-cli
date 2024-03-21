// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::docker::DockerError::CredentialsError;
use crate::utils::handle_stream_output;
use base64::{engine::general_purpose, Engine as _};
use bollard::auth::DockerCredentials;
use bollard::image::{BuildImageOptions, CreateImageOptions};
use bollard::secret::ImageInspect;
use bollard::Docker;
use flate2::{write::GzEncoder, Compression};
use log::{debug, error};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;
use url::Url;

/// Docker inspect architecture constants
pub const DOCKER_ARCH_ARM64: &str = "arm64";
pub const DOCKER_ARCH_AMD64: &str = "amd64";

#[derive(Debug, PartialEq, Eq)]
pub enum DockerError {
    ConnectionError,
    BuildError,
    InspectError,
    PullError,
    RuntimeError,
    TempfileError,
    CredentialsError(String),
    UnsupportedEntryPoint,
}

/// Struct exposing the Docker functionalities to the EIF builder
pub struct DockerUtil {
    docker: Docker,
    docker_image: String,
}

impl DockerUtil {
    /// Constructor that takes as argument a tag for the docker image to be used
    pub fn new(docker_image: String) -> Result<Self, DockerError> {
        let mut docker_image = docker_image;

        if !docker_image.contains(':') {
            docker_image.push_str(":latest");
        }

        // DOCKER_HOST environment variable is parsed inside
        // if docker daemon address needs to be substituted.
        // By default, it tries to connect to 'unix:///var/run/docker.sock'
        let docker = Docker::connect_with_defaults().map_err(|e| {
            error!("{:?}", e);
            DockerError::ConnectionError
        })?;

        Ok(DockerUtil {
            docker,
            docker_image,
        })
    }

    fn parse_docker_host(docker_image: &str) -> Option<String> {
        if let Ok(uri) = Url::parse(docker_image) {
            uri.host().map(|s| s.to_string())
        } else {
            // Some Docker URIs don't have the protocol included, so just use
            // a dummy one to trick Url that it's a properly defined Uri.
            let uri = format!("dummy://{docker_image}");
            if let Ok(uri) = Url::parse(&uri) {
                uri.host().map(|s| s.to_string())
            } else {
                None
            }
        }
    }
    /// Returns the credentials by reading ${HOME}/.docker/config.json or ${DOCKER_CONFIG}
    ///
    /// config.json doesn't seem to have a schema that we could use to validate
    /// we are parsing it correctly, so the parsing mechanism had been infered by
    /// reading a config.json created by:
    //         Docker version 19.03.2
    fn get_credentials(&self) -> Result<DockerCredentials, DockerError> {
        let host = match Self::parse_docker_host(&self.docker_image) {
            Some(host) => host,
            None => return Err(CredentialsError("Invalid docker image URI!".to_string())),
        };

        let config_file = self.get_config_file()?;

        let config_json: serde_json::Value = serde_json::from_reader(&config_file)
            .map_err(|err| CredentialsError(format!("JSON was not well-formatted: {err}")))?;

        let auths = config_json.get("auths").ok_or_else(|| {
            CredentialsError("Could not find auths key in config JSON".to_string())
        })?;

        if let Value::Object(auths) = auths {
            for (registry_name, registry_auths) in auths.iter() {
                if !registry_name.to_string().contains(&host) {
                    continue;
                }

                let auth = registry_auths
                    .get("auth")
                    .ok_or_else(|| {
                        CredentialsError("Could not find auth key in config JSON".to_string())
                    })?
                    .to_string();

                let auth = auth.replace('"', "");
                let decoded = general_purpose::STANDARD.decode(auth).map_err(|err| {
                    CredentialsError(format!("Invalid Base64 encoding for auth: {err}"))
                })?;
                let decoded = std::str::from_utf8(&decoded).map_err(|err| {
                    CredentialsError(format!("Invalid utf8 encoding for auth: {err}"))
                })?;

                if let Some(index) = decoded.rfind(':') {
                    let (user, after_user) = decoded.split_at(index);
                    let (_, password) = after_user.split_at(1);
                    return Ok(DockerCredentials {
                        username: Some(user.to_string()),
                        password: Some(password.to_string()),
                        ..Default::default()
                    });
                }
            }
        }

        Err(CredentialsError(
            "No credentials found for the current image".to_string(),
        ))
    }

    fn get_config_file(&self) -> Result<File, DockerError> {
        if let Ok(file) = std::env::var("DOCKER_CONFIG") {
            let config_file = File::open(file).map_err(|err| {
                DockerError::CredentialsError(format!(
                    "Could not open file pointed by env\
                     DOCKER_CONFIG: {err}"
                ))
            })?;
            Ok(config_file)
        } else {
            if let Ok(home_dir) = std::env::var("HOME") {
                let default_config_path = format!("{home_dir}/.docker/config.json");
                let config_path = Path::new(&default_config_path);
                if config_path.exists() {
                    let config_file = File::open(config_path).map_err(|err| {
                        DockerError::CredentialsError(format!(
                            "Could not open file {:?}: {}",
                            config_path.to_str(),
                            err
                        ))
                    })?;
                    return Ok(config_file);
                }
            }
            Err(DockerError::CredentialsError(
                "Config file not present, please set env \
                 DOCKER_CONFIG accordingly"
                    .to_string(),
            ))
        }
    }

    /// Pull the image, with the tag provided in constructor, from the Docker registry
    pub fn pull_image(&self) -> Result<(), DockerError> {
        // Check if the Docker image is locally available.
        // If available, early exit.
        if self.inspect().is_ok() {
            eprintln!("Using the locally available Docker image...");
            return Ok(());
        }

        let runtime = Runtime::new().map_err(|_| DockerError::RuntimeError)?;

        runtime.block_on(async {
            let create_image_options = CreateImageOptions {
                from_image: self.docker_image.clone(),
                ..Default::default()
            };

            let credentials = match self.get_credentials() {
                Ok(auth) => Some(auth),
                // It is not mandatory to have the credentials set, but this is
                // the most likely reason for failure when pulling, so log the
                // error.
                Err(err) => {
                    debug!("WARNING!! Credential could not be set {:?}", err);
                    None
                }
            };

            let stream = self
                .docker
                .create_image(Some(create_image_options), None, credentials);

            handle_stream_output(stream, DockerError::PullError).await
        })
    }

    fn build_tarball(dockerfile_dir: String) -> Result<Vec<u8>, DockerError> {
        let encoder = GzEncoder::new(Vec::default(), Compression::best());
        let mut archive = tar::Builder::new(encoder);

        archive.append_dir_all(".", &dockerfile_dir).map_err(|e| {
            error!("{:?}", e);
            DockerError::BuildError
        })?;

        archive.into_inner().and_then(|c| c.finish()).map_err(|e| {
            error!("{:?}", e);
            DockerError::BuildError
        })
    }

    /// Build an image locally, with the tag provided in constructor, using a
    /// directory that contains a Dockerfile
    pub fn build_image(&self, dockerfile_dir: String) -> Result<(), DockerError> {
        let runtime = Runtime::new().map_err(|_| DockerError::RuntimeError)?;

        runtime.block_on(async move {
            let stream = self.docker.build_image(
                BuildImageOptions {
                    dockerfile: "Dockerfile".to_string(),
                    t: self.docker_image.clone(),
                    ..Default::default()
                },
                None,
                Some(Self::build_tarball(dockerfile_dir)?.into()),
            );

            handle_stream_output(stream, DockerError::BuildError).await
        })
    }

    fn inspect(&self) -> Result<ImageInspect, DockerError> {
        let runtime = Runtime::new().map_err(|_| DockerError::RuntimeError)?;
        let image_future = self.docker.inspect_image(&self.docker_image);

        runtime.block_on(async {
            match image_future.await {
                Ok(image) => Ok(image),
                Err(e) => {
                    error!("{:?}", e);
                    Err(DockerError::InspectError)
                }
            }
        })
    }

    /// Inspect docker image and return its description as a json String
    pub fn inspect_image(&self) -> Result<serde_json::Value, DockerError> {
        match self.inspect() {
            Ok(image) => Ok(json!(image)),
            Err(e) => {
                error!("{:?}", e);
                Err(DockerError::InspectError)
            }
        }
    }

    fn extract_image(&self) -> Result<(Vec<String>, Vec<String>), DockerError> {
        // First try to find CMD parameters (together with potential ENV bindings)
        let image = self.inspect()?;
        let config = image.config.ok_or(DockerError::UnsupportedEntryPoint)?;

        if let Some(cmd) = &config.cmd {
            let env = config.env.unwrap_or_default();
            return Ok((cmd.clone(), env));
        }

        // If no CMD instructions are found, try to locate an ENTRYPOINT command
        if let Some(entrypoint) = &config.entrypoint {
            let env = config.env.unwrap_or_default();
            return Ok((entrypoint.clone(), env));
        }

        Err(DockerError::UnsupportedEntryPoint)
    }

    /// The main function of this struct. This needs to be called in order to
    /// extract the necessary configuration values from the docker image with
    /// the tag provided in the constructor
    pub fn load(&self) -> Result<(NamedTempFile, NamedTempFile), DockerError> {
        let (cmd, env) = self.extract_image()?;

        let cmd_file = write_config(cmd)?;
        let env_file = write_config(env)?;

        Ok((cmd_file, env_file))
    }

    /// Fetch architecture information from an image
    pub fn architecture(&self) -> Result<String, DockerError> {
        let image = self.inspect()?;
        Ok(image.architecture.unwrap_or_default())
    }
}

fn write_config(config: Vec<String>) -> Result<NamedTempFile, DockerError> {
    let mut file = NamedTempFile::new().map_err(|_| DockerError::TempfileError)?;

    for line in config {
        file.write_fmt(format_args!("{line}\n"))
            .map_err(|_| DockerError::TempfileError)?;
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use std::{env, io::Read};

    /// Test extracted configuration is as expected
    #[test]
    fn test_config() {
        let docker = DockerUtil::new(String::from("public.ecr.aws/aws-nitro-enclaves/hello:v1"));

        let (cmd_file, env_file) = docker.unwrap().load().unwrap();
        let mut cmd_file = File::open(cmd_file.path()).unwrap();
        let mut env_file = File::open(env_file.path()).unwrap();

        let mut cmd = String::new();
        cmd_file.read_to_string(&mut cmd).unwrap();
        assert_eq!(cmd, "/bin/hello.sh\n");

        let mut env = String::new();
        env_file.read_to_string(&mut env).unwrap();
        assert_eq!(
            env,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
             HELLO=Hello from the enclave side!\n"
        );
    }

    #[test]
    fn test_new() {
        let docker = DockerUtil::new(String::from("alpine")).unwrap();
        assert_eq!(docker.docker_image, "alpine:latest");
        let docker = DockerUtil::new(String::from("nginx:1.19")).unwrap();
        assert_eq!(docker.docker_image, "nginx:1.19");
    }

    #[test]
    fn test_get_credentials() {
        let test_user = "test_user";
        let test_password = "test_password";
        let auth = format!("{}:{}", test_user, test_password);
        let encoded_auth = general_purpose::STANDARD.encode(auth);
        let config = format!(
            r#"{{
            "auths": {{
              "https://public.ecr.aws/aws-nitro-enclaves/hello/v1/": {{
                "auth": "{}"
              }},
              "https://registry.example.com": {{
                "auth": "b3RoZXJfdXNlcjpvdGhlcl9wYXNzd29yZA=="
              }}
            }}
          }}"#,
            encoded_auth
        );

        // Create a temporary file
        let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file.");

        // Write the config to the temporary file
        write!(temp_file, "{}", config).expect("Failed to write to temporary file.");

        // Set the DOCKER_CONFIG environment variable to point to the temporary file's path
        let temp_file_path = temp_file.path().to_string_lossy().to_string();
        env::set_var("DOCKER_CONFIG", temp_file_path);

        let docker =
            DockerUtil::new(String::from("public.ecr.aws/aws-nitro-enclaves/hello:v1")).unwrap();
        let creds = docker.get_credentials().unwrap();
        assert_eq!(creds.username, Some(test_user.to_string()));
        assert_eq!(creds.password, Some(test_password.to_string()));

        temp_file.close().unwrap();
    }

    #[test]
    fn test_architecture() {
        #[cfg(target_arch = "x86_64")]
        {
            let docker =
                DockerUtil::new(String::from("public.ecr.aws/aws-nitro-enclaves/hello:v1"))
                    .unwrap();
            docker.pull_image().unwrap();
            let arch = docker.architecture().unwrap();
            assert_eq!(arch, "amd64");
        }

        #[cfg(target_arch = "aarch64")]
        {
            let docker = DockerUtil::new(String::from("arm64v8/alpine")).unwrap();
            docker.pull_image().unwrap();
            let arch = docker.architecture().unwrap();
            assert_eq!(arch, "arm64");
        }
    }
}
