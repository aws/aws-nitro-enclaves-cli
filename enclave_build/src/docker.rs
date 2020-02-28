// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::docker::DockerError::CredentialsError;
use log::{debug, error, info};
use serde_json::value::Value;
use shiplift::RegistryAuth;
use shiplift::{BuildOptions, Docker, PullOptions};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
use tokio::prelude::{Future, Stream};
use url::Url;

#[derive(Debug, PartialEq)]
pub enum DockerError {
    BuildError,
    InspectError,
    PullError,
    RuntimeError,
    TempfileError,
    CredentialsError(String),
}

/// Struct exposing the Docker functionalities to the EIF builder
pub struct DockerUtil {
    docker: Docker,
    docker_image: String,
}

impl DockerUtil {
    /// Constructor that takes as argument a tag for the docker image to be used
    pub fn new(docker_image: String) -> Self {
        // Try to parse the DOCKER_HOST environment variable.
        let host = match env::var("DOCKER_HOST") {
            Ok(docker_host) => match docker_host.parse() {
                Ok(host) => Some(host),
                Err(_) => None,
            },
            Err(_) => None,
        };

        // If DOCKER_HOST could not be parsed, default to
        // using 'unix:///var/run/docker.sock'.
        let docker = match host {
            Some(host) => Docker::host(host),
            None => Docker::unix("/var/run/docker.sock"),
        };

        let mut docker_image = docker_image;

        if !docker_image.contains(":") {
            docker_image.push_str(":latest");
        }

        DockerUtil {
            docker,
            docker_image,
        }
    }

    /// Returns the credentials by reading ${HOME}/.docker/config.json or ${DOCKER_CONFIG}
    ///
    /// config.json doesn't seem to have a schema that we could use to validate
    /// we are parsing it correctly, so the parsing mechanism had been infered by
    /// reading a config.json created by:
    //         Docker version 19.03.2
    fn get_credentials(&self) -> Result<RegistryAuth, DockerError> {
        let image = self.docker_image.clone();
        let host = if let Ok(uri) = Url::parse(&image) {
            uri.host().map(|s| s.to_string())
        } else {
            // Some Docker URIs don't have the protocol included, so just use
            // a dummy one to trick Url that it's a properly defined Uri.
            let uri = format!("dummy://{}", image);
            if let Ok(uri) = Url::parse(&uri) {
                uri.host().map(|s| s.to_string())
            } else {
                None
            }
        };

        if let Some(registry_domain) = host {
            let config_file = self.get_config_file()?;

            let config_json: serde_json::Value =
                serde_json::from_reader(&config_file).map_err(|err| {
                    CredentialsError(format!("JSON was not well-formatted: {}", err.to_string()))
                })?;

            let auths = config_json.get("auths").ok_or(CredentialsError(
                "Could not find auths key in config JSON".to_string(),
            ))?;

            if let Value::Object(auths) = auths {
                for (registry_name, registry_auths) in auths.iter() {
                    if !registry_name.to_string().contains(&registry_domain) {
                        continue;
                    }

                    let auth = registry_auths
                        .get("auth")
                        .ok_or(CredentialsError(
                            "Could not find auth key in config JSON".to_string(),
                        ))?
                        .to_string();

                    let auth = auth.replace(r#"""#, "");
                    let decoded = base64::decode(&auth).map_err(|err| {
                        CredentialsError(format!("Invalid Base64 encoding for auth: {}", err))
                    })?;
                    let decoded = std::str::from_utf8(&decoded).map_err(|err| {
                        CredentialsError(format!("Invalid utf8 encoding for auth: {}", err))
                    })?;

                    if let Some(index) = decoded.rfind(":") {
                        let (user, after_user) = decoded.split_at(index);
                        let (_, password) = after_user.split_at(1);
                        return Ok(RegistryAuth::builder()
                            .username(user)
                            .password(password)
                            .build());
                    }
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
                     DOCKER_CONFIG: {}",
                    err.to_string()
                ))
            })?;
            Ok(config_file)
        } else {
            if let Ok(home_dir) = std::env::var("HOME") {
                let default_config_path = format!("{}/.docker/config.json", home_dir);
                let config_path = Path::new(&default_config_path);
                if config_path.exists() {
                    let config_file = File::open(config_path).map_err(|err| {
                        DockerError::CredentialsError(format!(
                            "Could not open file {:?}: {}",
                            config_path.to_str(),
                            err.to_string()
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
        let mut pull_options_builder = PullOptions::builder();
        pull_options_builder.image(&self.docker_image);

        match self.get_credentials() {
            Ok(auth) => {
                pull_options_builder.auth(auth);
            }
            // It is not mandatory to have the credentials set, but this is
            // the most likely reason for failure when pulling, so log the
            // error.
            Err(err) => {
                debug!("WARNING!! Credential could not be set {:?}", err);
            }
        };

        let act = self
            .docker
            .images()
            .pull(&pull_options_builder.build())
            .then(|output| {
                if let Ok(msg) = &output {
                    if let Some(err_msg) = msg.get("error") {
                        return Err(err_msg.clone());
                    }
                }
                Ok(output)
            })
            .for_each(|msg| {
                if let Ok(msg) = msg {
                    info!("{}", msg);
                }
                Ok(())
            })
            .map_err(|e| {
                error!("{:?}", e);
                DockerError::PullError
            });

        let mut runtime = tokio::runtime::Runtime::new().map_err(|_| DockerError::RuntimeError)?;
        runtime.block_on(act)
    }

    /// Build an image locally, with the tag provided in constructor, using a
    /// directory that contains a Dockerfile
    pub fn build_image(&self, dockerfile_dir: String) -> Result<(), DockerError> {
        let act = self
            .docker
            .images()
            .build(
                &BuildOptions::builder(dockerfile_dir)
                    .tag(self.docker_image.clone())
                    .build(),
            )
            .then(|output| {
                if let Ok(msg) = &output {
                    if let Some(err_msg) = msg.get("error") {
                        return Err(err_msg.clone());
                    }
                }
                Ok(output)
            })
            .for_each(|msg| {
                if let Ok(msg) = msg {
                    info!("{}", msg);
                }
                Ok(())
            })
            .map_err(|e| {
                error!("{:?}", e);
                DockerError::BuildError
            });

        let mut runtime = tokio::runtime::Runtime::new().map_err(|_| DockerError::RuntimeError)?;

        runtime.block_on(act)
    }

    fn inspect_image(&self) -> Result<(Vec<String>, Vec<String>), DockerError> {
        let act = self
            .docker
            .images()
            .get(&self.docker_image)
            .inspect()
            .map(|image| (image.config.cmd.unwrap(), image.config.env.unwrap()))
            .map_err(|e| {
                error!("{:?}", e);
                DockerError::InspectError
            });

        let mut runtime = tokio::runtime::Runtime::new().map_err(|_| DockerError::RuntimeError)?;

        runtime.block_on(act)
    }

    /// The main function of this struct. This needs to be called in order to
    /// extract the necessary configuration values from the docker image with
    /// the tag provided in the constructor
    pub fn load(&self) -> Result<(NamedTempFile, NamedTempFile), DockerError> {
        let (cmd, env) = self.inspect_image()?;

        let cmd_file = write_config(cmd)?;
        let env_file = write_config(env)?;

        Ok((cmd_file, env_file))
    }
}

fn write_config(config: Vec<String>) -> Result<NamedTempFile, DockerError> {
    let mut file = NamedTempFile::new().map_err(|_| DockerError::TempfileError)?;

    for line in config {
        file.write_fmt(format_args!("{}\n", line))
            .map_err(|_| DockerError::TempfileError)?;
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Test extracted configuration is as expected
    #[test]
    fn test_config() {
        let docker = DockerUtil::new(String::from(
            "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample",
        ));

        let (cmd_file, env_file) = docker.load().unwrap();
        let mut cmd_file = File::open(cmd_file.path()).unwrap();
        let mut env_file = File::open(env_file.path()).unwrap();

        let mut cmd = String::new();
        cmd_file.read_to_string(&mut cmd).unwrap();
        assert_eq!(
            cmd,
            "/nc-vsock\n\
             -l\n\
             5000\n"
        );

        let mut env = String::new();
        env_file.read_to_string(&mut env).unwrap();
        assert_eq!(
            env,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        );
    }
}
