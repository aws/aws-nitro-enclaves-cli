// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::cache::CacheManager;
use crate::image::ImageDetails;
use crate::{EnclaveBuildError, Result};

use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

/// Trait which provides an interface for handling images.
pub trait ImageManager {
    fn image_name(&self) -> &String;
    /// Pulls the image from remote and stores it in the local cache.
    fn pull_image(&mut self) -> Result<()>;
    /// Builds an image locally (from a Dockerfile in case of Docker).
    fn build_image(&self, dockerfile_dir: String) -> Result<()>;
    /// Inspects the image and returns its metadata in the form of a JSON Value.
    fn inspect_image(&mut self) -> Result<serde_json::Value>;
    /// Returns the architecture of the image.
    fn architecture(&mut self) -> Result<String>;
    /// Returns two temp files containing the CMD and ENV expressions extracted from the image,
    /// in this order.
    fn load(&mut self) -> Result<(NamedTempFile, NamedTempFile)>;
    /// Returns true if the image manager uses the Docker daemon
    fn use_docker(&self) -> bool;
}

pub struct OciImageManager {
    /// Name of the container image.
    image_name: String,
    /// Have the cache as an option in order to not stop the CLI if there is a cache creation
    /// error (the image will simply be pulled in this case, instead of being fetched from cache)
    cache: Option<CacheManager>,
}

impl ImageManager for OciImageManager {
    fn image_name(&self) -> &String {
        &self.image_name
    }

    /// Pulls the image from remote and attempts to cache it locally.
    fn pull_image(&mut self) -> Result<()> {
        let image_name = self.image_name.clone();
        let act = async {
            // Attempt to pull and store the image in the local cache
            self.get_image_details(&image_name).await?;

            Ok(())
        };

        let runtime = Runtime::new().map_err(|_| EnclaveBuildError::RuntimeError)?;
        runtime.block_on(act)
    }

    fn build_image(&self, _: String) -> Result<()> {
        todo!();
    }

    /// Inspect the image and return its description as a JSON String.
    fn inspect_image(&mut self) -> Result<serde_json::Value> {
        let image_name = self.image_name.clone();
        let act = async {
            let image_details = self.get_image_details(&image_name).await?;

            // Serialize to a serde_json::Value
            serde_json::to_value(&image_details).map_err(EnclaveBuildError::SerdeError)
        };

        let runtime = Runtime::new().map_err(|_| EnclaveBuildError::RuntimeError)?;
        runtime.block_on(act)
    }

    /// Extracts the CMD and ENV expressions from the image and returns them each in a
    /// temporary file
    fn load(&mut self) -> Result<(NamedTempFile, NamedTempFile)> {
        let (cmd, env) = self.extract_image()?;

        let cmd_file = crate::docker::write_config(cmd)
            .map_err(|err| EnclaveBuildError::ExtractError(format!("{:?}", err)))?;
        let env_file = crate::docker::write_config(env)
            .map_err(|err| EnclaveBuildError::ExtractError(format!("{:?}", err)))?;

        Ok((cmd_file, env_file))
    }

    /// Returns architecture information of the image.
    fn architecture(&mut self) -> Result<String> {
        let image_name = self.image_name.clone();
        let act_get_image = async {
            let image = self.get_image_details(&image_name).await?;

            Ok(format!("{}", image.config.architecture()))
        };

        let runtime = Runtime::new().map_err(|_| EnclaveBuildError::RuntimeError)?;
        runtime.block_on(act_get_image)
    }

    /// The OCI image manager does not use the Docker daemon
    fn use_docker(&self) -> bool {
        false
    }
}

impl OciImageManager {
    /// When calling this constructor, it also tries to create / initialize the cache at
    /// the default path.\
    /// If this fails, the ImageManager is still created, but the 'cache'
    /// field is set to 'None'.
    pub fn new<S: AsRef<str>>(image_name: S) -> Self {
        // Add the default ":latest" tag if the image tag is missing
        let image_name = check_tag(&image_name);

        // The docker daemon is not used, so a local cache needs to be created
        // Get the default cache root path
        let root_path = match CacheManager::get_default_cache_root_path() {
            Ok(path) => path,
            Err(_) => {
                // If the cache root path could not be determined, then the cache can not be initialized
                return Self {
                    image_name,
                    cache: None,
                };
            }
        };

        // Try to create / read the cache
        let cache = match CacheManager::new(&root_path) {
            Ok(manager) => Some(manager),
            Err(err) => {
                // If the cache could not be created, log the error
                eprintln!("{:?}", err);
                None
            }
        };

        Self { image_name, cache }
    }

    /// Returns a struct containing image metadata.
    ///
    /// If the image is cached correctly, the function tries to fetch the image from the cache.
    ///
    /// If the image is not cached or a cache was not created (the 'cache' field is None),
    /// it pulls the image, caches it (if the 'cache' field is not None) and returns its metadata.
    ///
    /// If the pull succeeded but the caching failed, it returns the pulled image metadata.
    async fn get_image_details<S: AsRef<str>>(&mut self, image_name: S) -> Result<ImageDetails> {
        let image_name = check_tag(&image_name);

        let local_cache = (self.cache).as_mut();

        if let Some(cache) = local_cache {
            if cache.check_cached_image(&image_name).is_ok() {
                // Try to fetch the image from the cache
                let image_details = cache.fetch_image_details(&image_name).map_err(|err| {
                    // Log the fetching error
                    eprintln!("{:?}", err);
                    err
                });

                // If the fetching failed, pull it from remote
                if image_details.is_err() {
                    // Pull the image from remote
                    let image_data = crate::pull::pull_image_data(&image_name).await?;

                    // Get the image metadata from the pulled struct
                    let new_details = ImageDetails::from(&image_name, &image_data)?;

                    return Ok(new_details);
                }

                return image_details;
            }
        }

        self.fetch_and_store_image(image_name).await
    }

    /// Pulls image from remote registry and caches it if possible
    async fn fetch_and_store_image<S: AsRef<str>>(
        &mut self,
        image_name: S,
    ) -> Result<ImageDetails> {
        // The image is not cached, so try to pull and then cache it
        let image_data = crate::pull::pull_image_data(&image_name).await?;

        if let Some(local_cache) = self.cache.as_mut() {
            local_cache
                .store_image_data(&image_name, &image_data)
                .map_err(|err| eprintln!("Failed to store image to cache: {:?}", err))
                .ok();
        }

        // Get the image metadata from the pulled struct
        let image_details = ImageDetails::from(&image_name, &image_data)?;

        // Even if the caching failed, return the image details
        Ok(image_details)
    }

    /// Extracts from the image and returns the CMD and ENV expressions (in this order).
    ///
    /// If there are no CMD expressions found, it tries to locate the ENTRYPOINT command.
    fn extract_image(&mut self) -> Result<(Vec<String>, Vec<String>)> {
        let image_name = self.image_name.clone();
        // Try to get the image details
        let act_get_image = async { self.get_image_details(&image_name).await };
        let image = Runtime::new()
            .map_err(|_| EnclaveBuildError::RuntimeError)?
            .block_on(act_get_image)
            .map_err(|err| EnclaveBuildError::ExtractError(format!("{:?}", err)))?;

        // Get the expressions from the image
        let cmd = image
            .config
            .config()
            .as_ref()
            .ok_or(EnclaveBuildError::ConfigError)?
            .cmd();
        let env = image
            .config
            .config()
            .as_ref()
            .ok_or(EnclaveBuildError::ConfigError)?
            .env();
        let entrypoint = image
            .config
            .config()
            .as_ref()
            .ok_or(EnclaveBuildError::ConfigError)?
            .entrypoint();

        // If no CMD instructions are found, try to locate an ENTRYPOINT command
        match (cmd, env, entrypoint) {
            (Some(cmd), Some(env), _) => Ok((cmd.to_vec(), env.to_vec())),
            (_, Some(env), Some(entrypoint)) => Ok((entrypoint.to_vec(), env.to_vec())),
            (_, _, Some(entrypoint)) => Ok((entrypoint.to_vec(), Vec::<String>::new())),
            (_, _, _) => Err(EnclaveBuildError::ExtractError(
                "Failed to locate ENTRYPOINT".to_string(),
            )),
        }
    }
}

/// Adds the default ":latest" tag to an image if it is untagged
fn check_tag<S: AsRef<str>>(image_name: S) -> String {
    let name = image_name.as_ref().to_string();
    match name.contains(':') {
        true => name,
        false => format!("{}:latest", name),
    }
}
