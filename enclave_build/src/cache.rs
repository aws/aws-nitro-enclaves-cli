// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// S&PDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Error, ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use sha2::Digest;

use crate::{
    image::{self, ImageDetails},
    EnclaveBuildError, Result,
};

use oci_distribution::client::ImageData;

/// Root folder for the cache.
pub const CACHE_ROOT_FOLDER: &str = "XDG_DATA_HOME";
/// Name of the cache index file which stores the (image URI <-> image hash) mappings.
pub const CACHE_INDEX_FILE_NAME: &str = "index.json";
/// The name of the folder used by the cache to store the image layers.
pub const CACHE_LAYERS_FOLDER_NAME: &str = "layers";
/// The name of the image config file from the cache.
pub const CACHE_CONFIG_FILE_NAME: &str = "config.json";
/// The name of the image manifest file from the cache.
pub const CACHE_MANIFEST_FILE_NAME: &str = "manifest.json";

/// Struct which provides operations with the local cache.
///
/// The index.json file is located in the cache root folder and keeps track of images stored in cache.
///
/// The cache structure is:
///
/// {CACHE_ROOT_PATH}/index.json\
/// {CACHE_ROOT_PATH}/image_cache_folder1\
/// {CACHE_ROOT_PATH}/image_cache_folder2\
/// etc.
///
/// An image cache folder contains:
///
/// {IMAGE_FOLDER_PATH}/config.json - the image configuration, stored as a JSON String.\
/// {IMAGE_FOLDER_PATH}/manifest.json - the image manifest, stored as a JSON String.\
/// {IMAGE_FOLDER_PATH}/layers - folder containing all layers, each in a separate gzip compressed tar file.
#[derive(Clone)]
pub struct CacheManager {
    /// The root folder of the cache
    root_path: PathBuf,

    /// A map storing the cached images, with the map entry format being (image_reference, image_hash)
    cached_images: HashMap<String, String>,
}

impl CacheManager {
    /// Creates a new CacheManager instance and returns it. As argument, a path to the root folder
    /// of the cache should be provided.
    ///
    /// Apart from that, the function also creates (if not already created) all folders from the path
    /// specified as argument.
    ///
    /// If an index.json file exists at the path, it loads the file's contents into the 'cached_images'
    /// field. If not, a new empty index.json file is created at that path.
    pub fn new<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        // Create all missing folders, if not already created
        fs::create_dir_all(&root_path).map_err(EnclaveBuildError::CacheInitError)?;

        let mut contents = String::new();

        // Try to open the index.json file and read the contents.
        // If the file is missing, create it.
        OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(root_path.as_ref().to_path_buf().join(CACHE_INDEX_FILE_NAME))
            .map_err(EnclaveBuildError::CacheInitError)?
            .read_to_string(&mut contents)
            .map_err(EnclaveBuildError::CacheInitError)?;

        // If the index.json file is empty, return an empty hashmap
        if contents.is_empty() {
            return Ok(Self {
                root_path: root_path.as_ref().to_path_buf(),
                cached_images: HashMap::new(),
            });
        }

        // Try to deserialize the JSON string into a HashMap
        let cached_images: HashMap<String, String> =
            serde_json::from_str(&contents).map_err(EnclaveBuildError::SerdeError)?;

        Ok(Self {
            root_path: root_path.as_ref().to_path_buf(),
            cached_images,
        })
    }

    /// Stores the image data provided as argument in the cache at the folder pointed
    /// by the 'root_path' field.
    pub fn store_image_data<S: AsRef<str>>(
        &mut self,
        image_name: S,
        image_data: &ImageData,
    ) -> Result<()> {
        let image_hash = image::image_hash(image_data.config.data.as_slice()).map_err(|err| {
            EnclaveBuildError::HashingError(format!("Config hashing failed: {:?}", err))
        })?;

        // Create the folder where the image data will be stored
        let target_path = self.root_path.join(&image_hash);
        fs::create_dir_all(&target_path).map_err(EnclaveBuildError::CacheStoreError)?;

        // Create the 'layers' folder and store the layers in it
        let layers_path = target_path.join(CACHE_LAYERS_FOLDER_NAME);
        fs::create_dir_all(&layers_path).map_err(EnclaveBuildError::CacheStoreError)?;

        for layer in &image_data.layers {
            // Each layer file will be named after the layer's digest hash
            let layer_file_path =
                layers_path.join(format!("{:x}", sha2::Sha256::digest(&layer.data)));
            File::create(&layer_file_path)
                .map_err(EnclaveBuildError::CacheStoreError)?
                .write_all(&layer.data)
                .map_err(EnclaveBuildError::CacheStoreError)?;
        }

        // Store the manifest
        let manifest_json = match &image_data.manifest {
            Some(image_manifest) => {
                serde_json::to_string(&image_manifest).map_err(EnclaveBuildError::SerdeError)
            }
            None => Err(EnclaveBuildError::ManifestError),
        }?;

        File::create(&target_path.join(CACHE_MANIFEST_FILE_NAME))
            .map_err(EnclaveBuildError::CacheStoreError)?
            .write_all(manifest_json.as_bytes())
            .map_err(EnclaveBuildError::CacheStoreError)?;

        // Store the config
        let config_json = String::from_utf8(image_data.config.data.clone()).map_err(|_| {
            EnclaveBuildError::CacheStoreError(Error::new(
                ErrorKind::InvalidData,
                "Config data invalid",
            ))
        })?;

        File::create(&target_path.join(CACHE_CONFIG_FILE_NAME))
            .map_err(EnclaveBuildError::CacheStoreError)?
            .write_all(config_json.as_bytes())
            .map_err(EnclaveBuildError::CacheStoreError)?;

        // If all image data was successfully stored, add the image to the index.json file and
        // the hashmap
        let image_ref = image::build_image_reference(image_name)?;
        self.cached_images.insert(image_ref.whole(), image_hash);

        let index_file = File::options()
            .write(true)
            .open(self.root_path.join(CACHE_INDEX_FILE_NAME))
            .map_err(EnclaveBuildError::CacheStoreError)?;

        // Write the hashmap (the image URI <-> image hash mappings) to the index.json file
        serde_json::to_writer(index_file, &self.cached_images)
            .map_err(EnclaveBuildError::SerdeError)?;

        Ok(())
    }

    /// Determines if an image is stored correctly in the cache represented by the current CacheManager object.
    pub fn check_cached_image<S: AsRef<str>>(&self, image_name: S) -> Result<()> {
        // Check that the index.json file exists
        let index_file_path = self.root_path.join(CACHE_INDEX_FILE_NAME);
        fs::metadata(&index_file_path).map_err(|err| {
            EnclaveBuildError::CacheMissError(format!("Cache index file missing: {:?}", err))
        })?;

        // If the image is not in the index.json file, then it is definitely not cached
        let image_hash = self.get_image_hash_from_name(&image_name).ok_or_else(|| {
            EnclaveBuildError::CacheMissError(
                "Image hash missing from index.json file.".to_string(),
            )
        })?;

        // The image is theoretically cached, but check the manifest, config and layers to validate
        // that the image data is stored correctly
        let image_folder_path = self.root_path.join(&image_hash);

        // First validate the manifest
        // Since the struct pulled by the oci_distribution API does not contain the manifest digest,
        // and another HTTP request should be made to get the digest, just check that the manifest file
        // exists and is not empty
        let manifest_str = self
            .fetch_manifest(&image_name)
            .map_err(|_| EnclaveBuildError::ManifestError)?;

        // The manifest is checked, so now validate the layers
        self.validate_layers(
            &image_folder_path.join(CACHE_LAYERS_FOLDER_NAME),
            &manifest_str,
        )?;

        // Finally, check that the config is correctly cached
        // This is done by applying a hash function on the config file contents and comparing the
        // result with the config digest from the manifest
        let config_str = self.fetch_config(&image_name)?;

        let manifest_obj: serde_json::Value =
            serde_json::from_str(manifest_str.as_str()).map_err(|_| {
                EnclaveBuildError::CacheMissError("Could not parse manifest JSON.".to_string())
            })?;

        // Extract the config digest hash from the manifest
        let config_digest = manifest_obj
            .get("config")
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "'config' field missing from image manifest.".to_string(),
                )
            })?
            .get("digest")
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "'digest' field missing from image manifest.".to_string(),
                )
            })?
            .as_str()
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "Failed to get config digest from image manifest.".to_string(),
                )
            })?
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "Failed to get config digest from image manifest.".to_string(),
                )
            })?
            .to_string();
        // Compare the two digests
        if config_digest != format!("{:x}", sha2::Sha256::digest(config_str.as_bytes())) {
            return Err(EnclaveBuildError::CacheMissError(
                "Config content digest and manifest digest do not match".to_string(),
            ));
        }

        Ok(())
    }

    /// Fetches the image metadata from cache as an ImageDetails struct.
    ///
    /// If the data is not correctly cached or a file is missing, it returns an error.
    ///
    /// If the image is not cached, it does not attempt to pull the image from remote.
    pub fn fetch_image_details<S: AsRef<str>>(&self, image_name: S) -> Result<ImageDetails> {
        let hash = self
            .get_image_hash_from_name(&image_name)
            .ok_or_else(|| EnclaveBuildError::CacheMissError("Image hash missing".to_string()))?;

        // Add algorithm prefix to the hash
        let image_hash = format!("sha256:{}", hash);

        let config_json = self.fetch_config(&image_name)?;

        Ok(ImageDetails::new(
            image::build_image_reference(&image_name)?.whole(),
            image_hash,
            image::deserialize_from_reader(config_json.as_bytes())?,
        ))
    }

    /// Returns the manifest JSON string from the cache.
    pub fn fetch_manifest<S: AsRef<str>>(&self, image_name: S) -> Result<String> {
        let target_path = self.get_image_folder_path(&image_name)?;

        // Read the JSON string from the cached manifest file
        let manifest_path = target_path.join(CACHE_MANIFEST_FILE_NAME);
        let mut manifest_json = String::new();
        File::open(&manifest_path)
            .map_err(|_| EnclaveBuildError::ManifestError)?
            .read_to_string(&mut manifest_json)
            .map_err(|_| EnclaveBuildError::ManifestError)?;

        if manifest_json.is_empty() {
            return Err(EnclaveBuildError::ManifestError);
        }

        Ok(manifest_json)
    }

    /// Returns the config JSON string from the cache.
    pub fn fetch_config<S: AsRef<str>>(&self, image_name: S) -> Result<String> {
        let target_path = self.get_image_folder_path(&image_name)?;

        let mut config_json = String::new();
        File::open(target_path.join(CACHE_CONFIG_FILE_NAME))
            .map_err(|_| EnclaveBuildError::ConfigError)?
            .read_to_string(&mut config_json)
            .map_err(|_| EnclaveBuildError::ConfigError)?;

        if config_json.is_empty() {
            return Err(EnclaveBuildError::ConfigError);
        }

        Ok(config_json)
    }

    /// Validates that the image layers are cached correctly by checking them with the layer descriptors
    /// from the image manifest.
    fn validate_layers<P: AsRef<Path>>(&self, layers_path: P, manifest_str: &str) -> Result<()> {
        let manifest_obj: serde_json::Value = serde_json::from_str(manifest_str).map_err(|_| {
            EnclaveBuildError::CacheMissError("Manifest serialization failed".to_string())
        })?;

        // Try to get the layer list from the manifest JSON
        let layers_vec = manifest_obj
            .get("layers")
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "'layers' field missing from manifest JSON.".to_string(),
                )
            })?
            .as_array()
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError("Manifest deserialize error.".to_string())
            })?
            .to_vec();

        // Get the cached layers as a HashMap mapping a layer digest to the corresponding layer file
        let mut cached_layers = HashMap::new();

        fs::read_dir(layers_path)
            .map_err(|err| {
                EnclaveBuildError::CacheMissError(format!("Failed to get image layers: {:?}", err))
            })?
            .into_iter()
            // Get only the valid directory entries that are valid files and return (name, file) pair
            .filter_map(|entry| match entry {
                Ok(dir_entry) => match File::open(dir_entry.path()) {
                    Ok(file) => Some((dir_entry.file_name(), file)),
                    Err(_) => None,
                },
                Err(_) => None,
            })
            // Map a layer digest to the layer file
            // The 'cached_layers' hashmap will contain all layer files found in the cache for the current image
            .for_each(|(name, file)| {
                if let Ok(file_name) = name.into_string() {
                    cached_layers.insert(file_name, file);
                }
            });

        // Iterate through each layer found in the image manifest and validate that it is stored in
        // the cache by checking the digest
        for layer_obj in layers_vec {
            // Read the layer digest from the manifest
            let layer_digest: String = layer_obj
                .get("digest")
                .ok_or_else(|| {
                    EnclaveBuildError::CacheMissError(
                        "Image layer digest not found in manifest".to_string(),
                    )
                })?
                .as_str()
                .ok_or_else(|| {
                    EnclaveBuildError::CacheMissError("Layer info extract error".to_string())
                })?
                .strip_prefix("sha256:")
                .ok_or_else(|| {
                    EnclaveBuildError::CacheMissError("Layer info extract error".to_string())
                })?
                .to_string();

            // Get the cached layer file matching the digest
            // If not present, then a layer file is missing, so return Error
            let mut layer_file = cached_layers.get(&layer_digest).ok_or_else(|| {
                EnclaveBuildError::CacheMissError("Layer missing from cache.".to_string())
            })?;
            let mut layer_bytes = Vec::new();
            layer_file.read_to_end(&mut layer_bytes).map_err(|_| {
                EnclaveBuildError::CacheMissError("Failed to read layer".to_string())
            })?;

            let calc_digest = format!("{:x}", sha2::Sha256::digest(layer_bytes.as_slice()));

            // Check that the digests match
            if calc_digest != layer_digest {
                return Err(EnclaveBuildError::CacheMissError(
                    "Layer not valid".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Returns the default root folder path of the cache.
    ///
    /// The default cache path is {XDG_DATA_HOME}/.aws-nitro-enclaves-cli/container_cache, and if the env
    /// variable is not set, {HOME}/.local/share/.aws-nitro-enclaves-cli/container_cache is used.
    pub fn get_default_cache_root_path() -> Result<PathBuf> {
        // Try to use XDG_DATA_HOME as default root
        let root = match std::env::var_os(CACHE_ROOT_FOLDER) {
            Some(val) => val
                .into_string()
                .map_err(|_| EnclaveBuildError::PathError("cache root folder".to_string()))?,
            // If XDG_DATA_HOME is not set, use {HOME}/.local/share as specified in
            // https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
            None => {
                let home_folder = std::env::var_os("HOME").ok_or_else(|| {
                    EnclaveBuildError::PathError(
                        "HOME environment variable is not set.".to_string(),
                    )
                })?;
                format!(
                    "{}/.local/share/",
                    home_folder
                        .into_string()
                        .map_err(|err| EnclaveBuildError::PathError(format!("{:?}", err)))?
                )
            }
        };

        let mut path = PathBuf::from(root);
        // Add the additional path to the root
        path.push(".aws-nitro-enclaves-cli/container_cache");

        Ok(path)
    }

    /// Returns the image hash (if available in the CacheManager's hashmap) taking the image
    /// name as parameter.
    fn get_image_hash_from_name<S: AsRef<str>>(&self, name: S) -> Option<String> {
        match image::build_image_reference(&name) {
            Ok(image_ref) => self
                .cached_images
                .get(&image_ref.whole())
                .map(|val| val.to_string()),
            Err(_) => None,
        }
    }

    /// Returns the path to an image folder in the cache.
    ///
    /// This is achieved by looking up in the hashmap by the image reference in order
    /// to find the image hash.
    fn get_image_folder_path<S: AsRef<str>>(&self, image_name: S) -> Result<PathBuf> {
        let image_hash = self
            .get_image_hash_from_name(&image_name)
            .ok_or_else(|| EnclaveBuildError::HashingError("Image hash missing".to_string()))?;

        Ok(self.root_path.join(image_hash))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    use oci_distribution::{
        client::{Config, ImageLayer},
        manifest::OciImageManifest,
    };

    /// Name of the custom image to be used for testing the cache.
    /// This image will not be pulled from remote.
    const TEST_IMAGE_NAME: &str = "hello-world";

    /// The manifest.json of the image used for testing.
    const TEST_MANIFEST: &str = r#"
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
    const TEST_IMAGE_HASH: &str =
        "9f5747c1f734cb78bf90123f791324f2a75c75863f1b94a91051702aa87e9511";

    // Simple layers used for testing
    const TEST_LAYER_1: &str = "Hello World 1";
    const TEST_LAYER_2: &str = "Hello World 2";

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

    /// This function caches the test image in a temporary directory and returns that directory and
    /// the cache manager initalized with it as root path.
    fn setup_temp_cache() -> (TempDir, CacheManager) {
        // Use a temporary dir as the cache root path.
        let root_dir = tempdir().unwrap();

        // Use a mock ImageData struct
        let image_data = build_image_data();

        // Initialize the cache manager
        let mut cache_manager =
            CacheManager::new(&root_dir).expect("failed to create the  CacheManager");

        // Store the mock image data in the temp cache
        cache_manager
            .store_image_data(TEST_IMAGE_NAME.to_string(), &image_data)
            .expect("failed to store test image to cache");

        (root_dir, cache_manager)
    }

    #[test]
    fn test_image_is_cached() {
        let (_cache_root_path, cache_manager) = setup_temp_cache();

        let res = cache_manager.check_cached_image(TEST_IMAGE_NAME.to_string());

        assert!(res.is_ok());
    }

    #[test]
    fn test_image_is_not_cached() {
        let (cache_root_path, cache_manager) = setup_temp_cache();

        // Delete the index file so that check_cached_image() returns error
        let index_file_path = cache_root_path.path().join(CACHE_INDEX_FILE_NAME);
        fs::remove_file(&index_file_path).expect("could not remove the cache index file");

        let res = cache_manager.check_cached_image(TEST_IMAGE_NAME);

        assert!(res.is_err());
    }

    #[test]
    fn test_validate_layers() {
        let (cache_root_path, cache_manager) = setup_temp_cache();

        // Digest of the layer to be deleted
        let delete_layer_digest =
            "1aed4d8555515c961bffea900d5e7f1c1e4abf0f6da250d8bf15843106e0533b";

        let layer_path = cache_root_path
            .path()
            .to_path_buf()
            .join(TEST_IMAGE_HASH)
            .join(CACHE_LAYERS_FOLDER_NAME)
            .join(delete_layer_digest);
        fs::remove_file(&layer_path).expect("could not remove the layer file");

        let res = cache_manager.check_cached_image(TEST_IMAGE_NAME);

        assert!(res.is_err());
    }

    #[test]
    fn test_fetch_manifest() {
        let (_cache_root_path, cache_manager) = setup_temp_cache();

        let cached_manifest = cache_manager
            .fetch_manifest(TEST_IMAGE_NAME)
            .expect("failed to fetch image manifest from cache");

        let val1: serde_json::Value = serde_json::from_str(cached_manifest.as_str()).unwrap();
        let val2: serde_json::Value = serde_json::from_str(TEST_MANIFEST).unwrap();

        assert_eq!(val1, val2);
    }

    #[test]
    fn test_fetch_config() {
        let (_cache_root_path, cache_manager) = setup_temp_cache();

        let cached_config = cache_manager
            .fetch_config(TEST_IMAGE_NAME)
            .expect("failed to fetch image config from cache");

        let val1: serde_json::Value = serde_json::from_str(cached_config.as_str()).unwrap();
        let val2: serde_json::Value = serde_json::from_str(TEST_CONFIG).unwrap();

        assert_eq!(val1, val2);
    }

    #[test]
    fn test_get_image_hash_from_name() {
        let (_cache_root_path, cache_manager) = setup_temp_cache();

        let image_hash = cache_manager
            .get_image_hash_from_name(TEST_IMAGE_NAME)
            .ok_or("")
            .expect("failed to get image hash from cache");

        assert_eq!(image_hash, TEST_IMAGE_HASH.to_string());
    }

    #[test]
    fn test_get_default_cache_root_path() {
        let default_path = match std::env::var_os("XDG_DATA_HOME") {
            Some(val) => PathBuf::from(val.to_str().unwrap().to_string())
                .join(".aws-nitro-enclaves-cli/container_cache"),
            None => {
                let home = std::env::var_os("HOME").expect("HOME env not set");
                let append = format!(
                    "{}/.local/share/.aws-nitro-enclaves-cli/container_cache",
                    home.to_str().unwrap().to_string()
                );
                PathBuf::from(home).join(append)
            }
        };
        let calc_path = CacheManager::get_default_cache_root_path()
            .expect("failed to determine default cache path");

        assert_eq!(default_path, calc_path);
    }
}
