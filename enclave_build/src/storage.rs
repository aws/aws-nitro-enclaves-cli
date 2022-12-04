// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Error, ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use oci_distribution::{
    client::ImageData,
    manifest::{
        ImageIndexEntry, OciDescriptor, OciImageIndex, OciImageManifest, OCI_IMAGE_MEDIA_TYPE,
    },
};
use serde_json::json;
use sha2::Digest;

use oci_spec::image::ImageConfiguration;

use crate::{
    image::{self, deserialize_from_reader, ImageDetails},
    EnclaveBuildError, Result,
};

/// Root folder for the image storage.
const STORAGE_ROOT_FOLDER: &str = "XDG_DATA_HOME";
/// Path to the blobs folder
const STORAGE_BLOBS_FOLDER: &str = "blobs/sha256/";
/// Name of the storage index file which stores the (image URI <-> image hash) mappings.
const STORAGE_INDEX_FILE_NAME: &str = "index.json";
/// The name of the OCI layout file from the storage.
const STORAGE_OCI_LAYOUT_FILE: &str = "oci-layout";

/// Constants used for complying with the OCI storage structure
const REF_ANNOTATION: &str = "org.opencontainers.image.ref.name";
const OCI_LAYOUT: (&str, &str) = ("imageLayoutVersion", "1.0.0");

/// Structure which provides operations with the local storage.
///
/// The index file is located in the storage root folder and keeps track of stored images.
///
/// The storage structure is:
///
/// {STORAGE_ROOT_PATH}/index.json\
/// {STORAGE_ROOT_PATH}/blobs/sha256\
/// {STORAGE_ROOT_PATH}/blobs/sha256/hash_of_blob_1\
/// {STORAGE_ROOT_PATH}/blobs/sha256/hash_of_blob_2\
/// etc.
///
/// A blob can be:
///
/// {IMAGE_FOLDER_PATH}/blobs/sha256/manifest_hash - the image manifest, stored as a JSON String.\
/// {IMAGE_FOLDER_PATH}/blobs/sha256/config_hash - the image configuration, stored as a JSON String.\
/// {IMAGE_FOLDER_PATH}/blobs/sha256/layer_hash - one of the image layers, each in a separate gzip compressed tar file.
pub struct OciStorage {
    /// The root folder of the storage
    root_path: PathBuf,

    /// The config of the OCI image used to build the EIF. This field is optional as we might
    /// not have stored an image and we have to pull it from a remote registry.
    config: Option<ImageConfiguration>,
}

impl OciStorage {
    pub fn new(root_path: &Path) -> Result<Self> {
        // Create all missing folders, if not already created
        fs::create_dir_all(root_path).map_err(EnclaveBuildError::OciStorageInit)?;

        Ok(Self {
            root_path: root_path.to_path_buf(),
            config: None,
        })
    }

    /// Stores the image data provided as argument in the storage at the folder pointed
    /// by the 'root_path' field.
    pub fn store_image_data(&mut self, image_name: &str, image_data: &ImageData) -> Result<()> {
        // Create the folder where the image data will be stored. Each image blob will be stored in
        // a file named by the SHA256 digest of the content.
        let blobs_path = self.root_path.join(STORAGE_BLOBS_FOLDER);
        fs::create_dir_all(&blobs_path).map_err(EnclaveBuildError::OciStorageStore)?;

        // Each layer file will be named after the layer's digest hash
        Self::store_layers(&blobs_path, image_data)?;

        let manifest = Self::store_manifest(&blobs_path, image_data)?;

        // Store the config and validate UTF8 bytes
        let config_content = Self::store_config(&blobs_path, image_data)?;

        // If index file present, read and append new image entry to the JSON list
        self.store_index(image_name, manifest)?;

        // Write oci_layout file from template constant
        self.store_layout()?;

        self.config = Some(deserialize_from_reader(config_content.as_bytes())?);

        Ok(())
    }

    fn default_oci_index() -> OciImageIndex {
        OciImageIndex {
            schema_version: 2,
            media_type: None,
            manifests: Vec::new(),
            annotations: None,
        }
    }

    fn store_layers(blobs_path: &Path, image_data: &ImageData) -> Result<()> {
        for layer in &image_data.layers {
            Self::write_blob(blobs_path, &layer.data)?;
        }

        Ok(())
    }

    fn store_manifest<'a>(
        blobs_path: &Path,
        image_data: &'a ImageData,
    ) -> Result<&'a OciImageManifest> {
        let manifest = image_data
            .manifest
            .as_ref()
            .ok_or(EnclaveBuildError::ManifestError)?;
        let manifest_bytes = serde_json::to_vec(manifest).map_err(EnclaveBuildError::SerdeError)?;

        Self::write_blob(blobs_path, &manifest_bytes)?;

        Ok(manifest)
    }

    fn store_config(blobs_path: &Path, image_data: &ImageData) -> Result<String> {
        let config_content = String::from_utf8(image_data.config.data.clone()).map_err(|_| {
            EnclaveBuildError::OciStorageStore(Error::new(
                ErrorKind::InvalidData,
                "Config data invalid",
            ))
        })?;

        Self::write_blob(blobs_path, config_content.as_bytes())?;

        Ok(config_content)
    }

    fn store_index(&self, image_name: &str, manifest: &OciImageManifest) -> Result<()> {
        let mut index_content: OciImageIndex = File::open(STORAGE_INDEX_FILE_NAME).map_or_else(
            |_| Ok(Self::default_oci_index()),
            |file| serde_json::from_reader(file).map_err(EnclaveBuildError::SerdeError),
        )?;
        let image_ref =
            Self::normalize_reference(&image::build_image_reference(image_name)?.whole());

        // Create manifest entry in the index file
        let manifest_bytes = serde_json::to_vec(manifest).map_err(EnclaveBuildError::SerdeError)?;
        let new_manifest = ImageIndexEntry {
            media_type: manifest
                .media_type
                .as_ref()
                .unwrap_or(&OCI_IMAGE_MEDIA_TYPE.to_string())
                .to_string(),
            digest: Self::blob_hash(&manifest_bytes),
            size: manifest_bytes.len() as i64,
            platform: None,
            annotations: Some(HashMap::from([(REF_ANNOTATION.to_string(), image_ref)])),
        };

        // If all image data was successfully stored, add the image to the index file
        index_content.manifests.push(new_manifest);
        let index_file = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.root_path.join(STORAGE_INDEX_FILE_NAME))
            .map_err(EnclaveBuildError::OciStorageStore)?;

        // Write index file content
        serde_json::to_writer(index_file, &index_content).map_err(EnclaveBuildError::SerdeError)?;

        Ok(())
    }

    fn store_layout(&self) -> Result<()> {
        let layout_content = json!(HashMap::from([OCI_LAYOUT]));

        let layout_file = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.root_path.join(STORAGE_OCI_LAYOUT_FILE))
            .map_err(EnclaveBuildError::OciStorageStore)?;

        serde_json::to_writer(layout_file, &layout_content)
            .map_err(EnclaveBuildError::SerdeError)?;

        Ok(())
    }

    fn write_blob(blobs_path: &Path, bytes: &[u8]) -> Result<()> {
        let digest = format!("{:x}", sha2::Sha256::digest(bytes));

        File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(blobs_path.join(digest))
            .map_err(EnclaveBuildError::OciStorageStore)?
            .write_all(bytes)
            .map_err(EnclaveBuildError::OciStorageStore)?;
        Ok(())
    }

    /// Determines if an image is stored correctly
    fn check_stored_image(&self, image_name: &str) -> Result<ImageConfiguration> {
        // Check that the index file exists
        let index: OciImageIndex = Self::fetch_index(&self.root_path)?;

        // First validate the manifest
        // Since the struct pulled by the oci_distribution API does not contain the manifest digest,
        // and another HTTP request should be made to get the digest, just check that the manifest file
        // exists and has the right structure for the next validations
        let manifest = self
            .fetch_manifest_from_index(image_name, index)
            .map_err(|_| EnclaveBuildError::ManifestError)?;

        // The manifest is checked, so now validate the layers from the manifest
        self.validate_layers(&manifest)?;

        // Extract the config digest from the manifest
        let config_digest = manifest
            .config
            .digest
            .strip_prefix("sha256:")
            .ok_or(EnclaveBuildError::ConfigError)?;

        // Finally, check that the config is correctly stored
        // This is done by applying a hash function on the config file contents and comparing the
        // result with the config digest from the manifest
        let config_string = Self::fetch_config(&self.root_path, config_digest)?;

        // Compare the two digests
        if config_digest != format!("{:x}", sha2::Sha256::digest(config_string.as_bytes())) {
            return Err(EnclaveBuildError::OciStorageMalformed(
                "Config content digest and digest from manifest do not match".to_string(),
            ));
        }

        deserialize_from_reader(config_string.as_bytes())
    }

    /// Validates that the image layers are stored correctly by checking them with the layer
    /// descriptors from the image manifest.
    fn validate_layers(&self, manifest_obj: &OciImageManifest) -> Result<()> {
        let layers_path = self.root_path.join(STORAGE_BLOBS_FOLDER);

        // Get the stored blobs as a HashMap mapping a layer digest to the corresponding layer file
        let mut blobs = HashMap::new();

        fs::read_dir(layers_path)
            .map_err(|err| {
                EnclaveBuildError::OciStorageNotFound(format!(
                    "Failed to get image layers: {:?}",
                    err
                ))
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
            // The blobs hashmap will contain all layer files found in the storage for the current image
            // (along with config blobs as well which will be ignored)
            .for_each(|(name, file)| {
                if let Ok(file_name) = name.into_string() {
                    blobs.insert(file_name, file);
                }
            });

        // Iterate through each layer found in the image manifest and validate that it is
        // stored by checking the digest
        manifest_obj
            .layers
            .iter()
            .try_for_each(|layer| Self::check_layer(layer, &blobs))?;

        Ok(())
    }

    /// Validate particular layer manifest entry against stored blob files
    fn check_layer(layer: &OciDescriptor, blobs: &HashMap<String, File>) -> Result<()> {
        // Get the stored layer file matching the digest
        // If not present, then a layer file is missing, so return Error
        let layer_ref = layer.digest.strip_prefix("sha256:").ok_or_else(|| {
            EnclaveBuildError::OciStorageMalformed("Layer digest incorrect.".to_string())
        })?;
        let mut layer_file = blobs.get(layer_ref).ok_or_else(|| {
            EnclaveBuildError::OciStorageNotFound("Layer missing from storage.".to_string())
        })?;
        let mut layer_string = String::new();
        layer_file.read_to_string(&mut layer_string).map_err(|_| {
            EnclaveBuildError::OciStorageNotFound("Failed to read layer".to_string())
        })?;

        let calc_digest = Self::blob_hash(layer_string.as_bytes());

        // Check that the digests match
        if calc_digest != layer.digest {
            return Err(EnclaveBuildError::OciStorageMalformed(
                "Layer not valid".to_string(),
            ));
        }

        Ok(())
    }

    /// Returns the manifest JSON string from the storage
    fn fetch_manifest_from_index(
        &self,
        image_name: &str,
        index: OciImageIndex,
    ) -> Result<OciImageManifest> {
        let img_ref = Self::normalize_reference(&image::build_image_reference(image_name)?.whole());
        let manifest_entry = index
            .manifests
            .iter()
            .find(|entry| match &entry.annotations {
                Some(annotations) => annotations
                    .get(REF_ANNOTATION)
                    .map_or_else(|| false, |value| img_ref == *value),
                None => false,
            })
            .ok_or(EnclaveBuildError::ManifestError)?;

        Self::fetch_manifest(&self.root_path, &manifest_entry.digest)
    }

    /// Fetch index file from the storage root path
    fn fetch_index(root_path: &Path) -> Result<OciImageIndex> {
        match File::open(root_path.join(STORAGE_INDEX_FILE_NAME)) {
            Ok(file) => serde_json::from_reader(file).map_err(EnclaveBuildError::SerdeError),
            Err(err) => Err(EnclaveBuildError::OciStorageNotFound(format!(
                "Index file missing: {:?}",
                err
            ))),
        }
    }

    /// Returns manifest from blob, given the digest
    fn fetch_manifest(root_path: &Path, manifest_hash: &str) -> Result<OciImageManifest> {
        let digest = manifest_hash
            .strip_prefix("sha256:")
            .ok_or(EnclaveBuildError::ManifestError)?;
        let target_path = root_path.join(STORAGE_BLOBS_FOLDER);

        // Read the JSON string from the stored manifest file
        let manifest_path = target_path.join(digest);
        let file = File::open(manifest_path).map_err(|_| EnclaveBuildError::ManifestError)?;
        let manifest: OciImageManifest =
            serde_json::from_reader(file).map_err(EnclaveBuildError::SerdeError)?;

        Ok(manifest)
    }

    /// Returns the config JSON string from the storage
    fn fetch_config(root_path: &Path, config_digest: &str) -> Result<String> {
        let target_path = root_path.join(STORAGE_BLOBS_FOLDER);

        let mut config_json = String::new();
        File::open(target_path.join(config_digest))
            .map_err(|_| EnclaveBuildError::ConfigError)?
            .read_to_string(&mut config_json)
            .map_err(|_| EnclaveBuildError::ConfigError)?;

        if config_json.is_empty() {
            return Err(EnclaveBuildError::ConfigError);
        }

        Ok(config_json)
    }

    /// Add `docker.io` to references that are missing this registry. `Linuxkit` will search
    /// for images in the index file by automatically appending `docker.io` to their reference.
    /// To prevent `linuxkit` from pulling the image again (with a reference that doesn't exist),
    /// we want to save them the same way they will be searched.
    fn normalize_reference(reference: &str) -> String {
        let docker_prefix = "docker.io/";
        if reference.starts_with(docker_prefix) {
            return reference.to_string();
        }

        docker_prefix.to_owned() + reference
    }

    /// Format image blobs' hashes as represented in the storage files
    fn blob_hash(bytes: &[u8]) -> String {
        format!("sha256:{:x}", sha2::Sha256::digest(bytes))
    }

    /// Fetches the image metadata from storage as an ImageDetails struct.
    ///
    /// If the data is not correctly stored or a file is missing, it returns an error.
    ///
    /// If the image is not stored, it does not attempt to pull the image from remote.
    pub fn fetch_image_details(&mut self, image_name: &str) -> Result<ImageDetails> {
        let image_config = self
            .config
            .as_ref()
            .map(Ok)
            .unwrap_or_else(|| Err(self.check_stored_image(image_name)))
            .map_err(|err| EnclaveBuildError::OciStorageMalformed(format!("{:?}", err)))?;

        // Add algorithm prefix to the hash
        let image_hash = Self::blob_hash(
            &serde_json::to_vec(&self.config).map_err(EnclaveBuildError::SerdeError)?,
        );

        Ok(ImageDetails::new(
            image::build_image_reference(image_name)?.whole(),
            image_hash,
            image_config.clone(),
        ))
    }

    /// Returns the default root folder path of the local storage.
    ///
    /// The default storage path is {XDG_DATA_HOME}/.aws-nitro-enclaves-cli/container_storage, and if the env
    /// variable is not set, {HOME}/.local/share/.aws-nitro-enclaves-cli/container_storage is used.
    pub fn get_default_root_path() -> Result<PathBuf> {
        // Try to use XDG_DATA_HOME as default root
        let root = match std::env::var_os(STORAGE_ROOT_FOLDER) {
            Some(val) => val
                .into_string()
                .map_err(|_| EnclaveBuildError::PathError("storage root folder".to_string()))?,
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
        path.push(".aws-nitro-enclaves-cli/container_storage");

        Ok(path)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::image::build_image_reference;

    use super::*;
    use std::collections::HashMap;

    use oci_distribution::manifest::OciImageManifest;
    use vmm_sys_util::tempdir::TempDir;

    /// This function stores the test image in a temporary directory and returns that directory and
    /// the storage manager initialized with it as root path.
    fn setup_temp_storage() -> (TempDir, OciStorage) {
        // Use a temporary dir as the storage root path
        // Create temporary random path so tests running in parallel won't overlap
        let root_dir = TempDir::new().unwrap();

        fs::create_dir_all(&root_dir.as_path()).unwrap();

        // Use a mock ImageData struct
        let image_data = image::tests::build_image_data();

        // Initialize the storage structure
        let mut storage =
            OciStorage::new(&root_dir.as_path()).expect("failed to create the OciStorage");

        // Store the mock image data in the temp storage
        storage
            .store_image_data(image::tests::TEST_IMAGE_NAME, &image_data)
            .expect("failed to store test image to storage");

        (root_dir, storage)
    }

    #[test]
    fn test_image_is_valid() {
        let (_root_path, storage) = setup_temp_storage();

        assert!(storage
            .check_stored_image(image::tests::TEST_IMAGE_NAME)
            .is_ok())
    }

    #[test]
    fn test_image_is_not_valid() {
        let (root_dir, storage) = setup_temp_storage();
        let root_path = root_dir.as_path();

        // Delete the index file so that check_stored_image() returns error
        let index_file_path = root_path.join(STORAGE_INDEX_FILE_NAME);
        fs::remove_file(&index_file_path).expect("could not remove the storage index file");

        assert!(storage
            .check_stored_image(image::tests::TEST_IMAGE_NAME)
            .is_err())
    }

    #[test]
    fn test_validate_layers() {
        let (root_dir, storage) = setup_temp_storage();
        let root_path = root_dir.as_path();

        // Digest of the layer to be deleted
        let delete_layer_digest =
            "1aed4d8555515c961bffea900d5e7f1c1e4abf0f6da250d8bf15843106e0533b";

        let layer_path = root_path
            .join(STORAGE_BLOBS_FOLDER)
            .join(delete_layer_digest);
        fs::remove_file(&layer_path).expect("could not remove the layer file");

        let res = storage.check_stored_image(image::tests::TEST_IMAGE_NAME);

        assert!(res.is_err());
    }

    #[test]
    fn test_fetch_manifest_from_index() {
        let (_root_path, storage) = setup_temp_storage();

        let index: OciImageIndex = OciStorage::fetch_index(&storage.root_path).unwrap();
        let manifest = storage
            .fetch_manifest_from_index(image::tests::TEST_IMAGE_NAME, index)
            .unwrap();

        let expected_manifest: serde_json::Value =
            serde_json::from_str(image::tests::TEST_MANIFEST).unwrap();

        assert_eq!(json!(manifest), expected_manifest);
    }

    #[test]
    fn test_fetch_index() {
        let (root_dir, _storage) = setup_temp_storage();
        let root_path = root_dir.as_path();

        let index = OciStorage::fetch_index(&root_path).expect("Failed to fetch index.json");
        let index = json!(index);

        let manifest: OciImageManifest = serde_json::from_str(image::tests::TEST_MANIFEST).unwrap();
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_entry = ImageIndexEntry {
            media_type: manifest
                .media_type
                .as_ref()
                .unwrap_or(&OCI_IMAGE_MEDIA_TYPE.to_string())
                .to_string(),
            size: manifest_bytes.len() as i64,
            digest: OciStorage::blob_hash(&manifest_bytes),
            platform: None,
            annotations: Some(HashMap::from([(
                REF_ANNOTATION.to_string(),
                OciStorage::normalize_reference(
                    &image::build_image_reference(image::tests::TEST_IMAGE_NAME)
                        .unwrap()
                        .whole(),
                ),
            )])),
        };

        let expected_index = OciImageIndex {
            schema_version: 2,
            media_type: None,
            manifests: vec![manifest_entry],
            annotations: None,
        };
        let expected_index = json!(expected_index);

        assert_eq!(index, expected_index);
    }

    #[test]
    fn test_fetch_manifest() {
        let (root_dir, _storage) = setup_temp_storage();
        let root_path = root_dir.as_path();

        let manifest_digest = OciStorage::blob_hash(
            &image::tests::TEST_MANIFEST
                .to_string()
                .replace("\n", "")
                .replace(" ", "")
                .as_bytes(),
        );

        let manifest = OciStorage::fetch_manifest(&root_path, &manifest_digest)
            .expect("failed to fetch image manifest from storage");
        let manifest = json!(manifest);

        let val: serde_json::Value = serde_json::from_str(image::tests::TEST_MANIFEST).unwrap();

        assert_eq!(manifest, val);
    }

    #[test]
    fn test_fetch_config() {
        let (root_dir, _storage) = setup_temp_storage();
        let root_path = root_dir.as_path();

        let config = OciStorage::fetch_config(&root_path, image::tests::TEST_IMAGE_HASH)
            .expect("failed to fetch image config from storage");

        let expected_config = image::tests::TEST_CONFIG.to_string();

        assert_eq!(config, expected_config);
    }

    #[test]
    fn test_fetch_image_details() {
        let (_root_path, mut storage) = setup_temp_storage();

        let image_details = storage
            .fetch_image_details(image::tests::TEST_IMAGE_NAME)
            .expect("failed to get image hash from storage");

        let expected_config: ImageConfiguration =
            deserialize_from_reader(image::tests::TEST_CONFIG.as_bytes()).unwrap();
        let expected_hash = OciStorage::blob_hash(&expected_config.to_string().unwrap().as_bytes());
        let expected_details = ImageDetails::new(
            build_image_reference(image::tests::TEST_IMAGE_NAME)
                .unwrap()
                .whole(),
            expected_hash,
            expected_config,
        );

        assert_eq!(image_details, expected_details);
    }

    #[test]
    fn test_fetch_image_details_empty_storage() {
        // Initialize storage without storing any image (`storage` field should be `None`)
        let root_dir = TempDir::new().unwrap();
        fs::create_dir_all(&root_dir.as_path()).unwrap();
        let mut storage =
            OciStorage::new(&root_dir.as_path()).expect("failed to create the OciStorage");

        assert!(storage
            .fetch_image_details(image::tests::TEST_IMAGE_NAME)
            .is_err());
    }

    #[test]
    fn test_get_default_root_path() {
        let default_path = match std::env::var_os("XDG_DATA_HOME") {
            Some(val) => PathBuf::from(val.to_str().unwrap().to_string())
                .join(".aws-nitro-enclaves-cli/container_storage"),
            None => {
                let home = std::env::var_os("HOME").expect("HOME env not set");
                let append = format!(
                    "{}/.local/share/.aws-nitro-enclaves-cli/container_storage",
                    home.to_str().unwrap().to_string()
                );
                PathBuf::from(home).join(append)
            }
        };
        let calc_path =
            OciStorage::get_default_root_path().expect("failed to determine default storage path");

        assert_eq!(default_path, calc_path);
    }
}
