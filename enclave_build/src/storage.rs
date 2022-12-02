// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use std::{
    fs::{self},
    path::{Path, PathBuf},
};

use oci_spec::image::ImageConfiguration;

use crate::{EnclaveBuildError, Result};

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
}
