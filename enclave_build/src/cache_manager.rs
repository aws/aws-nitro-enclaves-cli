// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use crate::constants::CACHE_INDEX_FILE_NAME;
use crate::utils::{ExtractLogic, Image};

#[derive(Debug, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum CacheError {
    StoreError(String),
    ArgumentError(String),
    PathError(String),
    RetrieveError(String),
}

/// (Idea)
/// Apart from keeping the (docker URI <-> image hash) mapping in a JSON file, my idea was to also use a
/// runtime-exclusive HashMap to store these mappings, in order to not open and read the JSON file for each query
pub struct CacheManager {
    values: HashMap<String, String>,
}

impl CacheManager {
    /// Create a new CacheManager
    pub fn new() -> CacheManager {
        Self {
            values: HashMap::new(),
        }
    }

    pub fn get_values(&self) -> &HashMap<String, String> {
        &self.values
    }

    pub fn get_values_mut(&mut self) -> &mut HashMap<String, String> {
        &mut self.values
    }

    /// Return the image hash corresponding to the image URI, if available in the hashmap
    pub fn get_image_hash_from_cache(&self, uri: &String) -> Option<String> {
        self.values.get(uri).map(|val| val.to_string())
    }

    /// Record the new image that was added to the cache (add it to the CacheManager's hashmap)
    pub fn record_image(&mut self, image: &Image) -> Result<(), CacheError> {
        // Get the image hash
        let image_hash = ExtractLogic::extract_image_hash(image.data())
            .map_err(|err| CacheError::StoreError(format!(
                "Cache manager failed to record image: {:?}", err)))?;

        // Get the image URI
        let image_uri = image.reference().whole();

        self.add_entry(&image_uri, &image_hash);

        Ok(())
    }

    /// Add a new image URI <-> hash entry to the hashmap
    pub fn add_entry(&mut self, uri: &String, hash: &String) {
        self.values.insert(uri.to_string(), hash.to_string());
    }

    /// Populate the hashmap with the values from a JSON index file which contains the mappings
    pub fn populate_hashmap(&mut self, index_file_path: &String) -> Result<(), CacheError> {
        // Open the JSON file
        let index_file = File::open(index_file_path);
        let mut json_file = index_file.map_err(|err| CacheError::RetrieveError(format!(
            "Failed to populate the hashmap from the JSON file: {:?}", err)))?;

        // Read the JSON string from the file
        let mut json_string = String::new();
        json_file.read_to_string(&mut json_string).map_err(|err|
            CacheError::RetrieveError(format!("Failed to read from index file: {:?}", err)))?;

        // Try to deserialize the JSON into a HashMap
        let map: HashMap<String, String> = serde_json::from_str(json_string.as_str())
            .map_err(|err| CacheError::RetrieveError(format!(
                "Failed to populate the hashmap from the JSON file: {:?}", err)))?;

        self.values = map;

        Ok(())
    }

    /// Writes the content of the hashmap ((image URI <-> image hash) mappings) to the index.json file
    /// in the specified path
    pub fn write_index_file(&self, path: &PathBuf) -> Result<(), CacheError> {
        let mut new_path = path.clone();
        new_path.push(CACHE_INDEX_FILE_NAME);

        // Create (or open if it's already created) the index.json file
        let index_file = File::create(new_path)
            .map_err(|err| CacheError::StoreError(format!(
                "The cache index file could not be created: {:?}", err)))?;

        // Write the hashmap (the mappings) to the file
        serde_json::to_writer(index_file, &self.values)
            .map_err(|err| CacheError::StoreError(format!(
                "Failed to write hashmap to index JSON file: {:?}", err)))
    }
}
