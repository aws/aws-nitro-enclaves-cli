// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::fs;
use std::path::Path;
use std::env;
use std::io::{Write, BufWriter};
use std::path::PathBuf;

use oci_distribution::{Reference};
use oci_distribution::client::ImageData;

use crate::cache_manager::{CacheManager, CacheError};
use crate::constants::{self, IMAGE_FILE_NAME, CACHE_ROOT_FOLDER, TEST_MODE_ENABLED};

use crate::utils::{ExtractLogic, Image};

pub struct CacheLogic {}

impl CacheLogic {
    /// Wrapper function for image_cache::CacheLogic::cache_image_data
    pub fn cache_image(image: &Image, cache_manager: &mut CacheManager) -> Result<(), CacheError> {
        let image_folder_path = CachePath::get_image_folder_path(image, cache_manager, TEST_MODE_ENABLED)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        CacheLogic::cache_image_data(image, &image_folder_path, cache_manager)
    }

    /// Stores the image and its associated meta and config data in the path (folder) given as parameter
    /// and records the image in the cache by adding it to the CacheManager's hashmap
    pub fn cache_image_data(image: &Image, path: &PathBuf, cache_manager: &mut CacheManager) -> Result<(), CacheError> {
        let image_data = image.data();

        CachePath::create_image_folder(image, cache_manager)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        CacheLogic::cache_image_file(image_data, path)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;
    
        CacheLogic::cache_config(image_data, path)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        CacheLogic::cache_manifest(image_data, path)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        CacheLogic::cache_layers(image_data, path)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        CacheLogic::cache_expressions(image_data, path, &"ENV".to_string())
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        CacheLogic::cache_expressions(image_data, path, &"CMD".to_string())
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        // Record the new cached image
        cache_manager.record_image(image)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        Ok(())
    }

    /// Store the actual image file to the path given as parameter
    pub fn cache_image_file(image_data: &ImageData, path: &PathBuf) -> Result<(), CacheError> {

        // Try to extract the image file data bytes from the remotely pulled ImageData struct
        let image_bytes = ExtractLogic::extract_image(image_data)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        // Build the cache path of the image file
        let mut file_path = path.clone();
        file_path.push(IMAGE_FILE_NAME);
        
        // Create the cached image file (the directories in the path should already be created)
        let mut output_file = File::create(&file_path)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        // Write the image file bytes to the cache image file
        output_file.write_all(&image_bytes)
            .map_err(|err| CacheError::StoreError(format!(
                "Image file could not be written to cache: {:?}", err)))
    }

    /// Store the config.json file of an image to the path given as parameter
    pub fn cache_config(image_data: &ImageData, path: &PathBuf) -> Result<(), CacheError> {
        // Try to extract the configuration JSON string from the remotely pulled ImageData struct
        let config_json = ExtractLogic::extract_config_json(image_data)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        // Build the cache path of the config file
        let mut file_path = path.clone();
        file_path.push("config.json");

        // Create the cached config JSON file (the directories in the path should already be created)
        let mut output_file = File::create(&file_path)
            .map_err(|err| CacheError::StoreError(format!(
                "Failed to create the configuration cache file: {:?}", err)))?;

        // Write the JSON string to the cached config file
        output_file.write_all(config_json.as_bytes())
            .map_err(|err| CacheError::StoreError(format!(
                "Configuration JSON could not be written to cache: {:?}", err)))
    }

    /// Store the manifest.json file of an image to the path given as parameter
    pub fn cache_manifest(image_data: &ImageData, path: &PathBuf) -> Result<(), CacheError> {
        // Try to extract the manifest JSON from the remotely pulled ImageData struct
        let manifest_json = ExtractLogic::extract_manifest_json(image_data)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;
        
        // Build the cache path of the manifest file
        let mut file_path = path.clone();
        file_path.push("manifest.json");

        // Create the cached manifest JSON file (the directories in the path should already be created)
        let mut output_file = File::create(&file_path)
            .map_err(|err| CacheError::StoreError(format!(
                "Failed to create the manifest cache file: {:?}", err)))?;

        // Write the manifest data to the manifest.json file
        output_file.write_all(manifest_json.as_bytes())
            .map_err(|err| CacheError::StoreError(format!(
                "Manifest file could not be written to cache: {:?}", err)))?;

        Ok(())
    }

    /// Store the image layers (as tar files) of an image to the path given as parameter, each layer
    /// in a different file
    pub fn cache_layers(image_data: &ImageData, path: &PathBuf) -> Result<(), CacheError> {
        // Try to extract the image layers from the remotely pulled ImageData struct
        let image_layers = ExtractLogic::extract_layers(image_data)
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        let mut output_path = path.clone();
        // Add the 'layers' directory to the path
        output_path.push("layers");

        // Create the 'layers' directory
        fs::create_dir_all(&output_path).map_err(|err| CacheError::StoreError(format!(
            "Failed to create the folder for storing the image layers: {:?}", err)))?;
        
        // Iterate through the layers and for each layer, store it in a tar file in the cache
        for (index, layer) in image_layers.iter().enumerate() {
            // Build the path of the layer tar file
            let mut file_path = output_path.clone();
            file_path.push(vec!["layer".to_string(), index.to_string()].concat());

            // Create the cache file containing the layer
            let mut output_file = File::create(&file_path)
                .map_err(|err| CacheError::StoreError(format!(
                    "Failed to create an image layer cache file: {:?}", err)))?;

            // Write the layer bytes to the cache file
            output_file.write_all(&layer.data)
                .map_err(|err| CacheError::StoreError(format!(
                    "Failed to write layer to cache file for layer {} with digest {}: {:?}",
                    index, layer.sha256_digest(), err)))?;
        }

        Ok(())
    }

    /// Store the 'ENV' or 'CMD' expressions in the env.sh or cmd.sh files in the path given as parameter
    /// The required expression is given in the 'expression_name' parameter
    pub fn cache_expressions(image_data: &ImageData, path: &PathBuf, expression_name: &String) -> Result<(), CacheError> {
        let expressions_res = match expression_name.as_str() {
            "ENV" => ExtractLogic::extract_env_expressions(image_data),
            "CMD" => ExtractLogic::extract_cmd_expressions(image_data),
            _ => {
                return Err(CacheError::ArgumentError(
                    "Function argument 'expression_name' should be 'CMD' or 'ENV'".to_string()));
            }
        };

        let expressions = expressions_res
            .map_err(|err| CacheError::StoreError(format!("{:?}", err)))?;

        // Build the path of the cache file containing the expressions
        let output_path = vec![path.clone().into_os_string().into_string().unwrap(),
            "/".to_string(), match expression_name.as_str() {
                "ENV" => constants::ENV_CACHE_FILE_NAME.to_string(),
                "CMD" => constants::CMD_CACHE_FILE_NAME.to_string(),
                // This case was already handled above
                _ => {
                    return Err(CacheError::ArgumentError("".to_string()));
                },
            }].concat();

        // Create the file
        let output_file = File::create(output_path)
            .map_err(|err| CacheError::StoreError(format!(
                "Failed to create the output flle: {:?}", err)))?;                              

        // Use a BufWriter to write to the cache file, one expression on every new line
        let mut writer = BufWriter::new(&output_file);

        // Iterate through the expressions and write each one of them on a new line
        expressions.iter()
            .try_for_each(|expr| writeln!(&mut writer, "{}", expr)
                .map_err(|err| CacheError::StoreError(format!(
                    "Failed to write {} expression to the output cache file: {}", expression_name, err))))?;
        Ok(())
    }

    /// Find and retrieve a cached image as a file if available in the local cache
    pub fn get_cached_image(image: &Image, cache_manager: &CacheManager) -> Result<File, CacheError> {
        // Get the image file path
        let image_file_path = match CachePath::get_image_folder_path(image, cache_manager, TEST_MODE_ENABLED) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::RetrieveError(format!("Cached image path could not be computed: {:?}", err)));
            }
        };

        // Check if there exists an image file at that path
        if Path::new(&image_file_path).exists() {
            // Return the image file as a File struct if it can be opened
            let image_file = File::open(&image_file_path).map_err(|err| {
                CacheError::RetrieveError(format!("Could not open image file at '{:?}': {}",
                    image_file_path, err))
            });
            Ok(image_file.unwrap())
        } else {
            Err(CacheError::RetrieveError(format!("Image file does not exist at '{:?}', probably the image is not cached.",
                    image_file_path)))
        }

    }

    /// Checks if an image is cached in the local cache
    pub fn is_cached(image_ref: &Reference, cache_manager: &CacheManager) -> bool {
        if cache_manager.get_image_hash_from_cache(&image_ref.whole()).is_some() {
            return true;
        }
        false
    }
}


pub struct CachePath {}

impl CachePath {
    /// Returns the root folder path of the cache
    /// 
    /// flag = true  => XDG_DATA_HOME is used as root
    /// 
    /// flag = false => local directory is used as a 'mock cache'
    ///               e.g. ./test/container_cache
    pub fn get_cache_root_folder(flag: bool) -> Result<PathBuf, CacheError> {
        if flag {
            return Ok(PathBuf::from("./test/container_cache/"));
        }

        // Use XDG_DATA_HOME as root
        let root = match env::var_os(CACHE_ROOT_FOLDER) {
            Some(val) => val.into_string()
                .map_err(|err| CacheError::PathError(format!("{:?}", err)))?,
            // If XDG_DATA_HOME is not set, use $HOME/.local/share as specified in
            // https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
            None => {
                let home_folder = env::var_os("HOME")
                    .ok_or_else(|| CacheError::PathError(
                        "HOME environment variable is not set.".to_string()))?;
                format!("{}/.local/share/", home_folder.into_string()
                    .map_err(|err| CacheError::PathError(format!("{:?}", err)))?)
            }
        };

        let mut path = PathBuf::from(root);
        path.push("/.nitro_cli/container_cache");

        Ok(path)
    }


    /// Returns the path to the cache root folder of an image
    /// 
    /// e.g. {ROOT}/.nitro_cli/container_cache/{IMAGE_HASH}
    pub fn get_image_folder_path(image: &Image, cache_manager: &CacheManager, flag: bool) -> Result<PathBuf, CacheError> {
        // Try to extract the image hash from the cache
        let hash = Image::get_image_hash(image, cache_manager).map_err(|err|
            CacheError::PathError(format!("Failed to determine the image folder path: {:?}", err)))?;

        // Get the cache root folder
        let mut cache_root = CachePath::get_cache_root_folder(flag)
            .map_err(|err| CacheError::PathError(format!(
                "Failed to determine the image folder path: {:?}", err)))?;

        cache_root.push(hash);

        Ok(cache_root)
    }

    /// Creates all folders from the path of the cache
    /// 
    /// flag = false => Default root path is used for cache
    /// 
    /// flag = true  => Current directory is used as cache root
    pub fn create_cache_folder_path(flag: bool) -> Result<(), CacheError> {
        fs::create_dir_all(CachePath::get_cache_root_folder(flag)
                .map_err(|err| CacheError::PathError(format!(
                    "Failed to create the cache folder path: {:?}", err)))?)
            .map_err(|err| CacheError::PathError(format!(
                "Failed to create the cache folder path: {:?}", err)))
    }

    /// Creates the folder in the cache where the image data will be stored
    pub fn create_image_folder(image: &Image, cache_manager: &CacheManager) -> Result<(), CacheError> {
        let image_folder_path = CachePath::get_image_folder_path(image, cache_manager, TEST_MODE_ENABLED)
            .map_err(|err| CacheError::PathError(format!(
                "Failed to create the image cache folder: {:?}", err)))?;

        fs::create_dir_all(image_folder_path).map_err(|err|
            CacheError::PathError(format!("Failed to create the image cache folder: {:?}", err)))
    }
}
