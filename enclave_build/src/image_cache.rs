// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::fs::File;
use std::fs::create_dir_all;
use std::path::Path;
use std::env;
use std::fs;
use std::io::{Write, BufWriter};

use oci_distribution::client::ImageLayer;
use oci_distribution::{manifest, Client, Reference};
use oci_distribution::client::ImageData;

use crate::cache_manager::{CacheManager, self, CacheError};
use crate::constants;

use crate::constants::{CACHE_ROOT_FOLDER};
use crate::utils::{self, ExtractLogic, Image};

pub struct CacheLogic {}

impl CacheLogic {

    /// Stores the image and its associated meta and config data in the path (folder) given as parameter
    pub fn cache_image_data(image: &Image, path: &String, cache_manager: &mut CacheManager) -> Result<(), CacheError> {
        let image_data = image.data();
        match CacheLogic::cache_image_file(image_data, path) {
            Ok(()) => (),
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        match CacheLogic::cache_config(image_data, path) {
            Ok(()) => (),
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        match CacheLogic::cache_manifest(image_data, path) {
            Ok(()) => (),
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        match CacheLogic::cache_layers(image_data, path) {
            Ok(()) => (),
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        match CacheLogic::cache_expressions(image_data, path, &"ENV".to_string()) {
            Ok(()) => (),
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        match CacheLogic::cache_expressions(image_data, path, &"CMD".to_string()) {
            Ok(()) => (),
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        // Record the new cached image
        match cache_manager.record_image(image) {
            Ok(()) => Ok(()),
            Err(err) => Err(CacheError::DataCacheError(format!("{:?}", err)))
        }

        // TODO add the new mapping to the JSON file

    }

    /// Store the actual image file to the path given as parameter
    pub fn cache_image_file(image_data: &ImageData, path: &String) -> Result<(), CacheError> {
        // Try to extract the image file data bytes from the remotely pulled ImageData struct
        let image_bytes = ExtractLogic::extract_image(image_data);
        match image_bytes {
            Ok(_) => (),
            Err(err) => {
                return Err(CacheError::ImageFileError(format!("{:?}", err)));
            }
        };

        // Create the cached image file (the directories in the path should already be created)
        let mut output_file = match File::create(path) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::ImageFileError(format!("Failed to create the cached image file: {}", err)));
            }
        };

        // Write the image file bytes to the cache image file
        match output_file.write_all(&image_bytes.unwrap()) {
            Ok(_) => Ok(()),
            Err(err) => Err(CacheError::ImageFileError(format!("Image file could not be written to cache: {}", err)))
        }
    }

    /// Store the config.json file of an image to the path given as parameter
    pub fn cache_config(image_data: &ImageData, path: &String) -> Result<(), CacheError> {
        // Try to extract the configuration JSON string from the remotely pulled ImageData struct
        let config_json = match ExtractLogic::extract_config_json(image_data) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        // Create the cached config JSON file (the directories in the path should already be created)
        let mut output_file = match File::create(path) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::DataCacheError(format!(
                    "Failed to create the configuration cache file: {:?}", err)));
            }
        };

        // Write the JSON string to the cached config file
        match output_file.write_all(config_json.as_bytes()) {
            Ok(_) => Ok(()),
            Err(err) => Err(CacheError::DataCacheError(format!(
                "Configuration JSON could not be written to cache: {:?}", err)))
        }
    }

    /// Store the manifest.json file of an image to the path given as parameter
    pub fn cache_manifest(image_data: &ImageData, path: &String) -> Result<(), CacheError> {
        // Try to extract the manifest JSON from the remotely pulled ImageData struct
        let manifest_json = match ExtractLogic::extract_manifest_json(image_data) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        // Create the cached manifest JSON file (the directories in the path should already be created)
        let mut output_file = match File::create(path) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::DataCacheError(format!(
                    "Failed to create the manifest cache file: {:?}", err)));
            }
        };

        match output_file.write_all(manifest_json.as_bytes()) {
            Ok(_) => Ok(()),
            Err(err) => Err(CacheError::DataCacheError(format!(
                "Manifest file could not be written to cache: {:?}", err)))
        }
    }

    /// Store the image layers (as tar files) of an image to the path given as parameter, each layer
    /// in a different file
    pub fn cache_layers(image_data: &ImageData, path: &String) -> Result<(), CacheError> {
        // Try to extracte the image layers from the remotely pulled ImageData struct
        let image_layers = match ExtractLogic::extract_layers(image_data) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };
        
        // Iterate through the layers and for each layer, store it in a tar file in the cache
        for (index, layer) in image_data.layers.iter().enumerate() {
            // Build the path of the layer tar file
            let output_path = vec![path.clone(), "layer".to_string(),
                index.to_string()].concat();

            // Create the cache file containing the layer
            let mut output_file = match File::create(output_path) {
                Ok(aux) => aux,
                Err(err) => {
                    return Err(CacheError::DataCacheError(format!(
                        "Failed to create an image layer cache file: {:?}", err)));
                }
            };

            // Write the layer bytes to the cache file
            match output_file.write_all(&layer.data) {
                Ok(_) => (),
                Err(err) => {
                    return Err(CacheError::DataCacheError(format!(
                        "Failed to write layer to cache file for layer {} with digest {}: {:?}",
                        index, layer.sha256_digest(), err)));
                }
            };
        }

        Ok(())
    }

    /// Store the 'ENV' or 'CMD' expressions in the env.sh or cmd.sh files in the path given as parameter
    /// The required expression is given in the 'expression_name' parameter
    pub fn cache_expressions(image_data: &ImageData, path: &String, expression_name: &String) -> Result<(), CacheError> {
        let expressions_res = match expression_name.as_str() {
            "ENV" => ExtractLogic::extract_env_expressions(image_data),
            "CMD" => ExtractLogic::extract_cmd_expressions(image_data),
            _ => {
                return Err(CacheError::ArgumentError(format!(
                    "Function argument 'expression_name' should be 'CMD' or 'ENV'")));
            }
        };

        let expressions = match expressions_res {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("{:?}", err)));
            }
        };

        // Build the path of the cache file containing the expressions
        let output_path = vec![path.clone(), match expression_name.as_str() {
            "ENV" => constants::ENV_CACHE_FILE_NAME.to_string(),
            "CMD" => constants::CMD_CACHE_FILE_NAME.to_string(),
            // This case was already handled above
            _ => {
                return Err(CacheError::ArgumentError("".to_string()));
            },
        }].concat();
        // Create the file
        let output_file = match File::create(output_path) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::DataCacheError(format!(
                    "Failed to create {} expressions cache file file: {:?}", expression_name, err)));
            }
        };

        // Use a BufWriter to write to the cache file, one expression on every new line
        let mut writer = BufWriter::new(&output_file);

        // Iterate through the expressions and write each one of them on a new line
        for expr in expressions {
            let res = writeln!(&mut writer, "{}", expr);
            match res {
                Ok(_) => (),
                Err(err) => {
                    return Err(CacheError::DataCacheError(format!(
                        "Failed to write {} expression to the output cache file: {}", expression_name, err)));
                }
            };
        }

        Ok(())
    }

    /// Find and retrieve a cached image as a file if available in the local cache
    pub fn get_cached_image(image_ref: &Reference, cache_manager: &CacheManager) -> Result<File, CacheError> {
        // Get the image file path
        let image_file_path = match CachePath::get_image_folder_path(image_ref, cache_manager) {
            Ok(aux) => aux,
            Err(err) => {
                return Err(CacheError::FindImageError(format!("Cached image path could not be computed: {:?}", err)));
            }
        };

        // Check if there exists an image file at that path
        if Path::new(&image_file_path).exists() {
            // Return the image file as a File struct if it can be opened
            let image_file = File::open(&image_file_path).map_err(|err| {
                CacheError::ImageFileError(format!("Could not open image file at '{}': {}",
                    image_file_path, err))
            });
            return Ok(image_file.unwrap());
        } else {
            Err(CacheError::FindImageError(format!("Image file does not exist at '{}', probably the image is not cached.",
                    image_file_path)))
        }

    }

    /// Checks if an image is cached in the local cache
    pub fn is_cached(image_ref: &Reference, cache_manager: &CacheManager) -> bool {
        match cache_manager.get_image_hash(&image_ref.whole()) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

pub struct CachePath {}

impl CachePath {

    /// Returns the root folder of the cache
    /// 
    /// For CACHE_ROOT_FOLDER = XDG_DATA_DIRS
    // pub fn get_cache_root_folder() -> String {
    //     let aux = env::var_os(CACHE_ROOT_FOLDER).unwrap();
    //     let xdg_data_dirs = aux.to_str().unwrap();
    //     let dirs: Vec<&str> = xdg_data_dirs.split(":").collect();

    //     // For CACHE_ROOT_FOLDER = XDG_DATA_DIRS, choose to take the first directory path
    //     // PROBLEM - on the EC2 AL2 instance XDG_DATA_DIRS is not set from what I have seen
    //     // => should have some default root folder for this case
    //     dirs[0].to_string()
    // }

    /// Returns the root folder of the cache
    /// 
    /// For CACHE_ROOT_FOLDER = HOME
    /// Used just for testing
    pub fn get_cache_root_folder() -> String {
        let aux = env::var_os(CACHE_ROOT_FOLDER).unwrap();
        let home = aux.to_str().unwrap();

        home.to_string()
    }

    /// Returns the path to the root folder of the cache
    pub fn get_root_path() -> String {
        let cache_root_folder = CachePath::get_cache_root_folder();

        format!("{}/.nitro_cli/container_cache/", cache_root_folder)
    }

    /// Returns the path to the cache root folder of an image
    /// e.g. {ROOT}/.nitro_cli/container_cache/{IMAGE_HASH}
    pub fn get_image_folder_path(image_ref: &Reference, cache_manager: &CacheManager) -> Result<String, CacheError> {
        let image_hash = cache_manager.get_image_hash(&image_ref.whole());
        match image_hash {
            Ok(_) => (),
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("Failed to find the cached image: {:?}", err)));
            }
        };

        Ok(format!("{}{}", CachePath::get_root_path(), image_hash.unwrap()))
    }

    /// Creates the folder path of the cache
    /// 
    /// e.g. if path is '{ROOT}/.nitro_cli/container_cache/', it creates each folder from the path
    pub fn create_cache_root_path(path: &String) -> Result<(), CacheError> {
        match create_dir_all(path) {
            Ok(()) => Ok(()),
            Err(err) => Err(CacheError::CacheCreationError(format!(
                "Failed to create cache folder structure: {:?}", err)))
        }
    }
}