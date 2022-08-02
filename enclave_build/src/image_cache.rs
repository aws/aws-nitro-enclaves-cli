use std::fs::File;
use std::path::Path;
use std::env;

use oci_distribution::{manifest, Client, Reference};
use oci_distribution::client::ImageData;

use crate::cache_manager::{CacheManager, self, CacheError};

use crate::constants::{CACHE_ROOT_FOLDER};

#[derive(Debug, PartialEq)]

pub struct CacheLogic {}

impl CacheLogic {

    // These functions will handle the effective copying of the data bytes to the local cache

    pub fn cache_image_file() {
        // TODO
    }

    pub fn cache_config() {
        // TODO
    }

    pub fn cache_manifest() {
        // TODO
    }

    pub fn cache_layers() {
        // TODO
    }

    pub fn cache_single_layer() {
        // TODO
    }

    pub fn cache_env_cmd_expressions() {
        // TODO
    }

    /// Find and retrieve a cached image as a file if available in the local cache
    pub fn get_cached_image(image_ref: &Reference, cache_manager: &mut CacheManager) -> Result<File, CacheError> {
        // Get the image file path
        let image_file_path_res = CachePath::get_image_path(image_ref, cache_manager);
        match image_file_path_res {
            Ok(_) => (),
            Err(err) => {
                return Err(CacheError::FindImageError(format!("Cached image path could not be computed: {:?}", err)));
            }
        }
        let image_file_path = image_file_path_res.unwrap();

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
    pub fn is_cached(image_ref: &Reference, cache_manager: &mut CacheManager) -> bool {
        match cache_manager.get_image_hash(&image_ref.whole()) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

pub struct CachePath {}

impl CachePath {

    /// Returns the root folder path of the cache
    pub fn get_cache_root_folder() -> String {
        let aux = env::var_os(CACHE_ROOT_FOLDER).unwrap();
        let xdg_data_dirs = aux.to_str().unwrap();
        let dirs: Vec<&str> = xdg_data_dirs.split(":").collect();

        // For CACHE_ROOT_FOLDER = XDG_DATA_DIRS, choose to take the first directory path
        // PROBLEM - on the EC2 AL2 instance XDG_DATA_DIRS is not set from what I have seen
        // => should have some default root folder for this case
        dirs[0].to_string()
    }

    /// Returns the path to the root folder of the cache
    pub fn get_root_path() -> String {
        let cache_root_folder = CachePath::get_cache_root_folder();

        format!("{}/.nitro_cli/container_cache/", cache_root_folder)
    }

    /// Returns the path to the cache root folder of an image
    /// e.g. {ROOT}/.nitro_cli/container_cache/{IMAGE_HASH}
    pub fn get_image_path(image_ref: &Reference, cache_manager: &mut CacheManager) -> Result<String, CacheError> {
        let image_hash = cache_manager.get_image_hash(&image_ref.whole());
        match image_hash {
            Ok(_) => (),
            Err(err) => {
                return Err(CacheError::DataCacheError(format!("Failed to find the cached image: {:?}", err)));
            }
        };

        Ok(format!("{}{}", CachePath::get_root_path(), image_hash.unwrap()))
    }
}