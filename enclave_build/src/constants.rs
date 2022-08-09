// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0


/// Docker inspect architecture constants
pub const DOCKER_ARCH_ARM64: &str = "arm64";
pub const DOCKER_ARCH_AMD64: &str = "amd64";

/// Root folder for the cache
pub const CACHE_ROOT_FOLDER: &str = "XDG_DATA_HOME";

/// For testing purposes, use $HOME as cache root folder
pub const HOME_ENV_VAR: &str = "HOME";

/// The name of the actual image file from the image cache folder
pub const IMAGE_FILE_NAME: &str = "image_file";

/// Name of the cache file where 'ENV' expressions are stored
pub const ENV_CACHE_FILE_NAME: &str = "env.sh";

/// Name of the cache file where 'CMD' expressions are stored
pub const CMD_CACHE_FILE_NAME: &str = "cmd.sh";

/// Name of the file which stores the (image URI <-> image hash) mappings
pub const CACHE_INDEX_FILE_NAME: &str = "index.json";

/// If true, {CURRENT_DIRECTORY}/test/container_cache will be used as cache
/// 
/// If false, the default path is used
pub const TEST_MODE_ENABLED: bool = true;
