// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use eif_defs::EifBuildInfo;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::SystemTime;

/// Utilities and helpers to fill EIF identity information

const MAX_META_FILE_SIZE: u64 = 4096;
const UNKNOWN_IMG_STR: &str = "Unknown";

/// Generate basic build info (build tool, version, time, image kernel info)
pub fn generate_build_info(
    build_tool: &str,
    build_tool_version: &str,
    img_config_path: &str,
) -> Result<EifBuildInfo, String> {
    let now = SystemTime::now();
    let now: DateTime<Utc> = now.into();

    let config_file = File::open(img_config_path)
        .map_err(|e| format!("Failed to open kernel image config file: {}", e))?;
    let os_string = BufReader::new(config_file)
        .lines()
        .nth(2)
        .unwrap()
        .map_err(|e| format!("Failed to read kernel config file: {}", e))?;

    // Extract OS and version from line format:
    // ' # Linux/x86_64 4.14.177-104.253.amzn2.x86_64 Kernel Configuration '
    let sep: Vec<char> = vec![' ', '/', '-'];
    let os_words: Vec<&str> = os_string.split(&sep[..]).collect();

    Ok(EifBuildInfo {
        build_time: now.to_rfc3339(),
        build_tool: build_tool.to_string(),
        build_tool_version: build_tool_version.to_string(),
        img_os: os_words.get(1).unwrap_or(&UNKNOWN_IMG_STR).to_string(),
        img_kernel: os_words.get(3).unwrap_or(&UNKNOWN_IMG_STR).to_string(),
    })
}

/// Macro helper for generate_buid_info function to automatically pick up cargo info for build tool fields
#[macro_export]
macro_rules! generate_build_info {
    ($kernel_config_path:expr) => {
        $crate::identity::generate_build_info(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            $kernel_config_path,
        )
    };
}

/// Read user-provided metadata from a file in a JSON format
pub fn parse_custom_metadata(path: &str) -> Result<serde_json::Value, String> {
    if !Path::new(&path).is_file() {
        return Err("Specified path is not a file".to_string());
    }

    // Check file size
    let file_meta =
        std::fs::metadata(path).map_err(|e| format!("Failed to get file metadata: {}", e))?;
    if file_meta.len() > MAX_META_FILE_SIZE {
        return Err(format!(
            "Metadata file size exceeded limit of {}B",
            MAX_META_FILE_SIZE
        ));
    }

    // Get json Value
    let custom_file =
        File::open(path).map_err(|e| format!("Failed to open custom metadata file: {}", e))?;
    let json_value: serde_json::Value = serde_json::from_reader(custom_file)
        .map_err(|e| format!("Failed to deserialize json: {}", e))?;

    Ok(json_value)
}
