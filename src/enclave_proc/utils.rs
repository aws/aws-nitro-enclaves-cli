// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use std::fs::metadata;
use std::fs::File;
use std::io::Read;

use crate::common::json_output::{EnclaveDescribeInfo, EnclaveRunInfo};
use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::enclave_proc::resource_manager::EnclaveManager;
use crate::enclave_proc::resource_manager::NE_ENCLAVE_DEBUG_MODE;
use crate::new_nitro_cli_failure;

/// Kibibytes.
#[allow(non_upper_case_globals)]
pub const KiB: u64 = 1024;

/// Mebibytes.
#[allow(non_upper_case_globals)]
pub const MiB: u64 = 1024 * KiB;

/// Gibibytes.
#[allow(non_upper_case_globals)]
pub const GiB: u64 = 1024 * MiB;

/// Get a string representation of the bit-mask which holds the enclave launch flags.
pub fn flags_to_string(flags: u64) -> String {
    if flags & NE_ENCLAVE_DEBUG_MODE == NE_ENCLAVE_DEBUG_MODE {
        "DEBUG_MODE"
    } else {
        "NONE"
    }
    .to_string()
}

/// Obtain the enclave information requested by the `describe-enclaves` command.
pub fn get_enclave_describe_info(
    enclave_manager: &EnclaveManager,
) -> NitroCliResult<EnclaveDescribeInfo> {
    let (slot_uid, enclave_cid, cpus_count, cpu_ids, memory_mib, flags, state) =
        enclave_manager.get_description_resources()?;
    let info = EnclaveDescribeInfo::new(
        generate_enclave_id(slot_uid)?,
        enclave_cid,
        cpus_count,
        cpu_ids,
        memory_mib,
        state.to_string(),
        flags_to_string(flags),
    );
    Ok(info)
}

/// Obtain the enclave information requested by the `run-enclaves` command.
pub fn get_run_enclaves_info(
    enclave_name: String,
    enclave_cid: u64,
    slot_id: u64,
    cpu_ids: Vec<u32>,
    memory: u64,
) -> NitroCliResult<EnclaveRunInfo> {
    let info = EnclaveRunInfo::new(
        enclave_name,
        generate_enclave_id(slot_id)?,
        enclave_cid,
        cpu_ids.len(),
        cpu_ids,
        memory,
    );
    Ok(info)
}

/// Generate a unique ID for a new enclave with the specified slot ID.
pub fn generate_enclave_id(slot_id: u64) -> NitroCliResult<String> {
    let file_path = "/sys/devices/virtual/dmi/id/board_asset_tag";
    if metadata(file_path).is_ok() {
        let mut file = File::open(file_path).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to open file: {:?}", e),
                NitroCliErrorEnum::FileOperationFailure
            )
            .add_info(vec![file_path, "Open"])
        })?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read from file: {:?}", e),
                NitroCliErrorEnum::FileOperationFailure
            )
            .add_info(vec![file_path, "Read"])
        })?;
        contents.retain(|c| !c.is_whitespace());
        return Ok(format!("{}-enc{:x}", contents, slot_id));
    }
    Ok(format!("i-0000000000000000-enc{:x}", slot_id))
}

/// Obtain an enclave's slot ID from its full ID.
pub fn get_slot_id(enclave_id: String) -> Result<u64, String> {
    let tokens: Vec<&str> = enclave_id.split("-enc").collect();

    match tokens.get(1) {
        Some(slot_id) => u64::from_str_radix(*slot_id, 16)
            .map_err(|_err| "Invalid enclave id format".to_string()),
        None => Err("Invalid enclave_id.".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_enclave_id() {
        let slot_id: u64 = 7;
        let enc_id = generate_enclave_id(slot_id);
        let file_path = "/sys/devices/virtual/dmi/id/board_asset_tag";

        if metadata(file_path).is_err() {
            assert!(enc_id
                .unwrap()
                .eq(&format!("i-0000000000000000-enc{:?}", slot_id)));
        } else {
            assert!(!enc_id
                .unwrap()
                .split('-')
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .eq(&"0000000000000000"));
        }
    }

    #[test]
    fn test_get_slot_id_valid() {
        let slot_id: u64 = 8;
        let enc_id = generate_enclave_id(slot_id);

        if let Ok(enc_id) = enc_id {
            let result = get_slot_id(enc_id);
            assert!(result.is_ok());
            assert_eq!(slot_id, result.unwrap());
        }
    }

    #[test]
    fn test_get_slot_id_invalid() {
        let enclave_id = String::from("i-0000_enc1234");
        let result = get_slot_id(enclave_id);

        assert!(result.is_err());
        if let Err(err_str) = result {
            assert!(err_str.eq("Invalid enclave_id."));
        }
    }

    /// Tests that `flags_to_string()` returns the correct String representation
    /// when the NE_ENCLAVE_DEBUG_MODE is either set or unset.
    #[test]
    fn test_flags_to_string() {
        let mut flags: u64 = 0;

        flags |= NE_ENCLAVE_DEBUG_MODE;
        let mut result = flags_to_string(flags);

        assert!(result.eq("DEBUG_MODE"));

        flags = 0;
        result = flags_to_string(flags);

        assert!(result.eq("NONE"));
    }

    /// Asserts that `get_run_enclaves_info()` returns a result containing
    /// exactly the same values as the supplied arguments.
    #[test]
    fn test_get_run_enclaves_info() {
        let enclave_name = "testName".to_string();
        let enclave_cid: u64 = 0;
        let slot_id: u64 = 7;
        let cpu_ids: Vec<u32> = vec![1, 3];
        let memory: u64 = 64;

        let result =
            get_run_enclaves_info(enclave_name, enclave_cid, slot_id, cpu_ids.clone(), memory);

        assert!(result.is_ok());

        if let Ok(result) = result {
            assert_eq!(enclave_cid, result.enclave_cid);
            assert_eq!(cpu_ids.len(), result.cpu_ids.len());
            for (idx, cpu_id) in result.cpu_ids.iter().enumerate() {
                assert_eq!(cpu_ids[idx], *cpu_id);
            }
            assert_eq!(memory, result.memory_mib);
        }
    }

    /// Asserts that `get_enclave_id()` returns the expected enclave
    /// id, which is obtained through a call to `get_run_enclaves_info()`.
    #[test]
    fn test_get_enclave_id() {
        let enclave_name = "testName".to_string();
        let enclave_cid: u64 = 0;
        let slot_id: u64 = 8;
        let cpu_ids: Vec<u32> = vec![1, 3];
        let memory: u64 = 64;

        let result =
            get_run_enclaves_info(enclave_name, enclave_cid, slot_id, cpu_ids.clone(), memory);

        assert!(result.is_ok());

        if let Ok(result) = result {
            let this_enclave_id = &result.enclave_id;
            assert!(this_enclave_id.eq(&result.enclave_id));

            assert_eq!(enclave_cid, result.enclave_cid);
            assert_eq!(cpu_ids.len(), result.cpu_ids.len());
            for (idx, cpu_id) in result.cpu_ids.iter().enumerate() {
                assert_eq!(cpu_ids[idx], *cpu_id);
            }
            assert_eq!(memory, result.memory_mib);
        }
    }
}
