// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use serde::{Deserialize, Serialize};

/// The arguments used by the `run-enclave` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEnclavesArgs {
    /// The path to the enclave image file.
    pub eif_path: String,
    /// The optional enclave CID
    pub enclave_cid: Option<u64>,
    /// The amount of memory that will be given to the enclave.
    pub memory_mib: u64,
    /// An optional list of CPU IDs that will be given to the enclave.
    pub cpu_ids: Option<Vec<u32>>,
    /// A flag indicating if the enclave will be started in debug mode.
    pub debug_mode: Option<bool>,
    /// The number of CPUs that the enclave will receive.
    pub cpu_count: Option<u32>,
}

/// The arguments used by the `describe-enclaves` command.
#[derive(Serialize, Deserialize)]
pub struct EmptyArgs {}
