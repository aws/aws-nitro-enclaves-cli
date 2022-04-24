// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::bindings::ne_enclave_start_info;

impl Default for ne_enclave_start_info {
    fn default() -> Self {
        Self {
            flags: 0,
            enclave_cid: 0,
        }
    }
}
