// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust FFI bindings to Linux Nitro Enclaves driver, generated using
//! [bindgen](https://crates.io/crates/bindgen).

#![allow(missing_docs)]
#![allow(non_camel_case_types)]

pub mod bindings;
pub use self::bindings::*;
