// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust FFI bindings to Linux Nitro Enclaves driver, generated using
//! [bindgen](https://crates.io/crates/bindgen).

#![allow(missing_docs)]
#![allow(non_camel_case_types)]

// Keep this until https://github.com/rust-lang/rust-bindgen/issues/1651 is fixed.
#[cfg_attr(test, allow(deref_nullptr))]
mod bindings;
pub use self::bindings::*;
mod wrappers;
pub use self::wrappers::*;
