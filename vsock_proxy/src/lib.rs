// Copyright 2019-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod dns;
pub mod proxy;

#[derive(Copy, Clone, PartialEq)]
pub enum IpAddrType {
    /// Only allows IP4 addresses
    IPAddrV4Only,
    /// Only allows IP6 addresses
    IPAddrV6Only,
    /// Allows both IP4 and IP6 addresses
    IPAddrMixed,
}

/// The most common result type provided by VsockProxy operations.
pub type VsockProxyResult<T> = Result<T, String>;
