// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod proxy;
pub mod dns;

use std::net::IpAddr;

#[derive(Copy, Clone, PartialEq)]
pub enum IpAddrType {
    /// Only allows IP4 addresses
    IPAddrV4Only,
    /// Only allows IP6 addresses
    IPAddrV6Only,
    /// Allows both IP4 and IP6 addresses
    IPAddrMixed
}

pub struct DnsResolveResult {
    ///Resolved address
    ip: IpAddr,
    ///DNS TTL value
    ttl: u32
}

/// The most common result type provided by VsockProxy operations.
pub type VsockProxyResult<T> = Result<T, String>;