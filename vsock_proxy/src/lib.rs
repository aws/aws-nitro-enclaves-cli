// Copyright 2019-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod dns;
pub mod proxy;

use std::net::IpAddr;

#[derive(Copy, Clone, PartialEq)]
pub enum IpAddrType {
    /// Only allows IP4 addresses
    IPAddrV4Only,
    /// Only allows IP6 addresses
    IPAddrV6Only,
    /// Allows both IP4 and IP6 addresses
    IPAddrMixed,
}

#[derive(Copy, Clone, Debug)]
pub struct DnsResolveResult {
    ///Resolved address
    pub ip: IpAddr,
    ///DNS TTL value
    pub ttl: u32,
}

/// The most common result type provided by VsockProxy operations.
pub type VsockProxyResult<T> = Result<T, String>;
