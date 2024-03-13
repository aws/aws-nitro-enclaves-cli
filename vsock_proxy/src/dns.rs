// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

/// Contains code for Proxy, a library used for translating vsock traffic to
/// TCP traffic
///
use dns_lookup::lookup_host;
use idna::domain_to_ascii;
use std::net::IpAddr;

use crate::{IpAddrType, VsockProxyResult, DnsResolveResult};

/// Resolve a DNS name (IDNA format) into multiple IP addresses (v4 or v6)
pub fn resolve(addr: &str, ip_addr_type: IpAddrType) -> VsockProxyResult<Vec<IpAddr>> {
    // IDNA parsing
    let addr = domain_to_ascii(addr).map_err(|_| "Could not parse domain name")?;

    // DNS lookup
    // It results in a vector of IPs (V4 and V6)
    let ips = match lookup_host(&addr) {
        Err(_) => {
            return Ok(vec![]);
        }
        Ok(v) => {
            if v.is_empty() {
                return Ok(v);
            }
            v
        }
    };

    // If there is no restriction, choose randomly
    if IpAddrType::IPAddrMixed == ip_addr_type {
        return Ok(ips.into_iter().collect());
    }

    // Split the IPs in v4 and v6
    let (ips_v4, ips_v6): (Vec<_>, Vec<_>) = ips.into_iter().partition(IpAddr::is_ipv4);

    if IpAddrType::IPAddrV4Only == ip_addr_type && !ips_v4.is_empty() {
        Ok(ips_v4.into_iter().collect())
    } else if IpAddrType::IPAddrV6Only == ip_addr_type && !ips_v6.is_empty() {
        Ok(ips_v6.into_iter().collect())
    } else {
        Err("No accepted IP was found".to_string())
    }
}

/// Resolve a DNS name (IDNA format) into a single address with a TTL value
pub fn resolve_single(addr: &str, ip_addr_type: IpAddrType) -> VsockProxyResult<DnsResolveResult> {
    let addrs = resolve(addr, ip_addr_type)
        .map_err(|err| format!("Could not parse remote address: {}", err))?;

    let ip = *addrs.first().ok_or("No IP address found")?;
    let ttl = 60; // IMPORTANT TODO: Obtain this value dynamically

    Ok(DnsResolveResult {
        ip,
        ttl
    })   
}