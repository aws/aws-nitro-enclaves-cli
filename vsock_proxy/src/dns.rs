// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

/// Contains code for Proxy, a library used for translating vsock traffic to
/// TCP traffic
///
use dns_lookup::lookup_host;
use idna::domain_to_ascii;
use std::net::IpAddr;

use crate::{DnsResolveResult, IpAddrType, VsockProxyResult};

/// Resolve a DNS name (IDNA format) into multiple IP addresses (v4 or v6)
pub fn resolve(addr: &str, ip_addr_type: IpAddrType) -> VsockProxyResult<Vec<DnsResolveResult>> {
    // IDNA parsing
    let addr = domain_to_ascii(addr).map_err(|_| "Could not parse domain name")?;

    // DNS lookup
    // It results in a vector of IPs (V4 and V6)
    let ips = lookup_host(&addr).map_err(|_| "DNS lookup failed!")?;

    if ips.is_empty() {
        return Err("DNS lookup returned no IP addresses!".into());
    }

    let ttl = 60; //TODO: update hardcoded value

    // If there is no restriction, choose randomly
    if IpAddrType::IPAddrMixed == ip_addr_type {
        return Ok(ips
            .into_iter()
            .map(|ip| DnsResolveResult { ip, ttl })
            .collect());
    }

    // Split the IPs in v4 and v6
    let (ips_v4, ips_v6): (Vec<_>, Vec<_>) = ips.into_iter().partition(IpAddr::is_ipv4);

    if IpAddrType::IPAddrV4Only == ip_addr_type && !ips_v4.is_empty() {
        Ok(ips_v4
            .into_iter()
            .map(|ip| DnsResolveResult { ip, ttl })
            .collect())
    } else if IpAddrType::IPAddrV6Only == ip_addr_type && !ips_v6.is_empty() {
        Ok(ips_v6
            .into_iter()
            .map(|ip| DnsResolveResult { ip, ttl })
            .collect())
    } else {
        Err("No accepted IP was found.".to_string())
    }
}

/// Resolve a DNS name (IDNA format) into a single address with a TTL value
pub fn resolve_single(addr: &str, ip_addr_type: IpAddrType) -> VsockProxyResult<DnsResolveResult> {
    let rresults = resolve(addr, ip_addr_type)?;
    // Return the first resolved IP address and its TTL value.
    rresults
        .first()
        .cloned()
        .ok_or_else(|| format!("Unable to resolve the DNS name: {}", addr))
}
