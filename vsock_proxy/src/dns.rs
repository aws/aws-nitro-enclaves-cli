// Copyright 2019-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]

use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use hickory_resolver::Resolver;
use idna::domain_to_ascii;

use crate::{IpAddrType, VsockProxyResult};

/// `DnsResolutionInfo` represents DNS resolution information, including the resolved
/// IP address, TTL value and last resolution time.
#[derive(Copy, Clone, Debug)]
pub struct DnsResolutionInfo {
    /// The IP address that the hostname was resolved to.
    ip_addr: IpAddr,
    /// The configured duration after which the DNS resolution should be refreshed.
    ttl: Duration,
    /// The timestamp representing the last time the DNS resolution was performed.
    last_dns_resolution_time: DateTime<Utc>,
}

impl DnsResolutionInfo {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.last_dns_resolution_time + self.ttl
    }

    fn new(new_ip_addr: IpAddr, new_ttl: Duration) -> Self {
        DnsResolutionInfo {
            ip_addr: new_ip_addr,
            ttl: new_ttl,
            last_dns_resolution_time: Utc::now(),
        }
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.ip_addr
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// Resolve a DNS name (IDNA format) into multiple IP addresses (v4 or v6)
pub fn resolve(addr: &str, ip_addr_type: IpAddrType) -> VsockProxyResult<Vec<DnsResolutionInfo>> {
    // IDNA parsing
    let addr = domain_to_ascii(addr).map_err(|_| "Could not parse domain name")?;

    // Initialize a DNS resolver using the system's configured nameservers.
    let resolver = Resolver::from_system_conf()
        .map_err(|_| "Error while initializing DNS resolver!".to_string())?;

    // DNS lookup
    // It results in a vector of IPs (V4 and V6)
    let rresults: Vec<DnsResolutionInfo> = resolver
        .lookup_ip(addr)
        .map_err(|_| "DNS lookup failed!")?
        .as_lookup()
        .records()
        .iter()
        .filter_map(|record| {
            if let Some(rdata) = record.data() {
                if let Some(ip_addr) = rdata.ip_addr() {
                    let ttl = Duration::seconds(record.ttl() as i64);
                    return Some(DnsResolutionInfo::new(ip_addr, ttl));
                }
            }
            None
        })
        .collect();

    if rresults.is_empty() {
        return Err("DNS lookup returned no IP addresses!".into());
    }

    // If there is no restriction, choose randomly
    if IpAddrType::IPAddrMixed == ip_addr_type {
        return Ok(rresults);
    }

    //Partition the resolution results into groups that use IPv4 or IPv6 addresses.
    let (rresults_with_ipv4, rresults_with_ipv6): (Vec<_>, Vec<_>) = rresults
        .into_iter()
        .partition(|result| result.ip_addr().is_ipv4());

    if IpAddrType::IPAddrV4Only == ip_addr_type && !rresults_with_ipv4.is_empty() {
        Ok(rresults_with_ipv4)
    } else if IpAddrType::IPAddrV6Only == ip_addr_type && !rresults_with_ipv6.is_empty() {
        Ok(rresults_with_ipv6)
    } else {
        Err("No accepted IP was found.".to_string())
    }
}

/// Resolve a DNS name (IDNA format) into a single address with a TTL value
pub fn resolve_single(addr: &str, ip_addr_type: IpAddrType) -> VsockProxyResult<DnsResolutionInfo> {
    let rresults = resolve(addr, ip_addr_type)?;
    // Return the first resolved IP address and its TTL value.
    rresults
        .first()
        .cloned()
        .ok_or_else(|| format!("Unable to resolve the DNS name: {}", addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    use ctor::ctor;
    use std::env;
    use std::sync::Once;

    static TEST_INIT: Once = Once::new();

    static mut INVALID_TEST_DOMAIN: &'static str = "invalid-domain";
    static mut IPV4_ONLY_TEST_DOMAIN: &'static str = "v4.ipv6test.app";
    static mut IPV6_ONLY_TEST_DOMAIN: &'static str = "v6.ipv6test.app";
    static mut DUAL_IP_TEST_DOMAIN: &'static str = "ipv6test.app";

    #[test]
    #[ctor]
    fn init() {
        // *** To use nonlocal domain names, set TEST_NONLOCAL_DOMAINS variable. ***
        // *** TEST_NONLOCAL_DOMAINS=1 cargo test                                ***
        TEST_INIT.call_once(|| {
            if env::var_os("TEST_NONLOCAL_DOMAINS").is_none() {
                eprintln!("[warn] dns: using 'localhost' for testing.");
                unsafe {
                    IPV4_ONLY_TEST_DOMAIN = "localhost";
                    IPV6_ONLY_TEST_DOMAIN = "::1";
                    DUAL_IP_TEST_DOMAIN = "localhost";
                }
            }
        });
    }

    #[test]
    fn test_resolve_valid_domain() {
        let domain = unsafe { IPV4_ONLY_TEST_DOMAIN };
        let rresults = resolve(domain, IpAddrType::IPAddrMixed).unwrap();
        assert!(!rresults.is_empty());
    }

    #[test]
    fn test_resolve_valid_dual_ip_domain() {
        let domain = unsafe { DUAL_IP_TEST_DOMAIN };
        let rresults = resolve(domain, IpAddrType::IPAddrMixed).unwrap();
        assert!(!rresults.is_empty());
    }

    #[test]
    fn test_resolve_invalid_domain() {
        let domain = unsafe { INVALID_TEST_DOMAIN };
        let rresults = resolve(domain, IpAddrType::IPAddrMixed);
        assert!(rresults.is_err() && rresults.err().unwrap().eq("DNS lookup failed!"));
    }

    #[test]
    fn test_resolve_ipv4_only() {
        let domain = unsafe { IPV4_ONLY_TEST_DOMAIN };
        let rresults = resolve(domain, IpAddrType::IPAddrV4Only).unwrap();
        assert!(rresults.iter().all(|item| item.ip_addr().is_ipv4()));
    }

    #[test]
    fn test_resolve_ipv6_only() {
        let domain = unsafe { IPV6_ONLY_TEST_DOMAIN };
        let rresults = resolve(domain, IpAddrType::IPAddrV6Only).unwrap();
        assert!(rresults.iter().all(|item| item.ip_addr().is_ipv6()));
    }

    #[test]
    fn test_resolve_no_accepted_ip() {
        let domain = unsafe { IPV4_ONLY_TEST_DOMAIN };
        let rresults = resolve(domain, IpAddrType::IPAddrV6Only);
        assert!(rresults.is_err() && rresults.err().unwrap().eq("No accepted IP was found."));
    }

    #[test]
    fn test_resolve_single_address() {
        let domain = unsafe { IPV4_ONLY_TEST_DOMAIN };
        let rresult = resolve_single(domain, IpAddrType::IPAddrMixed).unwrap();
        assert!(rresult.ip_addr().is_ipv4());
        assert!(rresult.ttl != Duration::seconds(0));
    }
}
