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

#[cfg(test)]
mod tests {
    use super::*;

    use ctor::ctor;
    use std::sync::Once;
    use std::env;

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
        assert!(rresults.iter().all(|item| item.ip.is_ipv4()));
    }

    #[test]
    fn test_resolve_ipv6_only() {
        let domain = unsafe { IPV6_ONLY_TEST_DOMAIN };
        let rresults = resolve(domain, IpAddrType::IPAddrV6Only).unwrap();
        assert!(rresults.iter().all(|item| item.ip.is_ipv6()));
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
        assert!(rresult.ip.is_ipv4());
        assert!(rresult.ttl != 0);
    }
}
