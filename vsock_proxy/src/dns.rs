// Copyright 2019-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]

use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use hickory_resolver::config::{LookupIpStrategy, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::{TokioResolver, MAX_TTL};
use idna::domain_to_ascii;
use log::warn;

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

    /// Same address, fresh timestamp, new TTL. Used to back off after a failed refresh.
    pub fn renew(&self, ttl: Duration) -> Self {
        DnsResolutionInfo {
            ttl,
            last_dns_resolution_time: Utc::now(),
            ..*self
        }
    }
}

/// Builder for a resolver that uses the system DNS configuration.
type ResolverBuilder = hickory_resolver::ResolverBuilder<TokioRuntimeProvider>;

/// Resolve a DNS name (IDNA format) into multiple IP addresses (v4 or v6).
/// Blocks on a local runtime; must not be called from an async context.
pub fn resolve(addr: &str, ip_addr_type: IpAddrType) -> VsockProxyResult<Vec<DnsResolutionInfo>> {
    resolve_with(addr, ip_addr_type, TokioResolver::builder_tokio)
}

/// `resolve` with the system resolver builder supplied by the caller.
fn resolve_with(
    addr: &str,
    ip_addr_type: IpAddrType,
    system_builder: impl FnOnce() -> Result<ResolverBuilder, NetError>,
) -> VsockProxyResult<Vec<DnsResolutionInfo>> {
    // An IP literal needs no resolver and must work on a host without DNS.
    if let Ok(ip_addr) = addr.parse::<IpAddr>() {
        let accepted = match ip_addr_type {
            IpAddrType::IPAddrMixed => true,
            IpAddrType::IPAddrV4Only => ip_addr.is_ipv4(),
            IpAddrType::IPAddrV6Only => ip_addr.is_ipv6(),
        };
        if !accepted {
            return Err("No accepted IP was found.".to_string());
        }
        return Ok(vec![DnsResolutionInfo::new(
            ip_addr,
            Duration::seconds(i64::from(MAX_TTL)),
        )]);
    }

    // IDNA parsing
    let addr = domain_to_ascii(addr).map_err(|_| "Could not parse domain name")?;

    // The resolver is async; run it to completion on a local runtime.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Error while initializing DNS resolver!".to_string())?;

    // DNS lookup using the system's configured nameservers.
    // It results in a vector of IPs (V4 and V6)
    let lookup = runtime.block_on(async {
        // Without a nameserver line in resolv.conf, 0.26 refuses to build a
        // resolver. Fall back to an empty config so /etc/hosts still works.
        let mut builder = system_builder().unwrap_or_else(|e| {
            warn!("Could not use the system DNS config ({e}); using /etc/hosts only.");
            TokioResolver::builder_with_config(
                ResolverConfig::from_parts(None, vec![], vec![]),
                TokioRuntimeProvider::default(),
            )
        });
        // 0.26 defaults to Ipv6AndIpv4; keep the IPv4-first order.
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        let resolver = builder
            .build()
            .map_err(|_| "Error while initializing DNS resolver!".to_string())?;
        resolver
            .lookup_ip(addr)
            .await
            .map_err(|_| "DNS lookup failed!".to_string())
    })?;

    let rresults: Vec<DnsResolutionInfo> = lookup
        .as_lookup()
        .answers()
        .iter()
        .filter_map(|record| {
            let ip_addr = record.data.ip_addr()?;
            let ttl = Duration::seconds(record.ttl as i64);
            Some(DnsResolutionInfo::new(ip_addr, ttl))
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
        .ok_or_else(|| format!("Unable to resolve the DNS name: {addr}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use ctor::ctor;
    use std::env;
    use std::sync::Once;

    static TEST_INIT: Once = Once::new();

    static mut INVALID_TEST_DOMAIN: &str = "invalid-domain";
    static mut IPV4_ONLY_TEST_DOMAIN: &str = "v4.ipv6test.app";
    static mut IPV6_ONLY_TEST_DOMAIN: &str = "v6.ipv6test.app";
    static mut DUAL_IP_TEST_DOMAIN: &str = "ipv6test.app";

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

    /// Stands in for a resolv.conf that hickory rejects.
    fn no_system_config() -> Result<ResolverBuilder, NetError> {
        Err(NetError::from(std::io::Error::other(
            "no nameservers found in config",
        )))
    }

    /// An IP literal must be answered without building a resolver.
    fn no_resolver_for_literal() -> Result<ResolverBuilder, NetError> {
        panic!("resolver built for an IP literal");
    }

    #[test]
    fn test_resolve_ip_literal_builds_no_resolver() {
        let v4 =
            resolve_with("10.0.0.5", IpAddrType::IPAddrMixed, no_resolver_for_literal).unwrap();
        assert_eq!(v4[0].ip_addr(), "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(v4[0].ttl(), Duration::seconds(i64::from(MAX_TTL)));
        assert!(resolve_with("::1", IpAddrType::IPAddrV6Only, no_resolver_for_literal).is_ok());
        let rejected = resolve_with(
            "10.0.0.5",
            IpAddrType::IPAddrV6Only,
            no_resolver_for_literal,
        );
        assert!(rejected.is_err() && rejected.err().unwrap().eq("No accepted IP was found."));
    }

    #[test]
    fn test_resolve_hosts_file_without_system_config() {
        let rresults =
            resolve_with("localhost", IpAddrType::IPAddrMixed, no_system_config).unwrap();
        assert!(rresults.iter().all(|r| r.ip_addr().is_loopback()));
        let missing = resolve_with(
            "no-such-host.invalid",
            IpAddrType::IPAddrMixed,
            no_system_config,
        );
        assert!(missing.is_err() && missing.err().unwrap().eq("DNS lookup failed!"));
    }

    #[test]
    fn test_renew_keeps_address_and_resets_ttl() {
        let ip_addr = "10.0.0.5".parse::<IpAddr>().unwrap();
        let expired = DnsResolutionInfo {
            ip_addr,
            ttl: Duration::seconds(0),
            last_dns_resolution_time: Utc::now() - Duration::seconds(60),
        };
        assert!(expired.is_expired());
        let renewed = expired.renew(Duration::seconds(30));
        assert_eq!(renewed.ip_addr(), ip_addr);
        assert_eq!(renewed.ttl(), Duration::seconds(30));
        assert!(!renewed.is_expired());
    }
}
