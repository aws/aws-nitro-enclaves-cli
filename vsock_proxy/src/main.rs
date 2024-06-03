// Copyright 2019-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

/// Simple proxy for translating vsock traffic to TCP traffic
/// Example of usage:
/// vsock-proxy 8000 127.0.0.1 9000
///
use clap::{App, Arg};
use env_logger::init;
use log::info;

use vsock_proxy::{
    proxy::{check_allowlist, Proxy},
    IpAddrType, VsockProxyResult,
};

fn main() -> VsockProxyResult<()> {
    init();

    let matches = App::new("Vsock-TCP proxy")
        .about("Vsock-TCP proxy")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("ipv4")
                .short('4')
                .long("ipv4")
                .help("Force the proxy to use IPv4 addresses only.")
                .required(false),
        )
        .arg(
            Arg::with_name("ipv6")
                .short('6')
                .long("ipv6")
                .help("Force the proxy to use IPv6 addresses only.")
                .required(false)
                .conflicts_with("ipv4"),
        )
        .arg(
            Arg::with_name("workers")
                .short('w')
                .long("num_workers")
                .help("Set the maximum number of simultaneous\nconnections supported.")
                .required(false)
                .takes_value(true)
                .default_value("4"),
        )
        .arg(
            Arg::with_name("local_port")
                .help("Local Vsock port to listen for incoming connections.")
                .required(true),
        )
        .arg(
            Arg::with_name("remote_addr")
                .help("Address of the server to be proxyed.")
                .required(true),
        )
        .arg(
            Arg::with_name("remote_port")
                .help("Remote TCP port of the server to be proxyed.")
                .required(true),
        )
        .arg(
            Arg::with_name("config_file")
                .long("config")
                .help("YAML file containing the services that\ncan be forwarded.\n")
                .required(false)
                .takes_value(true)
                .default_value("/etc/nitro_enclaves/vsock-proxy.yaml"),
        )
        .get_matches();

    let local_port = matches
        .value_of("local_port")
        // This argument is required, so clap ensures it's available
        .unwrap();
    let local_port = local_port
        .parse::<u32>()
        .map_err(|_| "Local port is not valid")?;

    let ipv4_only = matches.is_present("ipv4");
    let ipv6_only = matches.is_present("ipv6");
    let ip_addr_type: IpAddrType = match (ipv4_only, ipv6_only) {
        (true, false) => IpAddrType::IPAddrV4Only,
        (false, true) => IpAddrType::IPAddrV6Only,
        _ => IpAddrType::IPAddrMixed,
    };

    let remote_addr = matches
        .value_of("remote_addr")
        // This argument is required, so clap ensures it's available
        .unwrap();

    let remote_port = matches
        .value_of("remote_port")
        // This argument is required, so clap ensures it's available
        .unwrap();
    let remote_port = remote_port
        .parse::<u16>()
        .map_err(|_| "Remote port is not valid")?;

    let num_workers = matches
        .value_of("workers")
        // This argument has a default value, so it is available
        .unwrap();
    let num_workers = num_workers
        .parse::<usize>()
        .map_err(|_| "Number of workers is not valid")?;

    if num_workers == 0 {
        return Err("Number of workers must not be 0".to_string());
    }

    info!("Checking allowlist configuration");
    let config_file = matches.value_of("config_file");
    let remote_host = String::from(remote_addr);
    let _ = check_allowlist(&remote_host, remote_port, config_file, ip_addr_type)
        .map_err(|err| format!("Error at checking the allowlist: {}", err))?;

    let mut proxy = Proxy::new(
        local_port,
        remote_host,
        remote_port,
        num_workers,
        ip_addr_type,
    )
    .map_err(|err| format!("Could not create proxy: {}", err))?;

    let listener = proxy
        .sock_listen()
        .map_err(|err| format!("Could not listen for connections: {}", err))?;
    info!("Proxy is now in listening state");
    loop {
        proxy
            .sock_accept(&listener)
            .map_err(|err| format!("Could not accept connection: {}", err))?;
    }
}
