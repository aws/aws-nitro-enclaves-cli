// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Contains code for Proxy, a library used for translating vsock traffic to
/// TCP traffic
///
use dns_lookup::lookup_host;
use idna;
use log::info;
use nix::sys::select::{select, FdSet};
use nix::sys::socket::sockopt::ReuseAddr;
use nix::sys::socket::IpAddr as NixIpAddr;
use nix::sys::socket::{accept, bind, connect, listen, setsockopt, socket};
use nix::sys::socket::{AddressFamily, InetAddr, SockAddr, SockFlag, SockType};
use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr as StdIpAddr;
use std::os::unix::io::{FromRawFd, RawFd};
use threadpool::ThreadPool;
use yaml_rust::YamlLoader;

const BUFF_SIZE: usize = 8192;
pub const VSOCK_PROXY_CID: u32 = 3;
pub const VSOCK_PROXY_PORT: u32 = 8000;

#[derive(Debug, PartialEq)]
/// Internal errors while setting up proxy
pub enum ProxyError {
    SocketCreationError,
    SetSockOptError,
    BindError,
    ListenError,
    AcceptError,
    ConnectError,
    IOError,
    SelectError,
    WhitelistError,
    NoValidIPError,
    OpenFileError,
    ReadFileError,
    YamlFormatError,
    RemoteAddressError,
    DomainError,
}

/// Checks if the forwarded server is whitelisted
pub fn check_whitelist(
    remote_addr: NixIpAddr,
    remote_port: u16,
    config_file: Option<&str>,
    only_4: bool,
    only_6: bool,
) -> Result<(), ProxyError> {
    if let Some(config_file) = config_file {
        let mut f = File::open(config_file).map_err(|_err| ProxyError::OpenFileError)?;

        let mut content = String::new();
        f.read_to_string(&mut content)
            .map_err(|_err| ProxyError::ReadFileError)?;

        let docs =
            YamlLoader::load_from_str(&content).map_err(|_err| ProxyError::YamlFormatError)?;
        let services = (&docs[0])["whitelist"]
            .as_vec()
            .ok_or_else(|| ProxyError::YamlFormatError)?;

        for raw_service in services {
            let port = raw_service["port"]
                .as_i64()
                .ok_or_else(|| ProxyError::YamlFormatError)?;
            let port = port as u16;

            let addr = raw_service["address"]
                .as_str()
                .ok_or_else(|| ProxyError::YamlFormatError)?;
            let addrs = Proxy::parse_addr(addr, only_4, only_6)?;
            for addr in addrs.into_iter() {
                if addr == remote_addr && port == remote_port {
                    return Ok(());
                }
            }
        }
    }
    Err(ProxyError::WhitelistError)
}

/// Configuration parameters for port listening and remote destination
pub struct Proxy {
    local_port: u32,
    remote_addr: NixIpAddr,
    remote_port: u16,
    pool: ThreadPool,
    sock_type: SockType,
}

impl Proxy {
    pub fn new(
        local_port: u32,
        remote_addr: NixIpAddr,
        remote_port: u16,
        num_workers: usize,
        config_file: Option<&str>,
        only_4: bool,
        only_6: bool,
    ) -> Self {
        info!("Checking whitelist configuration");
        check_whitelist(remote_addr, remote_port, config_file, only_4, only_6)
            .expect("The service provided is not whitelisted");

        let pool = ThreadPool::new(num_workers);
        let sock_type = SockType::Stream;
        Proxy {
            local_port,
            remote_addr,
            remote_port,
            pool,
            sock_type,
        }
    }

    /// Resolve a DNS name (IDNA format) into an IP address (v4 or v6)
    pub fn parse_addr(
        addr: &str,
        only_4: bool,
        only_6: bool,
    ) -> Result<Vec<NixIpAddr>, ProxyError> {
        // IDNA parsing
        let addr = idna::domain_to_ascii(&addr).map_err(|_err| ProxyError::DomainError)?;

        // DNS lookup
        // It results in a vector of IPs (V4 and V6)
        let ips = lookup_host(&addr).map_err(|_err| ProxyError::RemoteAddressError)?;

        if ips.len() == 0 {
            return Err(ProxyError::NoValidIPError);
        }

        // If there is no restriction, choose randomly
        if !only_4 && !only_6 {
            return Ok(ips.into_iter().map(|ip| NixIpAddr::from_std(&ip)).collect());
        }

        // Split the IPs in v4 and v6
        let (ips_v4, ips_v6): (Vec<_>, Vec<_>) = ips.into_iter().partition(StdIpAddr::is_ipv4);

        if only_4 && ips_v4.len() != 0 {
            return Ok(ips_v4
                .into_iter()
                .map(|ip| NixIpAddr::from_std(&ip))
                .collect());
        } else if only_6 && ips_v6.len() != 0 {
            return Ok(ips_v6
                .into_iter()
                .map(|ip| NixIpAddr::from_std(&ip))
                .collect());
        } else {
            return Err(ProxyError::NoValidIPError);
        }
    }

    /// Creates a listening socket
    /// Returns the file descriptor for it or the appropriate error
    pub fn sock_listen(&self) -> Result<RawFd, ProxyError> {
        let socket_fd = socket(
            AddressFamily::Vsock,
            self.sock_type,
            SockFlag::empty(),
            None,
        )
        .map_err(|_err| ProxyError::SocketCreationError)?;

        let sockaddr = SockAddr::new_vsock(VSOCK_PROXY_CID, self.local_port);

        setsockopt(socket_fd, ReuseAddr, &true).map_err(|_err| ProxyError::SetSockOptError)?;

        bind(socket_fd, &sockaddr).map_err(|_err| ProxyError::BindError)?;
        info!("Binded to {:?}", sockaddr);

        listen(socket_fd, 5).map_err(|_err| ProxyError::ListenError)?;

        Ok(socket_fd)
    }

    /// Accepts an incoming connection coming on socked_fd and handles it on a
    /// different thread
    /// Returns the handle for the new thread or the appropriate error
    pub fn sock_accept(&self, socket_fd: RawFd) -> Result<(), ProxyError> {
        let vsock_sock = accept(socket_fd).map_err(|_err| ProxyError::AcceptError)?;
        info!("Accepted connection on fd {:?}", vsock_sock);

        let addr = InetAddr::new(self.remote_addr, self.remote_port);
        let sockaddr = SockAddr::new_inet(addr);
        let sock_type = self.sock_type;
        self.pool.execute(move || {
            let tcp_sock =
                socket(AddressFamily::Inet, sock_type, SockFlag::empty(), None).expect("socket");

            connect(tcp_sock, &sockaddr).expect("connect");
            info!(
                "Connected client on fd {:?} to {:?}",
                vsock_sock,
                sockaddr.to_str()
            );

            let client_clone = vsock_sock.clone();
            let server_clone = tcp_sock.clone();

            let mut client = unsafe { File::from_raw_fd(vsock_sock) };
            let mut server = unsafe { File::from_raw_fd(tcp_sock) };

            let mut disconnected = false;
            while !disconnected {
                let mut set = FdSet::new();
                set.insert(client_clone);
                set.insert(server_clone);

                select(None, Some(&mut set), None, None, None).expect("select");

                if set.contains(client_clone) {
                    disconnected = transfer(&mut client, &mut server);
                }
                if set.contains(server_clone) {
                    disconnected = transfer(&mut server, &mut client);
                }
            }
            info!("Client on fd {:?} disconnected", vsock_sock);
        });

        Ok(())
    }
}

/// Transfers a chunck of maximum 4KB from src to dst
/// If no error occurs, returns true if the source disconnects and false otherwise
fn transfer(src: &mut dyn Read, dst: &mut dyn Write) -> bool {
    let mut buffer = [0u8; BUFF_SIZE];

    let nbytes = src.read(&mut buffer);
    let nbytes = match nbytes {
        Err(_) => 0,
        Ok(n) => n,
    };

    if nbytes == 0 {
        return true;
    }

    if let Err(_) = dst.write_all(&buffer[..nbytes]) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use rand;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::process::Command;

    use super::*;

    /// Test transfer function with more data than buffer
    #[test]
    fn test_transfer() {
        let data: Vec<u8> = (0..2 * BUFF_SIZE).map(|_| rand::random::<u8>()).collect();

        let _ret = fs::create_dir("tmp");
        let mut src = File::create("tmp/src").unwrap();
        let mut dst = File::create("tmp/dst").unwrap();

        let _ret = src.write_all(&data);

        let mut src = File::open("tmp/src").unwrap();
        while !transfer(&mut src, &mut dst) {}

        let status = Command::new("cmp")
            .arg("tmp/src")
            .arg("tmp/dst")
            .status()
            .expect("command");

        let _ret = fs::remove_dir_all("tmp");

        assert!(status.success());
    }
}
