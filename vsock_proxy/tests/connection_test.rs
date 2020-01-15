// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use nix::sys::socket::sockopt::ReuseAddr;
use nix::sys::socket::{connect, setsockopt, socket};
use nix::sys::socket::{AddressFamily, IpAddr, Ipv4Addr, SockAddr, SockFlag, SockType};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::io::{FromRawFd, RawFd};
use std::str;
use std::sync::mpsc;
use std::{process, thread};

use vsock_proxy::starter::{Proxy, ProxyError};

fn vsock_connect(port: u32) -> Result<RawFd, ProxyError> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|_err| ProxyError::SocketCreationError)?;

    let sockaddr = SockAddr::new_vsock(vsock_proxy::starter::VSOCK_PROXY_CID, port);

    setsockopt(socket_fd, ReuseAddr, &true).map_err(|_err| ProxyError::SetSockOptError)?;

    connect(socket_fd, &sockaddr).map_err(|_err| ProxyError::ConnectError)?;

    Ok(socket_fd)
}

/// Test connection with both client and server sending each other messages
#[test]
fn test_tcp_connection() {
    // Proxy will translate from port 8000 vsock to localhost port 9000 TCP
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let proxy = Proxy::new(
        vsock_proxy::starter::VSOCK_PROXY_PORT,
        addr,
        9000,
        2,
        None,
        false,
        false,
    );

    let (tx, rx) = mpsc::channel();

    // Create a listening TCP server on port 9000
    let server_handle = thread::spawn(move || {
        let server = TcpListener::bind("127.0.0.1:9000").expect("server bind");
        tx.send(true).expect("server send event");
        let (mut stream, _) = server.accept().expect("server accept");

        // Read request
        let mut buf = [0; 13];
        stream.read_exact(&mut buf).expect("server read");
        let msg = str::from_utf8(&buf).expect("from_utf8");
        assert_eq!(msg, "client2server");

        // Write response
        stream.write_all(b"server2client").expect("server write");
    });

    let _ret = rx.recv().expect("main recv event");
    let (tx, rx) = mpsc::channel();

    // Start proxy in a different thread
    let sock = proxy.sock_listen();
    let sock = sock.expect("proxy listen");
    let proxy_handle = thread::spawn(move || {
        tx.send(true).expect("proxy send event");
        let _ret = proxy.sock_accept(sock).expect("proxy accept");
    });

    let _ret = rx.recv().expect("main recv event");

    // Start client that connects to proxy on port 8000 vsock
    let client_handle = thread::spawn(move || {
        let ret = vsock_connect(vsock_proxy::starter::VSOCK_PROXY_PORT);
        if ret.is_err() {
            eprintln!("{:?}", ret.err());
            process::exit(1);
        }
        let mut stream = unsafe { File::from_raw_fd(ret.unwrap()) };

        // Write request
        stream.write_all(b"client2server").expect("client write");

        // Read response
        let mut buf = [0; 13];

        stream.read_exact(&mut buf).expect("client read");
        let msg = str::from_utf8(&buf).expect("from_utf8");
        assert_eq!(msg, "server2client");
    });

    server_handle.join().expect("Server panicked");
    proxy_handle.join().expect("Proxy panicked");
    client_handle.join().expect("Client panicked");
}
