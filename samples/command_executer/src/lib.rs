pub mod command_parser;
pub mod protocol_helpers;
pub mod utils;

use command_parser::{CommandOutput, ListenArgs, RunArgs};
use protocol_helpers::{recv_len, recv_loop, send_len, send_loop};

use nix::sys::socket::listen as listen_vsock;
use nix::sys::socket::{accept, bind, connect, socket};
use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType};
use std::convert::TryInto;
use std::process::Command;

pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const BUF_MAX_LEN: usize = 8192;
pub const BACKLOG: usize = 128;

pub fn listen(args: ListenArgs) -> Result<(), String> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| format!("Create socket failed: {:?}", err))?;

    let sockaddr = SockAddr::new_vsock(VMADDR_CID_ANY, args.port);

    bind(socket_fd, &sockaddr).map_err(|err| format!("Bind failed: {:?}", err))?;

    listen_vsock(socket_fd, BACKLOG).map_err(|err| format!("Listen failed: {:?}", err))?;

    loop {
        let fd = accept(socket_fd).map_err(|err| format!("Accept failed: {:?}", err))?;

        // recv command
        let len = recv_len(fd)?;
        let mut buf = [0u8; BUF_MAX_LEN];
        recv_loop(fd, &mut buf, len)?;

        let len_usize = len.try_into().map_err(|err| format!("{:?}", err))?;
        let command = String::from(
            std::str::from_utf8(&buf[0..len_usize]).map_err(|err| format!("{:?}", err))?,
        );
        let mut iter = command.split_whitespace();
        let comm = iter.next().unwrap();
        let mut args = Vec::new();
        for token in iter {
            args.push(token);
        }

        // execute command
        let output = Command::new(comm)
            .args(&args)
            .output()
            .map_err(|err| format!("Could not execute the command: {:?}", err))?;

        // send output
        let json_output = serde_json::to_string(&CommandOutput::new(output)?)
            .map_err(|err| format!("Could not serialize the output: {:?}", err))?;
        let buf = json_output.as_bytes();
        let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
        send_len(fd, len, 0)?;
        send_loop(fd, &buf, len)?;
    }
}

pub fn run(args: RunArgs) -> Result<(), String> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| format!("Failed to create the socket: {:?}", err))?;

    let sockaddr = SockAddr::new_vsock(args.cid, args.port);

    connect(socket_fd, &sockaddr).map_err(|err| format!("Connect failed: {}", err))?;

    // send command
    let buf = args.command.as_bytes();
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_len(socket_fd, len, 0)?;
    send_loop(socket_fd, &buf, len)?;

    // recv output
    let mut buf = [0u8; BUF_MAX_LEN];
    let len = recv_len(socket_fd)?;
    recv_loop(socket_fd, &mut buf, len)?;
    let len_usize: usize = len.try_into().map_err(|err| format!("{:?}", err))?;
    let json_output =
        String::from(std::str::from_utf8(&buf[0..len_usize]).map_err(|err| format!("{:?}", err))?);
    println!("{}", json_output);

    Ok(())
}
