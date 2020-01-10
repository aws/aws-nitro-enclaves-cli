pub mod command_parser;
pub mod protocol_helpers;
pub mod utils;

use command_parser::{CommandOutput, ListenArgs, RecvFileArgs, RunArgs};
use protocol_helpers::{recv_loop, recv_u64, send_loop, send_u64};

use nix::sys::socket::listen as listen_vsock;
use nix::sys::socket::{accept, bind, connect, socket};
use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::cmp::min;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::RawFd;
use std::process::Command;

pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const BUF_MAX_LEN: usize = 8192;
pub const BACKLOG: usize = 128;

#[derive(Debug, Clone, FromPrimitive)]
enum CmdId {
    RunCmd = 0,
    RecvFile,
}

fn run_server(fd: RawFd) -> Result<(), String> {
    // recv command
    let len = recv_u64(fd)?;
    let mut buf = [0u8; BUF_MAX_LEN];
    recv_loop(fd, &mut buf, len)?;

    let len_usize = len.try_into().map_err(|err| format!("{:?}", err))?;
    let command = std::str::from_utf8(&buf[0..len_usize]).map_err(|err| format!("{:?}", err))?;

    // execute command
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|err| format!("Could not execute the command: {:?}", err))?;

    // send output
    let json_output = serde_json::to_string(&CommandOutput::new(output)?)
        .map_err(|err| format!("Could not serialize the output: {:?}", err))?;
    let buf = json_output.as_bytes();
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(fd, len)?;
    send_loop(fd, &buf, len)?;
    Ok(())
}

fn recv_file_server(fd: RawFd) -> Result<(), String> {
    // recv file path
    let len = recv_u64(fd)?;
    let mut buf = [0u8; BUF_MAX_LEN];
    recv_loop(fd, &mut buf, len)?;
    let len_usize = len.try_into().map_err(|err| format!("{:?}", err))?;
    let path = std::str::from_utf8(&buf[0..len_usize]).map_err(|err| format!("{:?}", err))?;

    let mut file = File::open(path).map_err(|err| format!("Could not open file {:?}", err))?;

    let filesize = file
        .metadata()
        .map_err(|err| format!("Could not get file metadata {:?}", err))?
        .len();

    send_u64(fd, filesize)?;
    println!("Sending file {} - size {}", path, filesize);

    let mut progress: u64 = 0;
    let mut tmpsize: u64;

    while progress < filesize {
        tmpsize = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
        tmpsize = min(tmpsize, filesize - progress);

        file.read_exact(&mut buf[..tmpsize.try_into().map_err(|err| format!("{:?}", err))?])
            .map_err(|err| format!("Could not read {:?}", err))?;
        send_loop(fd, &buf, tmpsize)?;
        progress += tmpsize
    }

    Ok(())
}

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

        //cmd id
        let cmdid = match recv_u64(fd) {
            Ok(id_u64) => match CmdId::from_u64(id_u64) {
                Some(c) => c,
                _ => {
                    eprintln!("Error no such command");
                    continue;
                }
            },
            Err(e) => {
                eprintln!("Error {}", e);
                continue;
            }
        };

        match cmdid {
            CmdId::RunCmd => {
                if let Err(e) = run_server(fd) {
                    eprintln!("Error {}", e);
                }
            }
            CmdId::RecvFile => {
                if let Err(e) = recv_file_server(fd) {
                    eprintln!("Error {}", e);
                }
            }
        }
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

    // Send command id
    send_u64(socket_fd, CmdId::RunCmd as u64)?;

    // send command
    let buf = args.command.as_bytes();
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(socket_fd, len)?;
    send_loop(socket_fd, &buf, len)?;

    // recv output
    let mut buf = [0u8; BUF_MAX_LEN];
    let len = recv_u64(socket_fd)?;
    recv_loop(socket_fd, &mut buf, len)?;
    let len_usize: usize = len.try_into().map_err(|err| format!("{:?}", err))?;
    let json_output =
        String::from(std::str::from_utf8(&buf[0..len_usize]).map_err(|err| format!("{:?}", err))?);
    println!("{}", json_output);

    Ok(())
}

pub fn recv_file(args: RecvFileArgs) -> Result<(), String> {
    let mut file = File::create(&args.localfile)
        .map_err(|err| format!("Could not open localfile {:?}", err))?;

    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| format!("Failed to create the socket: {:?}", err))?;

    let sockaddr = SockAddr::new_vsock(args.cid, args.port);

    connect(socket_fd, &sockaddr).map_err(|err| format!("Connect failed: {}", err))?;

    // Send command id
    send_u64(socket_fd, CmdId::RecvFile as u64)?;

    // send remotefile path
    let buf = args.remotefile.as_bytes();
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(socket_fd, len)?;
    send_loop(socket_fd, &buf, len)?;

    // Receive filesize
    let filesize = recv_u64(socket_fd)?;
    println!(
        "Receiving file {}(saving to {}) - size {}",
        &args.remotefile,
        &args.localfile[..],
        filesize
    );

    let mut progress: u64 = 0;
    let mut tmpsize: u64;
    let mut buf = [0u8; BUF_MAX_LEN];

    while progress < filesize {
        tmpsize = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
        tmpsize = min(tmpsize, filesize - progress);

        recv_loop(socket_fd, &mut buf, tmpsize)?;
        file.write_all(&buf[..tmpsize.try_into().map_err(|err| format!("{:?}", err))?])
            .map_err(|err| format!("Could not write {:?}", err))?;
        progress += tmpsize
    }
    Ok(())
}
