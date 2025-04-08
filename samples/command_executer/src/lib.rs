pub mod command_parser;
pub mod protocol_helpers;
pub mod utils;

use command_parser::{CommandOutput, FileArgs, ListenArgs, RunArgs};
use protocol_helpers::{recv_loop, recv_u64, send_loop, send_u64};

use nix::sys::socket::listen as listen_vsock;
use nix::sys::socket::{accept, bind, connect, shutdown, socket};
use nix::sys::socket::{AddressFamily, Shutdown, SockFlag, SockType, VsockAddr};
use nix::unistd::close;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::cmp::min;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;

pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const BUF_MAX_LEN: usize = 8192;
pub const BACKLOG: usize = 128;
const MAX_CONNECTION_ATTEMPTS: usize = 5;

#[derive(Debug, Clone, FromPrimitive)]
enum CmdId {
    RunCmd = 0,
    RecvFile,
    SendFile,
    RunCmdNoWait,
}

struct VsockSocket {
    socket_fd: RawFd,
}

impl VsockSocket {
    fn new(socket_fd: RawFd) -> Self {
        VsockSocket { socket_fd }
    }
}

impl Drop for VsockSocket {
    fn drop(&mut self) {
        shutdown(self.socket_fd, Shutdown::Both)
            .unwrap_or_else(|e| eprintln!("Failed to shut socket down: {:?}", e));
        close(self.socket_fd).unwrap_or_else(|e| eprintln!("Failed to close socket: {:?}", e));
    }
}

impl AsRawFd for VsockSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket_fd
    }
}

fn vsock_connect(cid: u32, port: u32) -> Result<VsockSocket, String> {
    let sockaddr = VsockAddr::new(cid, port);
    let mut err_msg = String::new();

    for i in 0..MAX_CONNECTION_ATTEMPTS {
        let vsocket = VsockSocket::new(
            socket(
                AddressFamily::Vsock,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .map_err(|err| format!("Failed to create the socket: {:?}", err))?,
        );
        match connect(vsocket.as_raw_fd(), &sockaddr) {
            Ok(_) => return Ok(vsocket),
            Err(e) => err_msg = format!("Failed to connect: {}", e),
        }

        std::thread::sleep(std::time::Duration::from_secs(1 << i));
    }

    Err(err_msg)
}

fn run_server(fd: RawFd, no_wait: bool) -> Result<(), String> {
    // recv command
    let len = recv_u64(fd)?;
    let mut buf = [0u8; BUF_MAX_LEN];
    recv_loop(fd, &mut buf, len)?;

    let len_usize = len.try_into().map_err(|err| format!("{:?}", err))?;
    let command = std::str::from_utf8(&buf[0..len_usize]).map_err(|err| format!("{:?}", err))?;

    // execute command
    let command_output = if no_wait {
        #[rustfmt::skip]
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .spawn();
        if output.is_err() {
            CommandOutput::new(
                String::new(),
                format!("Could not execute the command {}", command),
                1,
            )
        } else {
            CommandOutput::new(String::new(), String::new(), 0)
        }
    } else {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .map_err(|err| format!("Could not execute the command {}: {:?}", command, err))?;
        CommandOutput::new_from(output)?
    };

    // send output
    let json_output = serde_json::to_string(&command_output)
        .map_err(|err| format!("Could not serialize the output: {:?}", err))?;
    let buf = json_output.as_bytes();
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(fd, len)?;
    send_loop(fd, buf, len)?;
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

fn send_file_server(fd: RawFd) -> Result<(), String> {
    // recv file path
    let len = recv_u64(fd)?;
    let mut buf = [0u8; BUF_MAX_LEN];
    recv_loop(fd, &mut buf, len)?;
    let len_usize = len.try_into().map_err(|err| format!("{:?}", err))?;
    let path = std::str::from_utf8(&buf[0..len_usize]).map_err(|err| format!("{:?}", err))?;

    let mut file = File::create(path).map_err(|err| format!("Could not open file {:?}", err))?;

    // Receive filesize
    let filesize = recv_u64(fd)?;
    println!("Receiving file {} - size {}", path, filesize);

    let mut progress: u64 = 0;
    let mut tmpsize: u64;

    while progress < filesize {
        tmpsize = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
        tmpsize = min(tmpsize, filesize - progress);

        recv_loop(fd, &mut buf, tmpsize)?;
        file.write_all(&buf[..tmpsize.try_into().map_err(|err| format!("{:?}", err))?])
            .map_err(|err| format!("Could not write {:?}", err))?;
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

    let sockaddr = VsockAddr::new(VMADDR_CID_ANY, args.port);

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
                if let Err(e) = run_server(fd, false) {
                    eprintln!("Error {}", e);
                }
            }
            CmdId::RecvFile => {
                if let Err(e) = recv_file_server(fd) {
                    eprintln!("Error {}", e);
                }
            }
            CmdId::SendFile => {
                if let Err(e) = send_file_server(fd) {
                    eprintln!("Error {}", e);
                }
            }
            CmdId::RunCmdNoWait => {
                if let Err(e) = run_server(fd, true) {
                    eprintln!("Error {}", e);
                }
            }
        }
    }
}

pub fn run(args: RunArgs) -> Result<i32, String> {
    let vsocket = vsock_connect(args.cid, args.port)?;
    let socket_fd = vsocket.as_raw_fd();

    // Send command id
    if args.no_wait {
        send_u64(socket_fd, CmdId::RunCmdNoWait as u64)?;
    } else {
        send_u64(socket_fd, CmdId::RunCmd as u64)?;
    }

    // send command
    let buf = args.command.as_bytes();
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(socket_fd, len)?;
    send_loop(socket_fd, buf, len)?;

    // recv output
    let mut buf = [0u8; BUF_MAX_LEN];
    let len = recv_u64(socket_fd)?;
    let mut json_output = String::new();
    let mut to_recv = len;
    while to_recv > 0 {
        let recv_len = min(BUF_MAX_LEN as u64, to_recv);
        recv_loop(socket_fd, &mut buf, recv_len)?;
        to_recv -= recv_len;
        let to_recv_usize: usize = recv_len.try_into().map_err(|err| format!("{:?}", err))?;
        json_output.push_str(
            std::str::from_utf8(&buf[0..to_recv_usize]).map_err(|err| format!("{:?}", err))?,
        );
    }

    let output: CommandOutput = serde_json::from_str(json_output.as_str())
        .map_err(|err| format!("Could not deserialize the output: {:?}", err))?;
    print!("{}", output.stdout);
    eprint!("{}", output.stderr);

    Ok(output.rc.unwrap_or_default())
}

pub fn recv_file(args: FileArgs) -> Result<(), String> {
    let mut file = File::create(&args.localfile)
        .map_err(|err| format!("Could not open localfile {:?}", err))?;
    let vsocket = vsock_connect(args.cid, args.port)?;
    let socket_fd = vsocket.as_raw_fd();

    // Send command id
    send_u64(socket_fd, CmdId::RecvFile as u64)?;

    // send remotefile path
    let buf = args.remotefile.as_bytes();
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(socket_fd, len)?;
    send_loop(socket_fd, buf, len)?;

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

pub fn send_file(args: FileArgs) -> Result<(), String> {
    let mut file =
        File::open(&args.localfile).map_err(|err| format!("Could not open localfile {:?}", err))?;
    let vsocket = vsock_connect(args.cid, args.port)?;
    let socket_fd = vsocket.as_raw_fd();

    // Send command id
    send_u64(socket_fd, CmdId::SendFile as u64)?;

    // send remotefile path
    let buf = args.remotefile.as_bytes();
    let len: u64 = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
    send_u64(socket_fd, len)?;
    send_loop(socket_fd, buf, len)?;

    let filesize = file
        .metadata()
        .map_err(|err| format!("Could not get file metadate {:?}", err))?
        .len();

    send_u64(socket_fd, filesize)?;
    println!(
        "Sending file {}(sending to {}) - size {}",
        &args.localfile,
        &args.remotefile[..],
        filesize
    );

    let mut buf = [0u8; BUF_MAX_LEN];
    let mut progress: u64 = 0;
    let mut tmpsize: u64;

    while progress < filesize {
        tmpsize = buf.len().try_into().map_err(|err| format!("{:?}", err))?;
        tmpsize = min(tmpsize, filesize - progress);

        file.read_exact(&mut buf[..tmpsize.try_into().map_err(|err| format!("{:?}", err))?])
            .map_err(|err| format!("Could not read {:?}", err))?;
        send_loop(socket_fd, &buf, tmpsize)?;
        progress += tmpsize
    }

    Ok(())
}
