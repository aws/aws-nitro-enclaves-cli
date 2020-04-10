// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use crate::NitroCliResult;
use nix::fcntl::{flock, FlockArg};
use nix::poll::poll;
use nix::poll::{PollFd, PollFlags};
use nix::sys::socket::{connect, socket};
use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType};
use nix::unistd::read;
use signal_hook::iterator::Signals;
use signal_hook::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use std::fs::metadata;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::str::FromStr;
use std::thread::{sleep, spawn};
use std::time::{Duration, SystemTime};

use libc::c_void;
use libc::close;
use nix::sys::time::TimeVal;
use nix::sys::time::TimeValLike;
use std::mem::size_of;

pub const BUFFER_SIZE: usize = 1024;
pub const TIMEOUT: u64 = 100; // millis
pub const POLL_TIMEOUT: i32 = 10000; // millis

pub const CONSOLE_CONNECT_TIMEOUT: i64 = 20000; // millis
pub const SO_VM_SOCKETS_CONNECT_TIMEOUT: i32 = 6;

pub trait ExitGracefully<T, E> {
    fn ok_or_exit(self, message: &str) -> T;
}
use log::error;
impl<T, E: std::fmt::Debug> ExitGracefully<T, E> for Result<T, E> {
    fn ok_or_exit(self, message: &str) -> T {
        match self {
            Ok(val) => val,
            Err(err) => {
                error!("{:?}: {}", err, message);
                std::process::exit(1);
            }
        }
    }
}

fn vsock_set_connect_timeout(fd: RawFd, millis: i64) -> NitroCliResult<()> {
    let timeval = TimeVal::milliseconds(millis);
    let ret = unsafe {
        libc::setsockopt(
            fd as i32,
            libc::AF_VSOCK,
            SO_VM_SOCKETS_CONNECT_TIMEOUT,
            &timeval as *const _ as *const c_void,
            size_of::<TimeVal>() as u32,
        )
    };

    if ret != 0 {
        Err("Failed to configure SO_VM_SOCKETS_CONNECT_TIMEOUT timeout".to_string())
    } else {
        Ok(())
    }
}

pub fn handle_signals() {
    let signals =
        Signals::new(&[SIGINT, SIGQUIT, SIGTERM, SIGHUP]).ok_or_exit("Could not handle signals");
    spawn(move || {
        for sig in signals.forever() {
            if sig != SIGHUP {
                eprintln!("Warning! Trying to stop a command could leave the enclave in an unsafe state. If you think something is wrong please use SIGKILL to terminate the command.");
            }
        }
    });
}

pub struct Console {
    fd: RawFd,
}

impl Drop for Console {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl Console {
    pub fn new(cid: u32, port: u32) -> NitroCliResult<Self> {
        let socket_fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(|err| format!("Failed to create blocking console socket: {}", err))?;

        let sockaddr = SockAddr::new_vsock(cid, port);

        vsock_set_connect_timeout(socket_fd, CONSOLE_CONNECT_TIMEOUT)?;

        connect(socket_fd, &sockaddr)
            .map_err(|err| format!("Failed to connect to the console: {}", err))?;

        Ok(Console { fd: socket_fd })
    }

    pub fn new_nonblocking(cid: u32, port: u32) -> NitroCliResult<Self> {
        // create new non blocking socket
        let socket_fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(|err| format!("Failed to create nonblocking console socket: {}", err))?;

        vsock_set_connect_timeout(socket_fd, CONSOLE_CONNECT_TIMEOUT)?;

        let sockaddr = SockAddr::new_vsock(cid, port);

        let result = connect(socket_fd, &sockaddr);

        match result {
            Ok(_) => println!("Connected to the console"),
            Err(error) => match error {
                nix::Error::Sys(errno) => {
                    match errno {
                        // if the connection is not ready, wait until
                        // socket_fd is ready for write
                        nix::errno::Errno::EINPROGRESS => {
                            let poll_fd = PollFd::new(socket_fd, PollFlags::POLLOUT);
                            let mut poll_fds = [poll_fd];
                            match poll(&mut poll_fds, POLL_TIMEOUT) {
                                Ok(1) => println!("Connected to the console"),
                                _ => return Err(String::from("Failed to connect to the console")),
                            }
                        }
                        _ => return Err(String::from("Failed to connect to the console")),
                    }
                }
                _ => return Err(String::from("Failed to connect to the console")),
            },
        };

        Ok(Console { fd: socket_fd })
    }

    pub fn read_to(&self, output: &mut dyn Write) -> NitroCliResult<()> {
        loop {
            let mut buffer = [0u8; BUFFER_SIZE];
            let size = read(self.fd, &mut buffer).map_err(|err| format!("{}", err))?;

            if size == 0 {
                break;
            } else if size > 0 {
                output
                    .write(&buffer[..size])
                    .map_err(|err| format!("{}", err))?;
            }
        }

        Ok(())
    }

    pub fn read_to_buffer(&self, buf: &mut Vec<u8>, duration: Duration) -> NitroCliResult<()> {
        let sys_time = SystemTime::now();

        loop {
            let mut buffer = [0u8; BUFFER_SIZE];
            let result = read(self.fd, &mut buffer);

            match result {
                Ok(size) => {
                    if size > 0 {
                        let mut buf_vec = buffer.to_vec();
                        buf_vec.truncate(size);
                        (*buf).append(&mut buf_vec);
                    }
                }
                _ => (),
            }

            sleep(Duration::from_millis(TIMEOUT));

            if sys_time.elapsed().map_err(|err| format!("{}", err))? >= duration {
                break;
            }
        }

        Ok(())
    }
}

pub struct FileLock {
    pub _file: File,
}

impl FileLock {
    pub fn new(path: &str) -> NitroCliResult<Self> {
        let _file = File::open(path).map_err(|err| format!("{}", err))?;
        let fd = _file.as_raw_fd();
        flock(fd, FlockArg::LockExclusiveNonblock).map_err(|_err| {
            let executable = match std::env::args().next() {
                Some(name) => name,
                None => String::from("./nitro-cli"),
            };
            format!("{} is already running", executable)
        })?;

        Ok(FileLock { _file })
    }
}

pub fn generate_enclave_id(slot_id: u64) -> NitroCliResult<String> {
    let file_path = "/sys/devices/virtual/dmi/id/board_asset_tag";
    if metadata(file_path).is_ok() {
        let mut file = File::open(file_path).map_err(|err| format!("{:?}", err))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|err| format!("{:?}", err))?;
        contents.retain(|c| !c.is_whitespace());
        return Ok(format!("{}_enc{}", contents, slot_id));
    }
    Ok(format!("i-0000000000000000_enc{}", slot_id))
}

pub fn get_slot_id(enclave_id: String) -> Result<u64, String> {
    let tokens: Vec<&str> = enclave_id.split("_enc").collect();

    match tokens.get(1) {
        Some(slot_id) => {
            u64::from_str(*slot_id).map_err(|_err| "Invalid enclave id format".to_string())
        }
        None => Err("Invalid enclave_id.".to_string()),
    }
}
