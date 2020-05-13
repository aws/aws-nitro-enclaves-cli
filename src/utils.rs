// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use libc::{c_void, close};
use nix::poll::poll;
use nix::poll::{PollFd, PollFlags};
use nix::sys::socket::{connect, socket};
use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType};
use nix::sys::time::{TimeVal, TimeValLike};
use nix::unistd::read;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::thread::sleep;
use std::time::{Duration, SystemTime};

use crate::common::NitroCliResult;

const BUFFER_SIZE: usize = 1024;
const CONSOLE_CONNECT_TIMEOUT: i64 = 20000; // millis
const POLL_TIMEOUT: i32 = 10000; // millis
const SO_VM_SOCKETS_CONNECT_TIMEOUT: i32 = 6;
const TIMEOUT: u64 = 100; // millis

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

/// Set a timeout on a VSock connection.
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

    match ret {
        0 => Ok(()),
        _ => Err(format!(
            "Failed to configure SO_VM_SOCKETS_CONNECT_TIMEOUT: {}",
            ret
        )),
    }
}
