// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
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
use std::time::{Duration, Instant, SystemTime};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::new_nitro_cli_failure;

/// The size of the buffers used for reading console data.
const BUFFER_SIZE: usize = 1024;

/// The console connection time-out, in milliseconds.
const CONSOLE_CONNECT_TIMEOUT: i64 = 20000;

/// The `poll` time-out, in milliseconds.
const POLL_TIMEOUT: i32 = 10000;

/// The socket connection time-out flag.
const SO_VM_SOCKETS_CONNECT_TIMEOUT: i32 = 6;

/// The amount of time to wait between consecutive console reads, in milliseconds.
const TIMEOUT: u64 = 100;

/// The structure representing the console of an enclave.
pub struct Console {
    /// The file descriptor used for connecting to the enclave's console.
    fd: RawFd,
}

impl Drop for Console {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl Console {
    /// Create a new blocking `Console` connection from a given enclave CID and a vsock port.
    pub fn new(cid: u32, port: u32) -> NitroCliResult<Self> {
        let socket_fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(|err| {
            new_nitro_cli_failure!(
                &format!("Failed to create blocking console socket: {:?}", err),
                NitroCliErrorEnum::SocketError
            )
        })?;

        let sockaddr = SockAddr::new_vsock(cid, port);

        vsock_set_connect_timeout(socket_fd, CONSOLE_CONNECT_TIMEOUT).map_err(|err| {
            err.add_subaction("Failed to set console connect timeout".to_string())
        })?;

        connect(socket_fd, &sockaddr).map_err(|err| {
            new_nitro_cli_failure!(
                &format!("Failed to connect to the console: {:?}", err),
                NitroCliErrorEnum::EnclaveConsoleConnectionFailure
            )
        })?;

        Ok(Console { fd: socket_fd })
    }

    /// Create a new non-blocking `Console` connection from a given enclave CID and a vsock port.
    pub fn new_nonblocking(cid: u32, port: u32) -> NitroCliResult<Self> {
        // create new non blocking socket
        let socket_fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(|err| {
            new_nitro_cli_failure!(
                &format!("Failed to create nonblocking console socket: {:?}", err),
                NitroCliErrorEnum::SocketError
            )
        })?;

        vsock_set_connect_timeout(socket_fd, CONSOLE_CONNECT_TIMEOUT).map_err(|err| {
            err.add_subaction("Failed to set console connect timeout".to_string())
        })?;

        let sockaddr = SockAddr::new_vsock(cid, port);
        let result = connect(socket_fd, &sockaddr);

        match result {
            Ok(_) => println!("Connected to the console"),
            Err(error) => match error {
                nix::Error::Sys(errno) => {
                    match errno {
                        // If the connection is not ready, wait until socket_fd is ready for writing.
                        nix::errno::Errno::EINPROGRESS => {
                            let poll_fd = PollFd::new(socket_fd, PollFlags::POLLOUT);
                            let mut poll_fds = [poll_fd];
                            match poll(&mut poll_fds, POLL_TIMEOUT) {
                                Ok(1) => println!("Connected to the console"),
                                _ => {
                                    return Err(new_nitro_cli_failure!(
                                        "Failed to connect to the console",
                                        NitroCliErrorEnum::SocketError
                                    ))
                                }
                            }
                        }
                        _ => {
                            return Err(new_nitro_cli_failure!(
                                "Failed to connect to the console",
                                NitroCliErrorEnum::SocketError
                            ))
                        }
                    }
                }
                _ => {
                    return Err(new_nitro_cli_failure!(
                        "Failed to connect to the console",
                        NitroCliErrorEnum::SocketError
                    ))
                }
            },
        };

        Ok(Console { fd: socket_fd })
    }

    /// Read a chunk of raw data from the console and output it.
    pub fn read_to(
        &self,
        output: &mut dyn Write,
        disconnect_timeout_sec: Option<u64>,
    ) -> NitroCliResult<()> {
        // Initialize variables
        let (epoll, mut events, mut epoll_timeout_us, mut start_epoll_time) = (
            Epoll::new().map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to create epoll: {:?}", e),
                    NitroCliErrorEnum::EpollError
                )
            })?,
            [EpollEvent::default(); 1],
            0,
            Instant::now(),
        );

        if disconnect_timeout_sec.is_some() {
            let epoll_event = EpollEvent::new(EventSet::IN, self.fd as u64);
            epoll
                .ctl(ControlOperation::Add, self.fd, epoll_event)
                .map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to add fd to epoll: {:?}", e),
                        NitroCliErrorEnum::EpollError
                    )
                })?;

            // Disconnect timeout in microseconds
            epoll_timeout_us = (disconnect_timeout_sec.unwrap_or(0) * 1000 * 1000) as i128;
        }

        loop {
            if disconnect_timeout_sec.is_some() {
                start_epoll_time = Instant::now();

                // Use epoll_wait to exit the blocking state when the fd is ready to be read
                // or when the disconnect time has passed
                let num_events = epoll
                    .wait((epoll_timeout_us / 1000) as i32, &mut events)
                    .map_err(|e| {
                        new_nitro_cli_failure!(
                            &format!("Failed to wait on epoll: {:?}", e),
                            NitroCliErrorEnum::EpollError
                        )
                    })?;

                // If the timeout expires, no event happend and the console disconnects
                if num_events == 0 {
                    break;
                }
            }

            let mut buffer = [0u8; BUFFER_SIZE];
            let size = read(self.fd, &mut buffer).map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to read data from the console: {:?}", e),
                    NitroCliErrorEnum::EnclaveConsoleReadError
                )
            })?;

            if size == 0 {
                break;
            }

            if size > 0 {
                output.write(&buffer[..size]).map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!(
                            "Failed to write data from the console to the given stream: {:?}",
                            e
                        ),
                        NitroCliErrorEnum::EnclaveConsoleWriteOutputError
                    )
                })?;
            }

            // Account for the read/write/epoll_wait elapsed time
            if disconnect_timeout_sec.is_some() {
                epoll_timeout_us -= start_epoll_time.elapsed().as_micros() as i128;
            }
        }

        Ok(())
    }

    /// Read a chunk of raw data to a buffer.
    pub fn read_to_buffer(&self, buf: &mut Vec<u8>, duration: Duration) -> NitroCliResult<()> {
        let sys_time = SystemTime::now();

        loop {
            let mut buffer = [0u8; BUFFER_SIZE];
            let result = read(self.fd, &mut buffer);

            if let Ok(size) = result {
                if size > 0 {
                    let mut buf_vec = buffer.to_vec();
                    buf_vec.truncate(size);
                    (*buf).append(&mut buf_vec);
                }
            }

            sleep(Duration::from_millis(TIMEOUT));

            let time_elapsed = sys_time.elapsed().map_err(|err| {
                new_nitro_cli_failure!(
                    &format!("System time moved backwards: {:?}", err),
                    NitroCliErrorEnum::ClockSkewError
                )
            })?;

            if time_elapsed >= duration {
                break;
            }
        }

        Ok(())
    }
}

/// Set a timeout on a vsock connection.
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
        _ => Err(new_nitro_cli_failure!(
            &format!(
                "Failed to configure SO_VM_SOCKETS_CONNECT_TIMEOUT: {:?}",
                ret
            ),
            NitroCliErrorEnum::SocketConnectTimeoutError
        )),
    }
}

/// Computes the ceil of `lhs / rhs`. Used for reporting the lower
/// limit of enclave memory based on the EIF file size.
pub fn ceil_div(lhs: u64, rhs: u64) -> u64 {
    if rhs == 0 {
        return std::u64::MAX;
    }

    lhs / rhs
        + match lhs % rhs {
            0 => 0,
            _ => 1,
        }
}
