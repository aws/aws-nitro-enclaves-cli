// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use log::{debug, info, warn};
use nix::sys::epoll::{self, EpollEvent, EpollFlags, EpollOp};
use std::fs::set_permissions;
use std::fs::Permissions;
use std::io;

#[cfg(test)]
use std::os::raw::c_char;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread::{self, JoinHandle};

use super::connection::Connection;
use super::socket::EnclaveProcSock;
use crate::common::commands_parser::EmptyArgs;
use crate::common::{enclave_proc_command_send_single, receive_from_stream};
use crate::common::{
    EnclaveProcessCommandType, ExitGracefully, NitroCliErrorEnum, NitroCliFailure, NitroCliResult,
};
use crate::new_nitro_cli_failure;

/// A listener which waits for incoming connections on the enclave process socket.
#[derive(Default)]
pub struct ConnectionListener {
    /// The epoll descriptor used to register new connections.
    epoll_fd: RawFd,
    /// A dedicated thread that listens for new connections.
    listener_thread: Option<JoinHandle<()>>,
    /// The Unix socket that the listener binds to.
    socket: EnclaveProcSock,
}

/// The listener must be cloned when launching the listening thread.
impl Clone for ConnectionListener {
    fn clone(&self) -> Self {
        // Actually clone only what's relevant for the listening thread.
        ConnectionListener {
            epoll_fd: self.epoll_fd,
            listener_thread: None,
            socket: self.socket.clone(),
        }
    }
}

impl ConnectionListener {
    /// Create a new `ConnectionListener` instance.
    pub fn new() -> NitroCliResult<Self> {
        Ok(ConnectionListener {
            epoll_fd: epoll::epoll_create().map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to initialize epoll: {:?}", e),
                    NitroCliErrorEnum::EpollError
                )
            })?,
            listener_thread: None,
            socket: EnclaveProcSock::default(),
        })
    }

    /// Expose the `epoll` descriptor.
    pub fn get_epoll_fd(&self) -> RawFd {
        self.epoll_fd
    }

    /// Initialize the connection listener from a specified enclave ID.
    pub fn start(&mut self, enclave_id: &str) -> NitroCliResult<()> {
        // Obtain the socket to listen on.
        self.socket = EnclaveProcSock::new(enclave_id)
            .map_err(|e| e.add_subaction("Failed to create enclave process socket".to_string()))?;

        // Bind the listener to the socket and spawn the listener thread.
        let listener = UnixListener::bind(self.socket.get_path()).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to bind connection listener: {:?}", e),
                NitroCliErrorEnum::SocketError
            )
        })?;
        self.enable_credentials_passing(&listener);
        self.socket
            .start_monitoring(true)
            .map_err(|e| e.add_subaction("Failed to start monitoring socket".to_string()))?;
        debug!(
            "Connection listener started on socket {:?}.",
            self.socket.get_path()
        );

        let self_clone = self.clone();
        self.listener_thread = Some(thread::spawn(move || {
            self_clone
                .connection_listener_run(listener)
                .map_err(|e| {
                    e.add_subaction("Failed to start the listener thread".to_string())
                        .set_action("Run Enclave".to_string())
                })
                .ok_or_exit_with_errno(None);
        }));

        Ok(())
    }

    /// Add a stream to `epoll`.
    pub fn add_stream_to_epoll(&self, stream: UnixStream) -> NitroCliResult<()> {
        let stream_fd = stream.as_raw_fd();
        let mut cli_evt = EpollEvent::new(EpollFlags::EPOLLIN, stream.into_raw_fd() as u64);
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlAdd, stream_fd, &mut cli_evt).map_err(
            |e| {
                new_nitro_cli_failure!(
                    &format!("Failed to add stream to epoll: {:?}", e),
                    NitroCliErrorEnum::EpollError
                )
            },
        )?;

        Ok(())
    }

    /// Add the enclave descriptor to `epoll`.
    pub fn register_enclave_descriptor(&mut self, enc_fd: RawFd) -> NitroCliResult<()> {
        let mut enc_event = EpollEvent::new(
            EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
            enc_fd as u64,
        );
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlAdd, enc_fd, &mut enc_event).map_err(
            |e| {
                new_nitro_cli_failure!(
                    &format!("Failed to add enclave descriptor to epoll: {:?}", e),
                    NitroCliErrorEnum::EpollError
                )
            },
        )?;

        Ok(())
    }

    /// Handle an incoming connection.
    pub fn handle_new_connection(
        &self,
        mut stream: UnixStream,
    ) -> NitroCliResult<EnclaveProcessCommandType> {
        let cmd_type =
            receive_from_stream::<EnclaveProcessCommandType>(&mut stream).map_err(|e| {
                e.add_subaction("Failed to receive command type from stream".to_string())
            })?;

        // All connections must be registered with epoll, with the exception of the shutdown one.
        if cmd_type != EnclaveProcessCommandType::ConnectionListenerStop {
            self.add_stream_to_epoll(stream)
                .map_err(|e| e.add_subaction("Failed to add stream to epoll".to_string()))?;
        }

        Ok(cmd_type)
    }

    /// Listen for incoming connections and handle them as they appear.
    fn connection_listener_run(self, listener: UnixListener) -> NitroCliResult<()> {
        // Accept connections and process them (this is a blocking call).
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // Received a new connection. Shut down if required.
                    let cmd = self.handle_new_connection(stream);
                    if let Ok(cmd) = cmd {
                        if cmd == EnclaveProcessCommandType::ConnectionListenerStop {
                            break;
                        }
                    }
                }
                Err(err) => {
                    // Connection failed.
                    warn!("Connection error: {:?}", err);
                    break;
                }
            }
        }

        // Remove the listener's socket.
        self.socket
            .close()
            .map_err(|e| e.add_subaction("Failed to close socket".to_string()))?;
        debug!("Connection listener has finished.");
        Ok(())
    }

    /// Terminate the connection listener.
    pub fn stop(&mut self) -> NitroCliResult<()> {
        // Nothing to do if the connection listener thread has not been started.
        if self.listener_thread.is_none() {
            return Ok(());
        }

        // Send termination notification to the listener thread.
        let mut self_conn = UnixStream::connect(self.socket.get_path()).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to connect to listener thread: {:?}", e),
                NitroCliErrorEnum::SocketError
            )
        })?;
        enclave_proc_command_send_single::<EmptyArgs>(
            EnclaveProcessCommandType::ConnectionListenerStop,
            None,
            &mut self_conn,
        )
        .map_err(|e| e.add_subaction("Failed to notify listener thread of shutdown".to_string()))?;

        // Shut the connection down.
        self_conn.shutdown(std::net::Shutdown::Both).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to close connection: {:?}", e),
                NitroCliErrorEnum::SocketCloseError
            )
        })?;

        // Ensure that the listener thread has terminated.
        self.listener_thread.take().unwrap().join().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to join listener thread: {:?}", e),
                NitroCliErrorEnum::ThreadJoinFailure
            )
        })?;
        info!("The connection listener has been stopped.");

        Ok(())
    }

    /// Fetch the next available connection.
    pub fn get_next_connection(&self, enc_fd: Option<RawFd>) -> NitroCliResult<Connection> {
        // Wait on epoll until a valid event is received.
        let mut events = [EpollEvent::empty(); 1];
        loop {
            match epoll::epoll_wait(self.epoll_fd, &mut events, -1) {
                Ok(_) => break,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    return Err(new_nitro_cli_failure!(
                        &format!("Failed to wait on epoll: {:?}", e),
                        NitroCliErrorEnum::EpollError
                    ))
                }
            }
        }

        let fd = events[0].data() as RawFd;
        let input_stream = match enc_fd {
            // This is a connection to an enclave.
            Some(enc_fd) if enc_fd == fd => None,
            // This is a connection to a CLI instance or to ourselves.
            _ => Some(unsafe { UnixStream::from_raw_fd(fd) }),
        };

        // Remove the fetched descriptor from epoll. We are doing this here since
        // otherwise the Connection would have to do it when dropped and we prefer
        // the Connection not touch epoll directly.
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlDel, fd, None).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to remove descriptor from epoll: {:?}", e),
                NitroCliErrorEnum::EpollError
            )
        })?;

        Ok(Connection::new(events[0].events(), input_stream))
    }

    /// Enable the sending of credentials from incoming connections.
    fn enable_credentials_passing(&self, listener: &UnixListener) {
        let val: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                &val as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if rc < 0 {
            warn!(
                "Failed to enable credentials passing on socket listener: {}",
                io::Error::last_os_error()
            );
        }

        // Since access policy is handled within the enclave process explicitly, we
        // allow full access to the socket itself (otherwise other users will not
        // be allowed to connect to the socket in the first place).
        if let Ok(sock_addr) = listener.local_addr() {
            if let Some(sock_path) = sock_addr.as_pathname() {
                let perms = Permissions::from_mode(0o766);
                if let Err(e) = set_permissions(sock_path, perms) {
                    warn!("Failed to update socket permissions: {}", e);
                }
            } else {
                warn!("Failed to get the listener's socket path.");
            }
        } else {
            warn!("Failed to get the socket listener's local address.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::{get_sockets_dir_path, SOCKETS_DIR_PATH_ENV_VAR};

    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, Condvar, Mutex};

    const THREADS_STR: &str = "Threads:";
    const TMP_DIR: &str = "./npe";

    fn unset_envvar(varname: &str) {
        unsafe { libc::unsetenv(varname.as_ptr() as *const c_char) };
    }

    /// Inspects the content of /proc/<PID>/status in order to
    /// retrieve the number of threads running in the context of
    /// process <PID>.
    fn get_num_threads_from_status_output(status_str: String) -> u32 {
        let start_idx = status_str.find(THREADS_STR);
        let mut iter = status_str.chars();
        iter.by_ref().nth(start_idx.unwrap() + THREADS_STR.len()); // skip "Threads:\t"
        let slice = iter.as_str();

        let new_str = slice.to_string();
        let end_idx = new_str.find('\n'); // skip after the first '\n'
        let substr = &slice[..end_idx.unwrap()];

        substr.parse().unwrap()
    }

    /// Tests that get_epoll_fd() returns the expected epoll_fd.
    #[test]
    fn test_get_epoll_fd() {
        let connection_listener = ConnectionListener::new().unwrap();
        let epoll_fd = connection_listener.epoll_fd;

        assert_eq!(epoll_fd, connection_listener.get_epoll_fd());
    }

    /// Tests that new connections are monitored and that a command
    /// sent through the connection is received correctly.
    #[test]
    fn test_handle_new_connection() {
        let (mut sock0, sock1) = UnixStream::pair().unwrap();

        let connection_listener = ConnectionListener::new().unwrap();

        let cmd = EnclaveProcessCommandType::Describe;
        let _ = enclave_proc_command_send_single::<EmptyArgs>(cmd, None, &mut sock0);

        let result = connection_listener.handle_new_connection(sock1);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EnclaveProcessCommandType::Describe);
    }

    /// Test that add_stream_to_epoll registers a sockfd and that next subsequent
    /// attempts to register the same sockfd fail (since the sockfd is already registered
    /// once).
    #[test]
    fn test_add_stream_to_epoll() {
        let (_, sock1) = UnixStream::pair().unwrap();

        let connection_listener = ConnectionListener::new().unwrap();
        let copy_sock1 = sock1.try_clone();

        if let Ok(copy_sock1) = copy_sock1 {
            let mut cli_evt = EpollEvent::new(EpollFlags::EPOLLIN, copy_sock1.into_raw_fd() as u64);
            let _ = epoll::epoll_ctl(
                connection_listener.epoll_fd,
                EpollOp::EpollCtlAdd,
                sock1.as_raw_fd(),
                &mut cli_evt,
            );
            // Second add should return Err(Sys(EEXIST)), as sock1 is already registed
            // with connection_listener.epoll_fd
            let result = epoll::epoll_ctl(
                connection_listener.epoll_fd,
                EpollOp::EpollCtlAdd,
                sock1.as_raw_fd(),
                &mut cli_evt,
            );

            assert!(result.is_err());
        }
    }

    /// Test that connection_listener_run closes a previously-spawned thread when
    /// processing a ConnectionListenerStop command.
    #[test]
    fn test_connection_listener_run_connection_stop() {
        let old_log_path = env::var(SOCKETS_DIR_PATH_ENV_VAR);

        env::set_var(SOCKETS_DIR_PATH_ENV_VAR, TMP_DIR);

        let resources_dir = get_sockets_dir_path();

        let path_existed = resources_dir.as_path().exists();
        let _ = fs::create_dir(resources_dir.as_path());
        let dummy_sock_name = "run_connection_stop.sock";
        let dummy_sock_path = format!(
            "{}/{}",
            resources_dir.as_path().to_str().unwrap(),
            dummy_sock_name
        );

        // Remove pre-existing socket file
        let _ = std::fs::remove_file(&dummy_sock_path);

        let mut connection_listener = ConnectionListener::new().unwrap();
        connection_listener
            .socket
            .set_path(PathBuf::from(&dummy_sock_path));

        // Get number of running threads before spawning the listener thread
        let out_cmd0 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out0 = std::str::from_utf8(&out_cmd0.stdout).unwrap();
        let crt_num_threads0 = get_num_threads_from_status_output(out0.to_string());

        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let pair2 = pair.clone();

        let listener_thread = thread::spawn(move || {
            {
                let (lock, cvar) = &*pair2;
                let mut started = lock.lock().unwrap();
                *started = true;
                cvar.notify_one();
            }

            // Bind the listener to the socket and spawn the listener thread.
            let listener = UnixListener::bind(connection_listener.socket.get_path())
                .map_err(|e| format!("Failed to bind connection listener: {:?}", e))
                .unwrap();
            connection_listener.enable_credentials_passing(&listener);
            connection_listener
                .socket
                .start_monitoring(true)
                .map_err(|e| format!("Failed to start socket monitoring: {:?}", e))
                .unwrap();

            let res = connection_listener.connection_listener_run(listener);
            assert!(res.is_ok());
        });

        // Allow thread to finish spawning
        let (lock, cvar) = &*pair;
        let mut started = lock.lock().unwrap();
        while !*started {
            started = cvar.wait(started).unwrap();
        }

        // Check that the listener thread is running
        let out_cmd1 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out1 = std::str::from_utf8(&out_cmd1.stdout).unwrap();
        let crt_num_threads1 = get_num_threads_from_status_output(out1.to_string());
        assert!(crt_num_threads0 < crt_num_threads1);

        let my_stream = UnixStream::connect(&dummy_sock_path);

        if let Ok(mut my_stream) = my_stream {
            // Close the listener thread
            let cmd = EnclaveProcessCommandType::ConnectionListenerStop;
            let _ = enclave_proc_command_send_single::<EmptyArgs>(cmd, None, &mut my_stream);
        }

        // Wait for thread to join after exiting
        listener_thread
            .join()
            .expect("Failed to join on the associated thread");

        // Check number of threads after closing the listener thread
        let out_cmd2 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out2 = std::str::from_utf8(&out_cmd2.stdout).unwrap();
        let crt_num_threads2 = get_num_threads_from_status_output(out2.to_string());
        assert_eq!(crt_num_threads0, crt_num_threads2);
        assert!(crt_num_threads2 < crt_num_threads1);

        if !path_existed {
            // Remove whole resources_dir
            let _ = fs::remove_dir_all(resources_dir.as_path().to_str().unwrap());
        } else {
            // Only remove the socket file
            let _ = fs::remove_file(&dummy_sock_path);
        }

        // Restore previous environment variable value
        if let Ok(old_log_path) = old_log_path {
            env::set_var(SOCKETS_DIR_PATH_ENV_VAR, old_log_path);
        } else {
            env::set_var(SOCKETS_DIR_PATH_ENV_VAR, "");
            unset_envvar(&String::from(SOCKETS_DIR_PATH_ENV_VAR));
        }
    }

    /// Test that connection_listener_run closes a previously-spawned thread when
    /// processing a ConnectionListenerStop command.
    #[test]
    fn test_connection_listener_run_describe() {
        let old_log_path = env::var(SOCKETS_DIR_PATH_ENV_VAR);

        env::set_var(SOCKETS_DIR_PATH_ENV_VAR, TMP_DIR);

        let resources_dir = get_sockets_dir_path();
        let path_existed = resources_dir.as_path().exists();

        let _ = fs::create_dir(resources_dir.as_path());

        let dummy_sock_name = "run_describe.sock";
        let dummy_sock_path = format!(
            "{}/{}",
            resources_dir.as_path().to_str().unwrap(),
            dummy_sock_name
        );

        // Remove pre-existing socket file
        let _ = std::fs::remove_file(&dummy_sock_path);

        let mut connection_listener = ConnectionListener::new().unwrap();
        connection_listener
            .socket
            .set_path(PathBuf::from(&dummy_sock_path));

        // Get number of running threads before spawning the listener thread
        let out_cmd0 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out0 = std::str::from_utf8(&out_cmd0.stdout).unwrap();
        let crt_num_threads0 = get_num_threads_from_status_output(out0.to_string());

        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let pair2 = pair.clone();

        let conn_clone = connection_listener.clone();
        let listener_thread = thread::spawn(move || {
            {
                let (lock, cvar) = &*pair2;
                let mut started = lock.lock().unwrap();
                *started = true;
                cvar.notify_one();
            }

            // Bind the listener to the socket and spawn the listener thread.
            let listener = UnixListener::bind(connection_listener.socket.get_path())
                .map_err(|e| format!("Failed to bind connection listener: {:?}", e))
                .unwrap();
            connection_listener.enable_credentials_passing(&listener);
            connection_listener
                .socket
                .start_monitoring(true)
                .map_err(|e| format!("Failed to start socket monitoring: {:?}", e))
                .unwrap();

            conn_clone.connection_listener_run(listener).unwrap();
        });

        // Allow thread to finish spawning
        let (lock, cvar) = &*pair;
        let mut started = lock.lock().unwrap();
        while !*started {
            started = cvar.wait(started).unwrap();
        }

        // Check that the listener thread is running
        let out_cmd1 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out1 = std::str::from_utf8(&out_cmd1.stdout).unwrap();
        let crt_num_threads1 = get_num_threads_from_status_output(out1.to_string());
        assert!(crt_num_threads0 < crt_num_threads1);

        let my_stream = UnixStream::connect(&dummy_sock_path);

        if let Ok(mut my_stream) = my_stream {
            // Run a command other than ConnectionListenerStop
            let cmd = EnclaveProcessCommandType::Describe;
            let _ = enclave_proc_command_send_single::<EmptyArgs>(cmd, None, &mut my_stream);
        }

        // Check that the listener thread is still running
        let out_cmd2 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out2 = std::str::from_utf8(&out_cmd2.stdout).unwrap();
        let crt_num_threads2 = get_num_threads_from_status_output(out2.to_string());
        assert!(crt_num_threads0 < crt_num_threads2);

        let my_stream = UnixStream::connect(&dummy_sock_path);

        if let Ok(mut my_stream) = my_stream {
            // Close the listener thread
            let cmd = EnclaveProcessCommandType::ConnectionListenerStop;
            let _ = enclave_proc_command_send_single::<EmptyArgs>(cmd, None, &mut my_stream);

            // Wait for the thread to join after exiting
            listener_thread
                .join()
                .expect("Failed to join on the associated thread");
        }

        // Check number of threads after closing the listener thread
        let out_cmd3 = Command::new("cat")
            .arg(format!("/proc/{}/status", std::process::id()))
            .output()
            .expect("Failed to run cat");
        let out3 = std::str::from_utf8(&out_cmd3.stdout).unwrap();
        let crt_num_threads3 = get_num_threads_from_status_output(out3.to_string());
        assert_eq!(crt_num_threads0, crt_num_threads3);
        assert!(crt_num_threads3 < crt_num_threads1);

        if !path_existed {
            // Remove whole resources_dir
            let _ = fs::remove_dir_all(resources_dir.as_path().to_str().unwrap());
        } else {
            // Only remove the socket file
            let _ = fs::remove_file(&dummy_sock_path);
        }

        // Restore previous enviornment variable value
        if let Ok(old_log_path) = old_log_path {
            env::set_var(SOCKETS_DIR_PATH_ENV_VAR, old_log_path);
        } else {
            env::set_var(SOCKETS_DIR_PATH_ENV_VAR, "");
            unset_envvar(&String::from(SOCKETS_DIR_PATH_ENV_VAR));
        }
    }
}
