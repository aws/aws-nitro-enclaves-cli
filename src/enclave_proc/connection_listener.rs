// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use log::{debug, info, warn};
use nix::sys::epoll::{self, EpollEvent, EpollFlags, EpollOp};
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread::{self, JoinHandle};

use super::connection::Connection;
use super::socket::EnclaveProcSock;
use crate::common::commands_parser::EmptyArgs;
use crate::common::{enclave_proc_command_send_single, receive_command_type};
use crate::common::{EnclaveProcessCommandType, ExitGracefully};

/// A listener which waits for external connections.
pub struct ConnectionListener {
    /// The epoll descriptor used to register new connections.
    epoll_fd: RawFd,
    /// The thread which actually listens for new connections
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
    /// Create a new connection listener.
    pub fn new() -> Self {
        ConnectionListener {
            epoll_fd: epoll::epoll_create().ok_or_exit("Could not create epoll_fd."),
            listener_thread: None,
            socket: EnclaveProcSock::default(),
        }
    }

    /// Expose the epoll descriptor.
    pub fn get_epoll_fd(&self) -> RawFd {
        self.epoll_fd
    }

    /// Initialize the connection listener.
    pub fn start(&mut self, enclave_id: &String) -> io::Result<()> {
        // Obtain the socket to listen on.
        self.socket = EnclaveProcSock::new(enclave_id)?;

        let self_clone = self.clone();
        self.listener_thread = Some(thread::spawn(move || self_clone.connection_listener_run()));

        Ok(())
    }

    /// Add a stream to epoll.
    pub fn add_stream_to_epoll(&self, stream: UnixStream) {
        let stream_fd = stream.as_raw_fd();
        let mut cli_evt = EpollEvent::new(EpollFlags::EPOLLIN, stream.into_raw_fd() as u64);
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlAdd, stream_fd, &mut cli_evt)
            .ok_or_exit("Could not add new connection descriptor to epoll.");
    }

    /// Add the enclave descriptor to epoll.
    pub fn register_enclave_descriptor(&mut self, enc_fd: RawFd) {
        let mut enc_event = EpollEvent::new(
            EpollFlags::EPOLLIN | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
            enc_fd as u64,
        );
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlAdd, enc_fd, &mut enc_event)
            .ok_or_exit("Could not add enclave descriptor to epoll.");
    }

    /// Handle a new connection.
    pub fn handle_new_connection(&self, mut stream: UnixStream) -> EnclaveProcessCommandType {
        let cmd_type = receive_command_type(&mut stream).ok_or_exit("Failed to read command type.");

        // All connections must be registered with epoll, with the exception of the shutdown one.
        if cmd_type != EnclaveProcessCommandType::ConnectionListenerStop {
            self.add_stream_to_epoll(stream);
        }

        cmd_type
    }

    /// Wait for and handle new connections.
    fn connection_listener_run(mut self) {
        // Bind the listener to the socket and spawn the listener thread.
        let listener = UnixListener::bind(self.socket.get_path()).ok_or_exit("Error binding.");
        self.socket
            .start_monitoring()
            .ok_or_exit("Error monitoring socket.");
        debug!(
            "Connection listener started on socket {:?}.",
            self.socket.get_path()
        );

        // Accept connections and process them (this is a blocking call).
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // Received a new connection. Shut down if required.
                    if self.handle_new_connection(stream)
                        == EnclaveProcessCommandType::ConnectionListenerStop
                    {
                        break;
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
        self.socket.close();
        debug!("Connection listener has finished.");
    }

    /// Terminate the connection listener.
    pub fn stop(self) {
        // Nothing to do if the connection listener thread has not been started.
        if self.listener_thread.is_none() {
            return;
        }

        // Send termination notification to the listener thread.
        let mut self_conn = UnixStream::connect(self.socket.get_path())
            .ok_or_exit("Failed to connect to our own socket.");
        enclave_proc_command_send_single::<EmptyArgs>(
            &EnclaveProcessCommandType::ConnectionListenerStop,
            None,
            &mut self_conn,
        )
        .ok_or_exit("Failed to notify listener thread of shutdown.");

        // Shut the connection down.
        self_conn
            .shutdown(std::net::Shutdown::Both)
            .ok_or_exit("Failed to shut down.");

        // Ensure that the listener thread has terminated.
        self.listener_thread
            .unwrap()
            .join()
            .ok_or_exit("Failed to join listener thread.");
        info!("The connection listener has been stopped.");
    }

    /// Fetch the next available connection.
    pub fn get_next_connection(&self, enc_fd: Option<RawFd>) -> Connection {
        // Wait on epoll until a valid event is received.
        let mut events = [EpollEvent::empty(); 1];

        loop {
            let num_events = epoll::epoll_wait(self.epoll_fd, &mut events, -1)
                .ok_or_exit("Waiting on epoll failed.");
            if num_events > 0 {
                break;
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
        epoll::epoll_ctl(self.epoll_fd, EpollOp::EpollCtlDel, fd, None)
            .ok_or_exit("Failed to remove fd from epoll.");

        Connection::new(events[0].events(), input_stream)
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
    use std::sync::{Arc, Mutex, Condvar};

    const THREADS_STR: &str = "Threads:";
    const TMP_DIR: &str = "./npe";

    /// Inspects the content of /proc/<PID>/status in order to
    /// retrieve the number of threads running in the context of
    /// process <PID>.
    fn get_num_threads_from_status_output(status_str: String) -> u32 {
        let start_idx = status_str.find(THREADS_STR);
        let mut iter = status_str.chars();
        iter.by_ref().nth(start_idx.unwrap() + THREADS_STR.len()); // skip "Threads:\t"
        let slice = iter.as_str();

        let new_str = slice.to_string();
        let end_idx = new_str.find("\n"); // skip after the first '\n'
        let substr = &slice[..end_idx.unwrap()];

        substr.parse().unwrap()
    }


    /// Tests that get_epoll_fd() returns the expected epoll_fd.
    #[test]
    fn test_get_epoll_fd() {
        let connection_listener = ConnectionListener::new();
        let epoll_fd = connection_listener.epoll_fd;

        assert_eq!(epoll_fd, connection_listener.get_epoll_fd());
    }

    /// Tests that new connections are monitored and that a command
    /// sent through the connection is received correctly.
    #[test]
    fn test_handle_new_connection() {
        let (mut sock0, sock1) = UnixStream::pair().unwrap();

        let connection_listener = ConnectionListener::new();

        let cmd = EnclaveProcessCommandType::Describe;
        let _ = enclave_proc_command_send_single::<EmptyArgs>(&cmd, None, &mut sock0);

        let result = connection_listener.handle_new_connection(sock1);

        assert_eq!(result, EnclaveProcessCommandType::Describe);
    }

    /// Test that add_stream_to_epoll registers a sockfd and that next subsequent
    /// attempts to register the same sockfd fail (since the sockfd is already registered
    /// once).
    #[test]
    fn test_add_stream_to_epoll() {
        let (_, sock1) = UnixStream::pair().unwrap();

        let connection_listener = ConnectionListener::new();
        let copy_sock1 = sock1.try_clone();

        if let Ok(copy_sock1) = copy_sock1 {
            let mut cli_evt = EpollEvent::new(EpollFlags::EPOLLIN, copy_sock1.into_raw_fd() as u64);
            let _ = epoll::epoll_ctl(connection_listener.epoll_fd,
                                           EpollOp::EpollCtlAdd,
                                           sock1.as_raw_fd(),
                                           &mut cli_evt);
            // Second add should return Err(Sys(EEXIST)), as sock1 is already registed
            // with connection_listener.epoll_fd
            let result = epoll::epoll_ctl(connection_listener.epoll_fd,
                                           EpollOp::EpollCtlAdd,
                                           sock1.as_raw_fd(),
                                           &mut cli_evt);

            assert_eq!(result.is_err(), true);
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
            let dummy_sock_path = format!("{}/{}", resources_dir.as_path().to_str().unwrap(), dummy_sock_name);

            // Remove pre-existing socket file
            let _ = std::fs::remove_file(&dummy_sock_path);

            let mut connection_listener = ConnectionListener::new();
            connection_listener.socket.set_path(PathBuf::from(&dummy_sock_path));

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
                                                    connection_listener.connection_listener_run();
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
                let _ = enclave_proc_command_send_single::<EmptyArgs>(&cmd, None, &mut my_stream);
            }

            // Wait for thread to join after exiting
            listener_thread.join().expect("Failed to join on the associated thread");

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
            let dummy_sock_path = format!("{}/{}", resources_dir.as_path().to_str().unwrap(), dummy_sock_name);

            // Remove pre-existing socket file
            let _ = std::fs::remove_file(&dummy_sock_path);

            let mut connection_listener = ConnectionListener::new();
            connection_listener.socket.set_path(PathBuf::from(&dummy_sock_path));

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
                                                    &conn_clone.connection_listener_run();
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
                let _ = enclave_proc_command_send_single::<EmptyArgs>(&cmd, None, &mut my_stream);
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
                let _ = enclave_proc_command_send_single::<EmptyArgs>(&cmd, None, &mut my_stream);

                // Wait for the thread to join after exiting
                listener_thread.join().expect("Failed to join on the associated thread");
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
        }

    }
}
