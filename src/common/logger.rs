// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

use chrono::offset::{Local, Utc};
use chrono::DateTime;
use flexi_logger::writers::LogWriter;
use flexi_logger::{DeferredNow, Record};
use nix::unistd::Uid;
use std::env;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{Error, ErrorKind, Result, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::new_nitro_cli_failure;

/// The default logging level used by the logger.
const DEFAULT_LOG_LEVEL: &str = "info";

/// The environment variable which holds the path to the logging directory.
const LOGS_DIR_PATH_ENV_VAR: &str = "NITRO_CLI_LOGS_PATH";

/// The default path to the logging directory.
const LOGS_DIR_PATH: &str = "/var/log/nitro_enclaves";

/// The name of the output log file.
const LOG_FILE_NAME: &str = "nitro_enclaves.log";

/// A log writer which outputs its messages to a custom file. It also
/// allows the updating of its ID, in order to indicate which process
/// is actually logging a message. This implementation will also enable
/// synchronized logging to a centralized file for multiple enclaves.
#[derive(Clone)]
pub struct EnclaveProcLogWriter {
    out_file: Arc<Mutex<File>>,
    logger_id: Arc<Mutex<String>>,
}

impl EnclaveProcLogWriter {
    /// Create a new log writer.
    pub fn new() -> NitroCliResult<Self> {
        // All logging shall be directed to a centralized file.
        Ok(EnclaveProcLogWriter {
            out_file: Arc::new(Mutex::new(
                open_log_file(&get_log_file_path())
                    .map_err(|e| e.add_subaction("Failed to open log file".to_string()))?,
            )),
            logger_id: Arc::new(Mutex::new(String::new())),
        })
    }

    /// Check if the log file is present and if it is not, (re)open it.
    fn safe_open_log_file(&self) -> NitroCliResult<()> {
        let log_path = &get_log_file_path();
        if !log_path.exists() {
            let new_file = open_log_file(log_path)
                .map_err(|e| e.add_subaction(String::from("Failed to open log file")))?;
            let mut file_ref = self.out_file.lock().map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to acquire lock: {:?}", e),
                    NitroCliErrorEnum::LockAcquireFailure
                )
            })?;
            *file_ref.deref_mut() = new_file;
        }

        Ok(())
    }

    /// Update the logger ID (correlated with the process which is doing logging).
    pub fn update_logger_id(&self, new_id: &str) -> NitroCliResult<()> {
        let mut old_id = self.logger_id.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire logger ID lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        old_id.deref_mut().clear();
        old_id.deref_mut().push_str(new_id);

        Ok(())
    }

    /// Generate a single message string.
    fn create_msg(&self, now: &DateTime<Local>, record: &Record) -> NitroCliResult<String> {
        // UTC timestamp according to RFC 2822
        let timestamp = DateTime::<Utc>::from_naive_utc_and_offset(now.naive_utc(), Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let logger_id = self.logger_id.lock().map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to acquire logger ID lock: {:?}", e),
                NitroCliErrorEnum::LockAcquireFailure
            )
        })?;
        Ok(format!(
            "[{}][{}][{}][{}:{}] {}\n",
            logger_id.deref(),
            record.level(),
            timestamp,
            record.file().unwrap_or("?"),
            record.line().unwrap_or(0),
            &record.args()
        ))
    }
}

impl LogWriter for EnclaveProcLogWriter {
    fn write(&self, now: &mut DeferredNow, record: &Record) -> Result<()> {
        if self.safe_open_log_file().is_err() {
            return Err(Error::new(
                ErrorKind::Other,
                "Failed to safely open log file for writing",
            ));
        }

        if let Ok(record_str) = self.create_msg(now.now(), record) {
            if let Ok(mut out_file) = self.out_file.lock() {
                out_file.deref_mut().write_all(record_str.as_bytes())?;

                return Ok(());
            }

            return Err(Error::new(ErrorKind::Other, "Failed to lock log file"));
        }

        Err(Error::new(
            ErrorKind::Other,
            "Failed to create logger message",
        ))
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn max_log_level(&self) -> log::LevelFilter {
        // The log level is either given in RUST_LOG or defaults to a specified value.
        let level = std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_LOG_LEVEL.to_string());

        match level.to_lowercase().as_ref() {
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            "trace" => log::LevelFilter::Trace,
            _ => log::LevelFilter::Info,
        }
    }
}

/// Get the directory containing Nitro CLI related log files.
pub fn get_log_file_base_path() -> String {
    match env::var(LOGS_DIR_PATH_ENV_VAR) {
        Ok(env_path) => env_path,
        Err(_) => LOGS_DIR_PATH.to_string(),
    }
}

/// Get the path to the log file.
fn get_log_file_path() -> PathBuf {
    Path::new(&get_log_file_base_path()).join(LOG_FILE_NAME)
}

/// Open a file at a given location for writing and appending.
fn open_log_file(file_path: &Path) -> NitroCliResult<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(false)
        .open(file_path)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to open log file: {:?}", e),
                NitroCliErrorEnum::FileOperationFailure
            )
            .add_info(vec![
                file_path
                    .to_str()
                    .unwrap_or("Invalid unicode log file name"),
                "Open",
            ])
        })?;

    let log_file_uid = Uid::from_raw(
        file.metadata()
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to get log file metadata: {:?}", e),
                    NitroCliErrorEnum::FileOperationFailure
                )
                .add_info(vec![
                    file_path
                        .to_str()
                        .unwrap_or("Invalid unicode log file name"),
                    "Get metadata",
                ])
            })?
            .uid(),
    );

    // The log file should be write-accessible to any user, since
    // any user may launch a CLI instance. Only the file's owner
    // may change its permissions.
    if log_file_uid == Uid::current() {
        let perms = Permissions::from_mode(0o766);
        file.set_permissions(perms).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to change log file permissions: {:?}", e),
                NitroCliErrorEnum::FilePermissionsError
            )
        })?;
    }

    Ok(file)
}

/// Initialize logging.
pub fn init_logger() -> NitroCliResult<EnclaveProcLogWriter> {
    // The log file is "nitro-cli.log" and is stored in the NPE resources directory.
    let log_writer = EnclaveProcLogWriter::new()?;

    // Initialize logging with the new log writer.
    flexi_logger::Logger::try_with_env_or_str(DEFAULT_LOG_LEVEL)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to initialize enclave process logger: {:?}", e),
                NitroCliErrorEnum::LoggerError
            )
        })?
        .log_to_writer(Box::new(log_writer.clone()))
        .start()
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to initialize enclave process logger: {:?}", e),
                NitroCliErrorEnum::LoggerError
            )
        })?;

    // The log writer is provided for sharing between CLI-related processes.
    Ok(log_writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::NamedTempFile;

    /// Tests that `open_log_file()` creates a file
    /// with the expected permissions.
    #[test]
    fn test_open_log_file() {
        let file0 = NamedTempFile::new();

        if let Ok(file0) = file0 {
            let test_file_path = file0.path();

            let f = open_log_file(test_file_path).unwrap();
            let metadata = f.metadata();
            assert!(metadata.is_ok());

            if let Ok(metadata) = metadata {
                assert!(metadata.is_file());
                let permissions = metadata.permissions();
                let mode = permissions.mode();

                assert_eq!(mode & 0o777, 0o766);
            }
        }
    }

    /// Tests that the logger id is initially empty ("").
    #[test]
    fn test_init_logger() {
        let tmp_log_dir: &str = "./.tmp_logs_init_logger";

        // Get old environment variable value
        let old_log_path = env::var(LOGS_DIR_PATH_ENV_VAR);
        let path_existed = Path::new(tmp_log_dir).exists();

        // Update environment variable value
        env::set_var(LOGS_DIR_PATH_ENV_VAR, tmp_log_dir);
        let _ = fs::create_dir(tmp_log_dir);

        let log_writer = EnclaveProcLogWriter::new().unwrap();
        let lock_result = log_writer.logger_id.lock();

        assert!(lock_result.unwrap().is_empty());

        if !path_existed {
            // Remove whole `tmp_log_dir` if necessary
            let _ = fs::remove_dir_all(tmp_log_dir);
        } else {
            // Only remove the log file
            let _ = fs::remove_file(format!("{}/{}", tmp_log_dir, &LOG_FILE_NAME));
        }

        // Reset old environment variable value if necessary
        if let Ok(old_log_path) = old_log_path {
            env::set_var(LOGS_DIR_PATH_ENV_VAR, old_log_path);
        }
    }

    /// Tests that the logger id is altered after issuing a
    /// call to `update_logger_id()`.
    #[test]
    fn test_update_logger_id() {
        let tmp_log_dir: &str = "./.tmp_logs_update_logger_id";

        // Get old environment variable value
        let old_log_path = env::var(LOGS_DIR_PATH_ENV_VAR);
        let path_existed = Path::new(tmp_log_dir).exists();

        // Update environment variable value
        env::set_var(LOGS_DIR_PATH_ENV_VAR, tmp_log_dir);
        let _ = fs::create_dir(tmp_log_dir);

        let log_writer = EnclaveProcLogWriter::new().unwrap();
        log_writer.update_logger_id("new-logger-id").unwrap();
        let lock_result = log_writer.logger_id.lock();

        assert!(lock_result.unwrap().eq("new-logger-id"));

        log_writer.update_logger_id("").unwrap();

        if !path_existed {
            // Remove whole `tmp_log_dir` if necessary
            let _ = fs::remove_dir_all(tmp_log_dir);
        } else {
            // Only remove the log file
            let _ = fs::remove_file(format!("{}/{}", tmp_log_dir, &LOG_FILE_NAME));
        }

        // Reset old environment variable value if necessary
        if let Ok(old_log_path) = old_log_path {
            env::set_var(LOGS_DIR_PATH_ENV_VAR, old_log_path);
        }
    }
}
