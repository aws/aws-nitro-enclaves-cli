// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use chrono::offset::{Local, Utc};
use chrono::DateTime;
use flexi_logger::writers::LogWriter;
use flexi_logger::{DeferredNow, LogTarget, Record};
use std::fs::{File, OpenOptions};
use std::io::{Result, Write};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::common::safe_create_npe_resources_dir;
use crate::common::ExitGracefully;
use crate::common::ENCLAVE_PROC_RESOURCES_DIR;

const DEFAULT_LOG_LEVEL: &str = "info";
const LOG_FILE_NAME: &str = "nitro-cli.log";

/// A log writer class which outputs its messages to a custom file.
/// It also allows the updating of its ID, in order to indicate which process
/// is actually logging a message. This implementation will also enable
/// synchronized logging to a centralized file for multiple enclaves.
#[derive(Clone)]
pub struct EnclaveProcLogWriter {
    out_file: Arc<Mutex<File>>,
    out_file_path: String,
    logger_id: Arc<Mutex<String>>,
}

impl EnclaveProcLogWriter {
    /// Create a new log writer.
    pub fn new(log_file_name: &str) -> Result<Self> {
        safe_create_npe_resources_dir()?;
        let path = format!("{}/{}", ENCLAVE_PROC_RESOURCES_DIR, log_file_name);

        // All logging shall be directed to a centralized file.
        Ok(EnclaveProcLogWriter {
            out_file: Arc::new(Mutex::new(open_log_file(&path))),
            out_file_path: path,
            logger_id: Arc::new(Mutex::new(String::new())),
        })
    }

    /// Check if the log file is present and if it is not, (re)open it.
    fn safe_open_log_file(&self) {
        if !Path::new(&self.out_file_path).exists() {
            safe_create_npe_resources_dir().ok_or_exit("Failed to create NPE resource directory.");
            let new_file = open_log_file(&self.out_file_path);
            let mut file_ref = self.out_file.lock().ok_or_exit("Failed to lock log file.");
            *file_ref.deref_mut() = new_file;
        }
    }

    /// Update the logger ID (correlated with the process which is doing logging).
    pub fn update_logger_id(&self, new_id: &str) {
        let mut old_id = self
            .logger_id
            .lock()
            .ok_or_exit("Failed to lock logger ID.");
        old_id.deref_mut().clear();
        old_id.deref_mut().push_str(new_id);
    }

    /// Generate a single message string.
    fn create_msg(&self, now: &DateTime<Local>, record: &Record) -> String {
        // UTC timestamp according to RFC 2822
        let timestamp = DateTime::<Utc>::from_utc(now.naive_utc(), Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let logger_id = self
            .logger_id
            .lock()
            .ok_or_exit("Failed to lock logger ID.");
        format!(
            "[{}][{}][{}][{}:{}] {}\n",
            logger_id.deref(),
            record.level(),
            timestamp,
            record.file().unwrap_or("?"),
            record.line().unwrap_or(0),
            &record.args()
        )
    }
}

impl LogWriter for EnclaveProcLogWriter {
    fn write(&self, now: &mut DeferredNow, record: &Record) -> Result<()> {
        self.safe_open_log_file();
        let record_str = self.create_msg(now.now(), record);
        let mut out_file = self.out_file.lock().ok_or_exit("Failed to lock log file.");
        out_file.deref_mut().write_all(&record_str.as_bytes())?;
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn max_log_level(&self) -> log::LevelFilter {
        // The log level is either given in RUST_LOG or defaults to a specified value.
        let level = std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_LOG_LEVEL.to_string());

        level.to_lowercase();
        match level.as_ref() {
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            "trace" => log::LevelFilter::Trace,
            _ => log::LevelFilter::Info,
        }
    }
}

/// Open a file at a given location for writing and appending.
fn open_log_file(file_path: &String) -> File {
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(false)
        .open(file_path)
        .ok_or_exit("Failed to open log file.")
}

/// Initialize logging.
pub fn init_logger() -> EnclaveProcLogWriter {
    // The log file is "nitro-cli.log" and is stored in the NPE resources directory.
    let log_writer = EnclaveProcLogWriter::new(LOG_FILE_NAME)
        .ok_or_exit("Failed to initialize enclave process log writer.");

    // Initialize logging with the new log writer.
    flexi_logger::Logger::with_env_or_str(DEFAULT_LOG_LEVEL)
        .log_target(LogTarget::Writer(Box::new(log_writer.clone())))
        .start()
        .ok_or_exit("Failed to initialize enclave process logger.");

    // The log writer is provided for sharing between CLI-related processes.
    log_writer
}
