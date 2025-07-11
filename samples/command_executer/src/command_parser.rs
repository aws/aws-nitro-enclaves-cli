use serde::{Deserialize, Serialize};
use std::process::Output;

use clap::ArgMatches;

#[derive(Debug, Clone)]
pub struct ListenArgs {
    pub port: u32,
}

impl ListenArgs {
    pub fn new_with(args: &ArgMatches) -> Result<Self, String> {
        Ok(ListenArgs {
            port: parse_port(args)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RunArgs {
    pub cid: u32,
    pub port: u32,
    pub command: String,
    pub no_wait: bool,
}

impl RunArgs {
    pub fn new_with(args: &ArgMatches) -> Result<Self, String> {
        Ok(RunArgs {
            cid: parse_cid(args)?,
            port: parse_port(args)?,
            command: parse_command(args)?,
            no_wait: parse_no_wait(args),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileArgs {
    pub cid: u32,
    pub port: u32,
    pub localfile: String,
    pub remotefile: String,
}

impl FileArgs {
    pub fn new_with(args: &ArgMatches) -> Result<Self, String> {
        Ok(FileArgs {
            cid: parse_cid(args)?,
            port: parse_port(args)?,
            localfile: parse_localfile(args)?,
            remotefile: parse_remotefile(args)?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub rc: Option<i32>,
}

impl CommandOutput {
    pub fn new(stdout: String, stderr: String, code: i32) -> Self {
        CommandOutput {
            stdout,
            stderr,
            rc: Some(code),
        }
    }

    pub fn new_from(output: Output) -> Result<Self, String> {
        Ok(CommandOutput {
            stdout: String::from_utf8(output.stdout).map_err(|err| format!("{err:?}"))?,
            stderr: String::from_utf8(output.stderr).map_err(|err| format!("{err:?}"))?,
            rc: output.status.code(),
        })
    }
}

fn parse_cid(args: &ArgMatches) -> Result<u32, String> {
    args.get_one::<String>("cid")
        .ok_or("Could not find cid argument")?
        .parse()
        .map_err(|_err| "cid is not a number".to_string())
}

fn parse_port(args: &ArgMatches) -> Result<u32, String> {
    args.get_one::<String>("port")
        .ok_or("Could not find port argument")?
        .parse()
        .map_err(|_err| "port is not a number".to_string())
}

fn parse_command(args: &ArgMatches) -> Result<String, String> {
    args.get_one::<String>("command")
        .map(String::from)
        .ok_or_else(|| "Could not find command argument".to_string())
}

fn parse_no_wait(args: &ArgMatches) -> bool {
    args.get_flag("no-wait")
}

fn parse_localfile(args: &ArgMatches) -> Result<String, String> {
    args.get_one::<String>("localpath")
        .map(String::from)
        .ok_or_else(|| "Could not find localpath".to_string())
}

fn parse_remotefile(args: &ArgMatches) -> Result<String, String> {
    args.get_one::<String>("remotepath")
        .map(String::from)
        .ok_or_else(|| "Could not find remotepath".to_string())
}
