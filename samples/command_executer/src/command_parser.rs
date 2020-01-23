use serde::Serialize;
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
}

impl RunArgs {
    pub fn new_with(args: &ArgMatches) -> Result<Self, String> {
        Ok(RunArgs {
            cid: parse_cid(args)?,
            port: parse_port(args)?,
            command: parse_command(args)?,
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

#[derive(Serialize, Debug)]
pub struct CommandOutput {
    stdout: String,
    stderr: String,
    rc: Option<i32>,
}

impl CommandOutput {
    pub fn new(output: Output) -> Result<Self, String> {
        Ok(CommandOutput {
            stdout: String::from_utf8(output.stdout).map_err(|err| format!("{:?}", err))?,
            stderr: String::from_utf8(output.stderr).map_err(|err| format!("{:?}", err))?,
            rc: output.status.code(),
        })
    }
}

fn parse_cid(args: &ArgMatches) -> Result<u32, String> {
    let port = args.value_of("cid").ok_or("Could not find cid argument")?;
    port.parse()
        .map_err(|_err| "cid is not a number".to_string())
}

fn parse_port(args: &ArgMatches) -> Result<u32, String> {
    let port = args
        .value_of("port")
        .ok_or("Could not find port argument")?;
    port.parse()
        .map_err(|_err| "port is not a number".to_string())
}

fn parse_command(args: &ArgMatches) -> Result<String, String> {
    let command = args
        .value_of("command")
        .ok_or("Could not find command argument")?;
    Ok(String::from(command))
}

fn parse_localfile(args: &ArgMatches) -> Result<String, String> {
    let output = args
        .value_of("localpath")
        .ok_or("Could not find localpath")?;
    Ok(String::from(output))
}

fn parse_remotefile(args: &ArgMatches) -> Result<String, String> {
    let output = args
        .value_of("remotepath")
        .ok_or("Could not find remotepath")?;
    Ok(String::from(output))
}
