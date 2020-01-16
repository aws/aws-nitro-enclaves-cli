// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

use eif_defs::{EifHeader, EifSectionHeader};
use nix::sys::socket::{connect, socket};
use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::raw::c_char;
use std::os::unix::io::FromRawFd;
use std::thread::sleep;
use std::time::Duration;

const MAX_VSOCK_PACKET: usize = 4096;
const MAX_PAYLOAD: usize = MAX_VSOCK_PACKET - 8;

#[derive(Debug, PartialEq)]
/// Internal errors while sending an Eif file
pub enum EifLoaderError {
    SocketCreationError,
    VsockConnectingError,
    ImagePathError,
    HeaderReadingError,
    InvalidHeader,
    SectionReadingError,
    BuildingPacketError,
    PacketSendingError,
}

/// Creates a vsock_connection to the given cid and port and returns
/// a file  handle to that connection
fn vsock_connect(cid: u32, port: u32) -> Result<File, EifLoaderError> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|_err| EifLoaderError::SocketCreationError)?;

    let sockaddr = SockAddr::new_vsock(cid, port);
    connect(socket_fd, &sockaddr).map_err(|_err| EifLoaderError::VsockConnectingError)?;
    Ok(unsafe { File::from_raw_fd(socket_fd) })
}

fn send_packet(
    buf: &[u8],
    token: &[u8],
    dst: &mut dyn Write,
    between_packets_delay: Option<Duration>,
) -> Result<(), EifLoaderError> {
    if let Some(between_packets_delay) = between_packets_delay {
        sleep(between_packets_delay);
    };
    let mut pkt = Vec::with_capacity(token.len() + buf.len());
    if token.len() + pkt.len() > MAX_VSOCK_PACKET {
        return Err(EifLoaderError::BuildingPacketError);
    }

    pkt.extend_from_slice(&token);
    pkt.extend_from_slice(buf);
    dst.write_all(&pkt)
        .map_err(|_err| EifLoaderError::PacketSendingError)?;

    Ok(())
}

/// Sends an eif section from src to dst
fn send_section(
    src: &mut dyn Read,
    dst: &mut dyn Write,
    between_packets_delay: Option<Duration>,
) -> Result<(), EifLoaderError> {
    let mut buffer = [0u8; MAX_PAYLOAD];
    src.read_exact(&mut buffer[0..size_of::<EifSectionHeader>()])
        .map_err(|_err| EifLoaderError::SectionReadingError)?;

    let mut section_header = [0u8; size_of::<EifSectionHeader>()];
    section_header.copy_from_slice(&buffer[0..size_of::<EifSectionHeader>()]);
    let section_header_ptr = &section_header as *const u8 as *const EifSectionHeader;
    let section_header = unsafe { *section_header_ptr };

    let num_to_read = std::cmp::min(
        section_header.section_size as usize,
        buffer.len() - size_of::<EifSectionHeader>(),
    );
    src.read_exact(
        &mut buffer[size_of::<EifSectionHeader>()..size_of::<EifSectionHeader>() + num_to_read],
    )
    .map_err(|_err| EifLoaderError::SectionReadingError)?;
    send_packet(
        &buffer[0..size_of::<EifSectionHeader>() + num_to_read],
        &[],
        dst,
        between_packets_delay,
    )?;

    let mut num_read = num_to_read;
    while num_read < (section_header.section_size as usize) {
        let num_to_read = std::cmp::min(
            section_header.section_size as usize - num_read,
            buffer.len(),
        );
        src.read_exact(&mut buffer[0..num_to_read])
            .map_err(|_err| EifLoaderError::SectionReadingError)?;
        send_packet(&buffer[0..num_to_read], &[], dst, between_packets_delay)?;
        num_read += num_to_read;
    }
    Ok(())
}

// Sends an Image file to dst
fn send_image_to_dst(
    image_file: &mut File,
    dst: &mut dyn Write,
    token: [u8; std::mem::size_of::<u64>()],
    between_packets_delay: Option<Duration>,
) -> Result<(), EifLoaderError> {
    image_file
        .seek(SeekFrom::Start(0))
        .map_err(|_err| EifLoaderError::ImagePathError)?;
    let mut eif_header_buf = [0u8; size_of::<EifHeader>()];

    image_file
        .read_exact(&mut eif_header_buf)
        .map_err(|_err| EifLoaderError::HeaderReadingError)?;

    let eif_header_ptr = &eif_header_buf as *const u8 as *const EifHeader;
    let eif_header = unsafe { *eif_header_ptr };
    if eif_header.magic != eif_defs::EIF_MAGIC {
        return Err(EifLoaderError::InvalidHeader);
    }
    send_packet(&eif_header_buf, &token, dst, between_packets_delay)?;
    for _section in { 0..eif_header.num_sections } {
        send_section(image_file, dst, between_packets_delay)?;
    }
    Ok(())
}

pub fn send_image(
    eif_image: &mut File,
    cid: u32,
    port: u32,
    token: [u8; std::mem::size_of::<u64>()],
    between_packets_delay: Option<Duration>,
) -> Result<(), EifLoaderError> {
    let mut vsock_conn = vsock_connect(cid, port)?;

    send_image_to_dst(eif_image, &mut vsock_conn, token, between_packets_delay)
}

#[no_mangle]
/// Public interface for sending an EifFile over vsock
///
/// Returns 0 on Success
///        -1 otherwise.
pub extern "C" fn eif_loader_send_image(
    path: *const c_char,
    cid: u32,
    port: u32,
    token: u64,
) -> i32 {
    let image_path = unsafe {
        let path = CString::from_raw(path as *mut c_char);
        let copy = path.clone();
        path.into_raw();
        copy
    };

    let vsock_conn = vsock_connect(cid, port);
    if vsock_conn.is_err() {
        println!("{:?}", vsock_conn.err());
        return -1;
    }

    let mut vsock_conn = vsock_conn.unwrap();
    // Safe because they match in size
    let token: [u8; std::mem::size_of::<u64>()] = unsafe { std::mem::transmute(token.to_be()) };
    let image_path = image_path
        .to_str()
        .expect("Invalid utf8 character for path");

    let image_file = File::open(image_path);
    if image_file.is_err() {
        println!("{:?}", image_file.err());
        return -1;
    }
    let mut image_file = image_file.unwrap();

    let res = send_image_to_dst(&mut image_file, &mut vsock_conn, token, None);
    if res.is_err() {
        println!("{:?}", res.err());
        return -1;
    }
    0
}

#[cfg(test)]
mod tests {

    use super::*;
    use eif_utils::EifBuilder;
    use sha2::Digest;
    use std::fs::File;
    use std::io::{Read, Write};
    use tempfile::tempdir;
    const TOKEN: [u8; 8] = [0xef; 8];

    #[test]
    /// Tests sending an invalid eif file is detected
    fn test_invalid_eif() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("src.eif");
        let dst_path = dir.path().join("dst.eif");
        let mut dst_file = File::create(dst_path.clone()).unwrap();
        let num_bytes = 11876u32;
        {
            let mut src_file = File::create(src_path.clone()).unwrap();
            for _i in { 0..num_bytes } {
                let buf = [(num_bytes % 255) as u8];
                src_file.write(&buf).unwrap();
            }
        }

        let mut src_file = File::open(src_path).unwrap();
        assert_eq!(
            send_image_to_dst(&mut src_file, &mut dst_file, TOKEN, None)
                .err()
                .unwrap(),
            EifLoaderError::InvalidHeader
        );
    }

    #[test]
    /// Tests that all bytes of an eif file are sent to the destination
    fn test_valid_eif() {
        let dir = tempdir().unwrap();
        let num_bytes = 11876u32;
        let kernel_path = dir.path().join("kernel");
        let ramdisk_path = dir.path().join("ramdisk");
        let eif_path = dir.path().join("src.eif");
        let dst_path = dir.path().join("dst.eif");
        let mut dst_file = File::create(dst_path.clone()).unwrap();

        {
            let mut kernel_file = File::create(kernel_path.clone()).unwrap();
            let mut ramdisk_file = File::create(ramdisk_path.clone()).unwrap();
            for _i in { 0..num_bytes } {
                let buf = [(num_bytes % 255) as u8];
                kernel_file.write(&buf).unwrap();
                ramdisk_file.write(&buf).unwrap();
            }
        }

        let mut build = EifBuilder::new(
            &kernel_path,
            "dummy cmdline".to_string(),
            sha2::Sha256::new(),
        );
        let mut eif_out = File::create(eif_path.clone()).unwrap();
        build.add_ramdisk(&ramdisk_path);
        build.write_to(&mut eif_out);

        let mut eif_file = File::open(eif_path.clone()).unwrap();
        assert_eq!(
            send_image_to_dst(&mut eif_file, &mut dst_file, TOKEN, None).is_ok(),
            true
        );

        let mut src_file = File::open(eif_path).unwrap();
        let mut dst_file = File::open(dst_path).unwrap();
        let mut src_buff = Vec::new();
        let mut dst_buff = Vec::new();
        src_buff.extend_from_slice(&TOKEN);
        src_file.read_to_end(&mut src_buff).unwrap();
        dst_file.read_to_end(&mut dst_buff).unwrap();
        assert_eq!(src_buff, dst_buff);
    }
}
