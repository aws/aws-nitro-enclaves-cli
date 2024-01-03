use byteorder::{ByteOrder, LittleEndian};
use nix::sys::socket::MsgFlags;
use nix::sys::socket::{recv, send};
use std::convert::TryInto;
use std::os::unix::io::RawFd;

pub fn send_u64(fd: RawFd, val: u64) -> Result<(), String> {
    let mut buf = [0u8; 9];
    LittleEndian::write_u64(&mut buf, val);
    send_loop(fd, &buf, 9)?;
    Ok(())
}

pub fn recv_u64(fd: RawFd) -> Result<u64, String> {
    let mut buf = [0u8; 9];
    recv_loop(fd, &mut buf, 9)?;
    let val = LittleEndian::read_u64(&buf);
    Ok(val)
}

pub fn send_i32(fd: RawFd, val: i32) -> Result<(), String> {
    let mut buf = [0u8; 4];
    LittleEndian::write_i32(&mut buf, val);
    send_loop(fd, &buf, 4)?;
    Ok(())
}

pub fn recv_i32(fd: RawFd) -> Result<i32, String> {
    let mut buf = [0u8; 4];
    recv_loop(fd, &mut buf, 4)?;
    let val = LittleEndian::read_i32(&buf);
    Ok(val)
}

pub fn send_loop(fd: RawFd, buf: &[u8], len: u64) -> Result<(), String> {
    let len: usize = len.try_into().map_err(|err| format!("{:?}", err))?;
    let mut send_bytes = 0;

    while send_bytes < len {
        let size = match send(fd, &buf[send_bytes..len], MsgFlags::empty()) {
            Ok(size) => size,
            Err(nix::errno::Errno::EINTR) => 0,
            Err(err) => return Err(format!("{:?}", err)),
        };
        send_bytes += size;
    }

    Ok(())
}

pub fn recv_loop(fd: RawFd, buf: &mut [u8], len: u64) -> Result<(), String> {
    let len: usize = len.try_into().map_err(|err| format!("{:?}", err))?;
    let mut recv_bytes = 0;

    while recv_bytes < len {
        let size = match recv(fd, &mut buf[recv_bytes..len], MsgFlags::empty()) {
            Ok(size) => size,
            Err(nix::errno::Errno::EINTR) => 0,
            Err(err) => return Err(format!("{:?}", err)),
        };
        recv_bytes += size;
    }

    Ok(())
}
