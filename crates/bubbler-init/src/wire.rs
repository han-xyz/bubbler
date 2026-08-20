//! Socket I/O for the exec channel: request bytes plus exactly three fds
//! (stdin, stdout, stderr) via `SCM_RIGHTS`, then a 4-byte status back.

use std::ffi::{OsStr, OsString};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use crate::proto;

/// Exactly the stdio fds a request carries: stdin, stdout, stderr.
pub const REQUEST_FDS: usize = 3;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Send `argv` with the three stdio fds attached to the length prefix.
pub fn send_request(
    stream: &UnixStream,
    argv: &[&OsStr],
    fds: [BorrowedFd<'_>; REQUEST_FDS],
) -> io::Result<()> {
    let payload = proto::encode_request(argv);
    if payload.len() > proto::MAX_REQUEST {
        return Err(invalid("request too large"));
    }
    let len = (payload.len() as u32).to_le_bytes();
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(REQUEST_FDS))];
    let mut anc = SendAncillaryBuffer::new(&mut space);
    if !anc.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(invalid("ancillary buffer too small"));
    }
    let n = rustix::net::sendmsg(
        stream.as_fd(),
        &[IoSlice::new(&len)],
        &mut anc,
        SendFlags::empty(),
    )?;
    if n != len.len() {
        return Err(invalid("short length prefix"));
    }
    (&*stream).write_all(&payload)
}

/// Receive one request: argv and the attached fds, which must be exactly three.
pub fn recv_request(stream: &UnixStream) -> io::Result<(Vec<OsString>, Vec<OwnedFd>)> {
    let mut len = [0u8; 4];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(REQUEST_FDS))];
    let mut anc = RecvAncillaryBuffer::new(&mut space);
    let n = rustix::net::recvmsg(
        stream.as_fd(),
        &mut [IoSliceMut::new(&mut len)],
        &mut anc,
        RecvFlags::CMSG_CLOEXEC,
    )?
    .bytes;
    if n != len.len() {
        return Err(invalid("short length prefix"));
    }
    let mut fds = Vec::new();
    for m in anc.drain() {
        if let RecvAncillaryMessage::ScmRights(it) = m {
            fds.extend(it);
        }
    }
    if fds.len() != REQUEST_FDS {
        return Err(invalid("expected exactly three fds"));
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > proto::MAX_REQUEST {
        return Err(invalid("request too large"));
    }
    let mut buf = vec![0u8; len];
    (&*stream).read_exact(&mut buf)?;
    let argv = proto::decode_request(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    Ok((argv, fds))
}

/// Write the raw wait status of the executed command.
pub fn send_status(stream: &UnixStream, status: i32) -> io::Result<()> {
    (&*stream).write_all(&proto::encode_status(status))
}

/// Read the raw wait status; `UnexpectedEof` if init closed without one.
pub fn recv_status(stream: &UnixStream) -> io::Result<i32> {
    let mut b = [0u8; 4];
    (&*stream).read_exact(&mut b)?;
    Ok(proto::decode_status(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn request_roundtrip_carries_three_fds() {
        let (client, server) = UnixStream::pair().unwrap();
        let null = File::open("/dev/null").unwrap();
        let argv: Vec<&OsStr> = vec![OsStr::new("sh"), OsStr::new("-c"), OsStr::new("exit 3")];
        send_request(&client, &argv, [null.as_fd(), null.as_fd(), null.as_fd()]).unwrap();
        let (got, fds) = recv_request(&server).unwrap();
        assert_eq!(got, vec!["sh", "-c", "exit 3"]);
        assert_eq!(fds.len(), 3);
    }

    #[test]
    fn request_without_fds_is_rejected() {
        let (client, server) = UnixStream::pair().unwrap();
        let payload = crate::proto::encode_request(&[OsStr::new("true")]);
        (&client)
            .write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        (&client).write_all(&payload).unwrap();
        assert!(recv_request(&server).is_err());
    }

    #[test]
    fn status_roundtrip_over_socket() {
        let (client, server) = UnixStream::pair().unwrap();
        send_status(&server, 3 << 8).unwrap();
        assert_eq!(recv_status(&client).unwrap(), 3 << 8);
    }
}
