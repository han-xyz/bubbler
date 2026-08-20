//! Socket I/O for the exec channel: request bytes plus exactly three fds
//! (stdin, stdout, stderr) via `SCM_RIGHTS`, then a 4-byte status back.

use std::ffi::{OsStr, OsString};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

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

/// Arm the socket with the time left until `deadline`, so a whole request,
/// not merely one read, has to finish inside it.
fn arm(stream: &UnixStream, deadline: Instant) -> io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"));
    }
    stream.set_read_timeout(Some(left))
}

/// `read_exact` that re-arms the timeout before every read, so a client
/// trickling bytes cannot extend the deadline.
fn read_exact_by(stream: &UnixStream, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        arm(stream, deadline)?;
        match (&*stream).read(&mut buf[done..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
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

/// Receive one request whole before `deadline`: argv and its exactly
/// three fds. Blocks, so it is for a caller with nothing else to do; the
/// supervisor reads with [`Incoming`] instead.
pub fn recv_request(
    stream: &UnixStream,
    deadline: Instant,
) -> io::Result<(Vec<OsString>, Vec<OwnedFd>)> {
    let mut len = [0u8; 4];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(REQUEST_FDS))];
    let mut anc = RecvAncillaryBuffer::new(&mut space);
    arm(stream, deadline)?;
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
    read_exact_by(stream, &mut buf, deadline)?;
    let argv = proto::decode_request(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    Ok((argv, fds))
}

/// One request arriving in pieces on a non-blocking connection: the
/// length prefix carries the fds, the payload follows it. A client that
/// stops mid-request holds up nothing but its own connection.
#[derive(Debug, Default)]
pub struct Incoming {
    prefix: [u8; 4],
    have: usize,
    /// Payload length, known once the prefix is whole.
    want: Option<usize>,
    payload: Vec<u8>,
    fds: Vec<OwnedFd>,
}

impl Incoming {
    /// A connection nothing has been read from yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read what `stream` has ready now. `Ok(None)` means the request is
    /// still incomplete and the caller should poll again; an error means
    /// the connection is unusable and must be dropped.
    pub fn read_step(
        &mut self,
        stream: &UnixStream,
    ) -> io::Result<Option<(Vec<OsString>, Vec<OwnedFd>)>> {
        loop {
            match self.want {
                None => {
                    if !self.read_prefix(stream)? {
                        return Ok(None);
                    }
                }
                Some(want) if self.payload.len() < want => {
                    let mut chunk = [0u8; 4096];
                    let room = (want - self.payload.len()).min(chunk.len());
                    match (&*stream).read(&mut chunk[..room]) {
                        Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                        Ok(n) => self.payload.extend_from_slice(&chunk[..n]),
                        Err(e) if would_block(&e) => return Ok(None),
                        Err(e) => return Err(e),
                    }
                }
                Some(_) => {
                    let argv = proto::decode_request(&self.payload).map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}"))
                    })?;
                    return Ok(Some((argv, std::mem::take(&mut self.fds))));
                }
            }
        }
    }

    /// Read towards the length prefix; `Ok(true)` once it is whole. The
    /// fds ride on it, so they are collected here and nowhere else: a
    /// plain `read` of the payload discards ancillary data.
    fn read_prefix(&mut self, stream: &UnixStream) -> io::Result<bool> {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(REQUEST_FDS))];
        let mut anc = RecvAncillaryBuffer::new(&mut space);
        let read = rustix::net::recvmsg(
            stream.as_fd(),
            &mut [IoSliceMut::new(&mut self.prefix[self.have..])],
            &mut anc,
            RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(io::Error::from);
        let n = match read {
            Ok(r) => r.bytes,
            Err(e) if would_block(&e) => return Ok(false),
            Err(e) => return Err(e),
        };
        for m in anc.drain() {
            if let RecvAncillaryMessage::ScmRights(it) = m {
                self.fds.extend(it);
            }
        }
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        self.have += n;
        if self.have < self.prefix.len() {
            return Ok(false);
        }
        if self.fds.len() != REQUEST_FDS {
            return Err(invalid("expected exactly three fds"));
        }
        let len = u32::from_le_bytes(self.prefix) as usize;
        if len > proto::MAX_REQUEST {
            return Err(invalid("request too large"));
        }
        self.want = Some(len);
        Ok(true)
    }
}

/// Whether the connection had nothing more to give right now. `EINTR` is
/// counted with it: the caller polls again, and the signal is acted on by
/// the loop that called in.
fn would_block(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
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
    use std::time::Duration;

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn request_roundtrip_carries_three_fds() {
        let (client, server) = UnixStream::pair().unwrap();
        let null = File::open("/dev/null").unwrap();
        let argv: Vec<&OsStr> = vec![OsStr::new("sh"), OsStr::new("-c"), OsStr::new("exit 3")];
        send_request(&client, &argv, [null.as_fd(); REQUEST_FDS]).unwrap();
        let (got, fds) = recv_request(&server, soon()).unwrap();
        assert_eq!(got, vec!["sh", "-c", "exit 3"]);
        assert_eq!(fds.len(), REQUEST_FDS);
    }

    #[test]
    fn request_without_fds_is_rejected() {
        let (client, server) = UnixStream::pair().unwrap();
        let payload = proto::encode_request(&[OsStr::new("true")]);
        (&client)
            .write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        (&client).write_all(&payload).unwrap();
        assert!(recv_request(&server, soon()).is_err());
    }

    #[test]
    fn a_truncated_payload_times_out_instead_of_hanging() {
        let (client, server) = UnixStream::pair().unwrap();
        let null = File::open("/dev/null").unwrap();
        let argv: Vec<&OsStr> = vec![OsStr::new("true")];
        let payload = proto::encode_request(&argv);
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(REQUEST_FDS))];
        let mut anc = SendAncillaryBuffer::new(&mut space);
        let fds = [null.as_fd(); REQUEST_FDS];
        assert!(anc.push(SendAncillaryMessage::ScmRights(&fds)));
        let len = (payload.len() as u32).to_le_bytes();
        rustix::net::sendmsg(
            client.as_fd(),
            &[IoSlice::new(&len)],
            &mut anc,
            SendFlags::empty(),
        )
        .unwrap();
        let started = Instant::now();
        let deadline = Instant::now() + Duration::from_millis(200);
        assert!(recv_request(&server, deadline).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_trickling_client_cannot_extend_the_deadline() {
        let (client, server) = UnixStream::pair().unwrap();
        let null = File::open("/dev/null").unwrap();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(REQUEST_FDS))];
        let mut anc = SendAncillaryBuffer::new(&mut space);
        let fds = [null.as_fd(); REQUEST_FDS];
        assert!(anc.push(SendAncillaryMessage::ScmRights(&fds)));
        rustix::net::sendmsg(
            client.as_fd(),
            &[IoSlice::new(&20u32.to_le_bytes())],
            &mut anc,
            SendFlags::empty(),
        )
        .unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..20 {
                if (&client).write_all(b"x").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        assert!(recv_request(&server, started + Duration::from_millis(300)).is_err());
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "one byte at a time extended the deadline to {:?}",
            started.elapsed()
        );
        drop(server);
        let _ = writer.join();
    }

    #[test]
    fn an_incoming_request_is_read_in_as_many_pieces_as_it_arrives_in() {
        let (client, server) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let null = File::open("/dev/null").unwrap();
        let argv: Vec<&OsStr> = vec![OsStr::new("sh"), OsStr::new("-c"), OsStr::new("exit 3")];
        let payload = proto::encode_request(&argv);
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(REQUEST_FDS))];
        let mut anc = SendAncillaryBuffer::new(&mut space);
        let fds = [null.as_fd(); REQUEST_FDS];
        assert!(anc.push(SendAncillaryMessage::ScmRights(&fds)));
        let mut incoming = Incoming::new();
        assert!(
            incoming.read_step(&server).unwrap().is_none(),
            "nothing sent yet"
        );
        rustix::net::sendmsg(
            client.as_fd(),
            &[IoSlice::new(&(payload.len() as u32).to_le_bytes())],
            &mut anc,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(
            incoming.read_step(&server).unwrap().is_none(),
            "no payload yet"
        );
        let (first, second) = payload.split_at(2);
        (&client).write_all(first).unwrap();
        assert!(
            incoming.read_step(&server).unwrap().is_none(),
            "half a payload"
        );
        (&client).write_all(second).unwrap();
        let (got, fds) = incoming
            .read_step(&server)
            .unwrap()
            .expect("the request is whole");
        assert_eq!(got, vec!["sh", "-c", "exit 3"]);
        assert_eq!(fds.len(), REQUEST_FDS);
    }

    #[test]
    fn an_incoming_prefix_without_fds_is_rejected() {
        let (client, server) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        (&client).write_all(&4u32.to_le_bytes()).unwrap();
        assert!(Incoming::new().read_step(&server).is_err());
    }

    #[test]
    fn an_incoming_request_larger_than_the_cap_is_rejected() {
        let (client, server) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let null = File::open("/dev/null").unwrap();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(REQUEST_FDS))];
        let mut anc = SendAncillaryBuffer::new(&mut space);
        let fds = [null.as_fd(); REQUEST_FDS];
        assert!(anc.push(SendAncillaryMessage::ScmRights(&fds)));
        rustix::net::sendmsg(
            client.as_fd(),
            &[IoSlice::new(&(proto::MAX_REQUEST as u32 + 1).to_le_bytes())],
            &mut anc,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(Incoming::new().read_step(&server).is_err());
    }

    #[test]
    fn status_roundtrip_over_socket() {
        let (client, server) = UnixStream::pair().unwrap();
        send_status(&server, 3 << 8).unwrap();
        assert_eq!(recv_status(&client).unwrap(), 3 << 8);
    }
}
