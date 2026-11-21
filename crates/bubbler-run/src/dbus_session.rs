//! A minimal D-Bus client for the session bus: the few calls bubbler
//! makes on the user's own bus, with file descriptors attached.
//!
//! The document portal takes `O_PATH` descriptors, and no command-line
//! tool passes one on our behalf, so bubbler speaks the protocol itself
//! instead of spawning `dbus-send`.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags, SocketType, recvmsg, sendmsg,
    socket_with,
};

use crate::dbus_wire::{
    BUS_INTERFACE, BUS_NAME, BUS_PATH, CALL_TIMEOUT, ERROR_NO_OWNER, ERROR_SERVICE_UNKNOWN,
    FIELD_DESTINATION, FIELD_INTERFACE, FIELD_MEMBER, FIELD_PATH, FIELD_SIGNATURE, FIELD_UNIX_FDS,
    FIXED_HEADER, MAX_AUTH_LINE, MAX_CALL_FDS, MAX_INCOMING, MAX_REPLY_FDS, MSG_ERROR,
    MSG_METHOD_CALL, MSG_METHOD_RETURN, Message, Value, WireError, check_fd_indices, decode,
    decode_message, encode, encode_message, frame, uid_hex,
};

fn timespec(d: Duration) -> Timespec {
    Timespec {
        tv_sec: d.as_secs() as Secs,
        tv_nsec: d.subsec_nanos() as Nsecs,
    }
}

fn wait(fd: BorrowedFd<'_>, events: PollFlags, deadline: Instant) -> Result<(), WireError> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(WireError::Timeout);
        }
        let mut fds = [PollFd::from_borrowed_fd(fd, events)];
        match poll(&mut fds, Some(&timespec(left))) {
            Ok(0) => return Err(WireError::Timeout),
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => {}
            Err(e) => return Err(WireError::Io(e.into())),
        }
    }
}

/// A connected, authenticated session-bus client that has been given its
/// unique name. Anything but a [`WireError::Remote`] leaves the connection
/// half-read, so the caller drops the session rather than calling again.
#[derive(Debug)]
pub struct Session {
    socket: OwnedFd,
    // An owner that changes mid-session makes the next call fail rather than
    // accept a reply from the wrong sender.
    owners: Vec<(String, String)>,
    fds_seen: usize,
    // "Must not be zero", so the first call sends 1.
    serial: u32,
    unique_name: String,
    fd_passing: bool,
    buf: Vec<u8>,
}

impl Session {
    /// Connect to `path`, authenticate as this uid with `EXTERNAL`, negotiate descriptor
    /// passing and say `Hello`, all inside one [`CALL_TIMEOUT`]. A bus that refuses descriptor
    /// passing is used anyway; a call with descriptors then fails, [`WireError::NoFdPassing`].
    pub fn connect(path: &Path) -> Result<Self, WireError> {
        let deadline = Instant::now() + CALL_TIMEOUT;
        let failed = |source: Errno| WireError::Connect {
            path: path.to_owned(),
            source: source.into(),
        };
        let addr = SocketAddrUnix::new(path).map_err(failed)?;
        // CLOEXEC: nothing bubbler spawns has any business on the bus
        // connection. NONBLOCK: every wait here has a deadline.
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(failed)?;
        match rustix::net::connect(&socket, &addr) {
            Ok(()) => {}
            Err(Errno::INPROGRESS) => {
                wait(socket.as_fd(), PollFlags::OUT, deadline)?;
                match rustix::net::sockopt::socket_error(&socket) {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) | Err(e) => return Err(failed(e)),
                }
            }
            Err(e) => return Err(failed(e)),
        }
        let mut session = Self {
            socket,
            owners: Vec::new(),
            fds_seen: 0,
            serial: 0,
            unique_name: String::new(),
            fd_passing: false,
            buf: Vec::new(),
        };
        session.authenticate(deadline)?;
        session.unique_name = session.hello(deadline)?;
        Ok(session)
    }

    /// The unique name the bus gave this connection, e.g. `:1.42`.
    pub fn unique_name(&self) -> &str {
        &self.unique_name
    }

    /// Whether the bus agreed to descriptor passing on this connection.
    #[cfg(test)]
    pub(crate) fn passes_fds(&self) -> bool {
        self.fd_passing
    }

    /// Call `member` on `iface` of `path` at `dest`, addressed to the unique owner of a well-known
    /// `dest`. One [`CALL_TIMEOUT`] covers the owner lookup, any activation and the reply. An
    /// `ERROR` becomes [`WireError::Remote`] and leaves the session usable; any other, half-read.
    // A destination, an object, an interface, a member, a signature, a
    // body and its descriptors is what a D-Bus method call is.
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &mut self,
        dest: &str,
        path: &str,
        iface: &str,
        member: &str,
        sig: &str,
        body: &[Value],
        fds: &[BorrowedFd<'_>],
    ) -> Result<Vec<Value>, WireError> {
        let deadline = Instant::now() + CALL_TIMEOUT;
        self.call_by(dest, path, iface, member, sig, body, fds, deadline)
    }

    // Against a deadline the caller owns, so the opening handshake and an
    // owner lookup share the call's.
    #[allow(clippy::too_many_arguments)]
    fn call_by(
        &mut self,
        dest: &str,
        path: &str,
        iface: &str,
        member: &str,
        sig: &str,
        body: &[Value],
        fds: &[BorrowedFd<'_>],
        deadline: Instant,
    ) -> Result<Vec<Value>, WireError> {
        if dest.is_empty() {
            return Err(WireError::NoDestination);
        }
        if !fds.is_empty() && !self.fd_passing {
            return Err(WireError::NoFdPassing);
        }
        if fds.len() > MAX_CALL_FDS {
            return Err(WireError::TooManyFds(fds.len()));
        }
        let count = u32::try_from(fds.len()).map_err(|_| WireError::TooManyFds(fds.len()))?;
        for value in body {
            check_fd_indices(value, count)?;
        }

        // Before anything is sent, so the reply has a sender to be held
        // to; the lookup is itself a call, to a name that needs none.
        let owner = self.owner_of(dest, deadline)?;
        let body = encode(sig, body)?;
        // Addressed to the owner: a restart between the lookup and the call is an
        // error from the bus instead of a call served by a different process.
        let mut fields = vec![
            (FIELD_PATH, Value::ObjectPath(path.to_owned())),
            (FIELD_DESTINATION, Value::Str(owner.clone())),
        ];
        // An empty interface is no interface: the member is left to be resolved
        // by the callee, which the specification allows for a method call.
        if !iface.is_empty() {
            fields.push((FIELD_INTERFACE, Value::Str(iface.to_owned())));
        }
        fields.push((FIELD_MEMBER, Value::Str(member.to_owned())));
        if !sig.is_empty() {
            fields.push((FIELD_SIGNATURE, Value::Signature(sig.to_owned())));
        }
        if count > 0 {
            fields.push((FIELD_UNIX_FDS, Value::Uint32(count)));
        }
        self.serial = self.serial.wrapping_add(1).max(1);
        let serial = self.serial;
        let message = encode_message(MSG_METHOD_CALL, 0, serial, &fields, &body)?;
        self.send(&message, fds, deadline)?;

        loop {
            // Checked here as well as inside the read: a peer that keeps sending
            // messages to skip never blocks the reader.
            if Instant::now() >= deadline {
                return Err(WireError::Timeout);
            }
            let reply = self.receive(deadline)?;
            if reply.reply_serial != Some(serial) {
                continue;
            }
            // A signal with a reply serial and an unknown message type "must be ignored":
            // only the two reply types may answer a call.
            if reply.kind != MSG_METHOD_RETURN && reply.kind != MSG_ERROR {
                continue;
            }
            // Serials are guessable, so a reply is only a reply if it came from the name's
            // owner. The bus itself is the exception, and only for an error: "when a method call
            // message cannot be sent or received due to a security policy, the message bus should
            // send an error reply", and it does the same for a peer that went away mid-call.
            // `SENDER` "is controlled by the message bus, so it is as reliable and trustworthy as
            // the message bus itself" — no peer can put the bus's name there.
            match reply.sender.as_deref() {
                Some(sender) if sender == owner => {}
                Some(sender) if sender == BUS_NAME && reply.kind == MSG_ERROR => {}
                Some(_) => continue,
                None => return Err(WireError::BadMessage("a reply with no sender")),
            }
            if reply.fds_arrived != reply.unix_fds as usize {
                return Err(WireError::BadMessage(
                    "a reply with fewer or more descriptors than it declares",
                ));
            }
            if reply.fds_arrived > MAX_REPLY_FDS {
                return Err(WireError::BadMessage("a reply with too many descriptors"));
            }
            return match reply.kind {
                MSG_METHOD_RETURN => decode(&reply.signature, &reply.body),
                MSG_ERROR => {
                    let Some(name) = reply.error_name else {
                        return Err(WireError::BadMessage("an error reply with no error name"));
                    };
                    // Whoever was looked up is not there any more, so the next call
                    // resolves the name again — and starts the service.
                    if name == ERROR_NO_OWNER || name == ERROR_SERVICE_UNKNOWN {
                        self.owners.retain(|(cached, _)| cached != dest);
                    }
                    Err(WireError::Remote {
                        name,
                        // The name is the half that matters, so a body that will not
                        // decode leaves the refusal a refusal rather than a wire failure.
                        message: match decode(&reply.signature, &reply.body) {
                            Ok(values) => match values.first() {
                                Some(Value::Str(text)) => text.clone(),
                                _ => String::new(),
                            },
                            Err(_) => String::new(),
                        },
                    })
                }
                _ => Err(WireError::BadMessage("a reply that is not a reply")),
            };
        }
    }

    // Asking first is what lets the reply be checked, but it also skips the auto-starting
    // a plain call would have done. So a name with no owner is started explicitly.
    fn owner_of(&mut self, dest: &str, deadline: Instant) -> Result<String, WireError> {
        if dest == BUS_NAME || dest.starts_with(':') {
            return Ok(dest.to_owned());
        }
        if let Some((_, owner)) = self.owners.iter().find(|(name, _)| name == dest) {
            return Ok(owner.clone());
        }
        let owner = match self.ask_owner(dest, deadline) {
            Err(WireError::Remote { name, .. }) if name == ERROR_NO_OWNER => {
                self.start_service(dest, deadline)?;
                self.ask_owner(dest, deadline)?
            }
            other => other?,
        };
        self.owners.push((dest.to_owned(), owner.clone()));
        Ok(owner)
    }

    fn ask_owner(&mut self, dest: &str, deadline: Instant) -> Result<String, WireError> {
        let reply = self.call_by(
            BUS_NAME,
            BUS_PATH,
            BUS_INTERFACE,
            "GetNameOwner",
            "s",
            &[Value::Str(dest.to_owned())],
            &[],
            deadline,
        )?;
        let [Value::Str(owner)] = reply.as_slice() else {
            return Err(WireError::BadMessage(
                "a GetNameOwner reply that is not one name",
            ));
        };
        if !owner.starts_with(':') {
            return Err(WireError::BadMessage("a name owner that is not unique"));
        }
        Ok(owner.clone())
    }

    // The result code is not read: neither started nor already running is a
    // guarantee the service is still there, and the lookup that follows decides.
    fn start_service(&mut self, dest: &str, deadline: Instant) -> Result<(), WireError> {
        self.call_by(
            BUS_NAME,
            BUS_PATH,
            BUS_INTERFACE,
            "StartServiceByName",
            "su",
            &[Value::Str(dest.to_owned()), Value::Uint32(0)],
            &[],
            deadline,
        )?;
        Ok(())
    }

    fn authenticate(&mut self, deadline: Instant) -> Result<(), WireError> {
        let uid = rustix::process::getuid().as_raw();
        // "Immediately after connecting to the server, the client must
        // send a single nul byte", which may carry credentials with it.
        let hello = format!("\0AUTH EXTERNAL {}\r\n", uid_hex(uid));
        self.send(hello.as_bytes(), &[], deadline)?;
        let line = self.line(deadline)?;
        if let Some(rest) = line.strip_prefix("REJECTED") {
            return Err(WireError::AuthRejected(rest.trim().to_owned()));
        }
        if !line.starts_with("OK ") {
            return Err(WireError::Auth(line));
        }
        self.send(b"NEGOTIATE_UNIX_FD\r\n", &[], deadline)?;
        let line = self.line(deadline)?;
        if line == "AGREE_UNIX_FD" {
            self.fd_passing = true;
        } else if !line.starts_with("ERROR") {
            return Err(WireError::Auth(line));
        }
        // "The server does not reply" to BEGIN.
        self.send(b"BEGIN\r\n", &[], deadline)?;
        Ok(())
    }

    // "Unique connection names must begin with the character ':'": a
    // name that does not is not one the bus assigned.
    fn hello(&mut self, deadline: Instant) -> Result<String, WireError> {
        let reply = self.call_by(
            BUS_NAME,
            BUS_PATH,
            BUS_INTERFACE,
            "Hello",
            "",
            &[],
            &[],
            deadline,
        )?;
        let [Value::Str(name)] = reply.as_slice() else {
            return Err(WireError::BadMessage("a Hello reply that is not one name"));
        };
        if !name.starts_with(':') {
            return Err(WireError::BadMessage(
                "a Hello reply that is not a unique name",
            ));
        }
        Ok(name.clone())
    }

    fn line(&mut self, deadline: Instant) -> Result<String, WireError> {
        loop {
            if let Some(end) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..end + 2).take(end).collect();
                if !line.is_ascii() {
                    return Err(WireError::Auth(String::from_utf8_lossy(&line).into_owned()));
                }
                return String::from_utf8(line).map_err(|_| WireError::BadString);
            }
            if self.buf.len() > MAX_AUTH_LINE {
                return Err(WireError::Auth("a line with no end".to_owned()));
            }
            self.fill(MAX_AUTH_LINE, deadline)?;
        }
    }

    // `fds` go with the first `sendmsg`: descriptors "may not be sent before the first
    // byte of the message itself is transferred or after the last byte".
    fn send(
        &self,
        bytes: &[u8],
        fds: &[BorrowedFd<'_>],
        deadline: Instant,
    ) -> Result<(), WireError> {
        let mut sent = 0;
        let mut carried = fds;
        while sent < bytes.len() {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_CALL_FDS))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            if !carried.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(carried)) {
                return Err(WireError::TooManyFds(carried.len()));
            }
            // NOSIGNAL: a bus that goes away is an error to return, not a
            // signal that kills bubbler.
            match sendmsg(
                &self.socket,
                &[IoSlice::new(&bytes[sent..])],
                &mut ancillary,
                SendFlags::NOSIGNAL,
            ) {
                Ok(0) => return Err(WireError::Closed),
                Ok(n) => {
                    sent += n;
                    carried = &[];
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    wait(self.socket.as_fd(), PollFlags::OUT, deadline)?;
                }
                Err(e) => return Err(WireError::Io(e.into())),
            }
        }
        Ok(())
    }

    // Any descriptor that arrives is closed at once: no call bubbler makes expects one
    // back, and one left open would be a descriptor the bus chose for us to hold.
    fn fill(&mut self, most: usize, deadline: Instant) -> Result<(), WireError> {
        let mut chunk = [0u8; 4096];
        let chunk = &mut chunk[..most.min(4096)];
        loop {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_REPLY_FDS))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            match recvmsg(
                &self.socket,
                &mut [IoSliceMut::new(chunk)],
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            ) {
                Ok(got) => {
                    for message in ancillary.drain() {
                        if let RecvAncillaryMessage::ScmRights(fds) = message {
                            for fd in fds {
                                self.fds_seen += 1;
                                drop(fd);
                            }
                        }
                    }
                    if got.bytes == 0 {
                        return Err(WireError::Closed);
                    }
                    self.buf.extend_from_slice(&chunk[..got.bytes]);
                    return Ok(());
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    wait(self.socket.as_fd(), PollFlags::IN, deadline)?;
                }
                Err(e) => return Err(WireError::Io(e.into())),
            }
        }
    }

    // No read goes past the end of the message, so none of the next one's descriptors
    // arrive with it. A message that is big-endian, longer than [`MAX_INCOMING`] or whose header
    // will not decode is skipped, since nothing in it can be trusted to say it is the reply.
    fn receive(&mut self, deadline: Instant) -> Result<Message, WireError> {
        loop {
            let mut want = FIXED_HEADER;
            if self.buf.len() >= FIXED_HEADER {
                let (body_at, body_len) = frame(&self.buf)?;
                want = body_at + body_len;
                if want > MAX_INCOMING {
                    self.discard(want, deadline)?;
                    continue;
                }
                if self.buf.len() >= want {
                    let bytes: Vec<u8> = self.buf.drain(..want).collect();
                    let fds_arrived = std::mem::take(&mut self.fds_seen);
                    match decode_message(&bytes) {
                        Ok(message) => {
                            return Ok(Message {
                                fds_arrived,
                                ..message
                            });
                        }
                        Err(_) => continue,
                    }
                }
            }
            // A message already whole is handed over above whatever the
            // clock says; it is only reading more that has to give up.
            if Instant::now() >= deadline {
                return Err(WireError::Timeout);
            }
            self.fill(want - self.buf.len(), deadline)?;
        }
    }

    fn discard(&mut self, total: usize, deadline: Instant) -> Result<(), WireError> {
        let mut left = total - self.buf.len();
        self.buf.clear();
        while left > 0 {
            if Instant::now() >= deadline {
                return Err(WireError::Timeout);
            }
            self.fill(left, deadline)?;
            left -= self.buf.len();
            self.buf.clear();
        }
        self.fds_seen = 0;
        Ok(())
    }
}

/// The fake bus every module's tests script: one connection, the
/// `EXTERNAL` handshake, and replies written from the bus's side.
///
/// It lives here because the client under it does: a second copy of this
/// harness is a second idea of what a bus sends, and the first thing to
/// go out of step is the `SENDER` the client checks.
#[cfg(test)]
pub(crate) mod testing {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::thread::JoinHandle;

    use super::*;
    use crate::dbus_wire::*;

    /// The header field codes and message types a script names, bound to
    /// the encoder's own so a test cannot assert on a number the wire
    /// does not use.
    pub(crate) const BUS_NAME: &str = crate::dbus_wire::BUS_NAME;
    pub(crate) const FIELD_PATH: u8 = crate::dbus_wire::FIELD_PATH;
    pub(crate) const FIELD_INTERFACE: u8 = crate::dbus_wire::FIELD_INTERFACE;
    pub(crate) const FIELD_MEMBER: u8 = crate::dbus_wire::FIELD_MEMBER;
    pub(crate) const FIELD_ERROR_NAME: u8 = crate::dbus_wire::FIELD_ERROR_NAME;
    pub(crate) const FIELD_REPLY_SERIAL: u8 = crate::dbus_wire::FIELD_REPLY_SERIAL;
    pub(crate) const FIELD_DESTINATION: u8 = crate::dbus_wire::FIELD_DESTINATION;
    pub(crate) const FIELD_SENDER: u8 = crate::dbus_wire::FIELD_SENDER;
    pub(crate) const FIELD_SIGNATURE: u8 = crate::dbus_wire::FIELD_SIGNATURE;
    pub(crate) const MSG_METHOD_RETURN: u8 = crate::dbus_wire::MSG_METHOD_RETURN;
    pub(crate) const MSG_ERROR: u8 = crate::dbus_wire::MSG_ERROR;

    /// Longest a script waits for the client, and the client for a
    /// connection: a test that stops talking fails its join rather than
    /// hanging the run.
    pub(crate) const SCRIPT_TIMEOUT: Duration = Duration::from_secs(20);

    /// One method call as the bus saw it.
    pub(crate) struct Call {
        /// Header fields in the order the client wrote them.
        pub(crate) fields: Vec<(u8, Value)>,
        /// Signature of the body, empty when there is none.
        pub(crate) signature: String,
        /// The body, decoded against that signature.
        pub(crate) body: Vec<Value>,
        /// Serial the reply must name.
        pub(crate) serial: u32,
        /// Descriptors the call carried.
        pub(crate) fds: Vec<OwnedFd>,
    }

    impl Call {
        /// The text of a header field, e.g. the member name.
        pub(crate) fn text(&self, code: u8) -> String {
            match self.fields.iter().find(|(c, _)| *c == code) {
                Some((_, Value::Str(text) | Value::ObjectPath(text))) => text.clone(),
                other => panic!("header field {code} is {other:?}"),
            }
        }

        /// Every textual header field, in the order it was written: what
        /// the client asked, and of whom.
        pub(crate) fn texts(&self) -> Vec<(u8, String)> {
            self.fields
                .iter()
                .map(|(code, value)| {
                    let text = match value {
                        Value::Str(s) | Value::ObjectPath(s) | Value::Signature(s) => s.clone(),
                        other => format!("{other:?}"),
                    };
                    (*code, text)
                })
                .collect()
        }
    }

    /// The serial of a message: the second UINT32 of its header.
    pub(crate) fn serial_of(message: &[u8]) -> u32 {
        u32::from_le_bytes([message[8], message[9], message[10], message[11]])
    }

    /// A bus on a socket under `dir` that runs `script` on the one
    /// connection it accepts.
    pub(crate) fn fake_bus<F>(dir: &Path, script: F) -> (PathBuf, JoinHandle<()>)
    where
        F: FnOnce(UnixStream) + Send + 'static,
    {
        let path = dir.join("bus");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            // Both waits are bounded before either happens: a client
            // that never connects, or one that stops mid-message, fails
            // the join instead of hanging the run.
            wait(
                listener.as_fd(),
                PollFlags::IN,
                Instant::now() + SCRIPT_TIMEOUT,
            )
            .expect("a client connected");
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(SCRIPT_TIMEOUT)).unwrap();
            script(stream);
        });
        (path, handle)
    }

    /// One `\r\n` line from the client, read a byte at a time so none of
    /// the message stream that follows `BEGIN` is swallowed.
    pub(crate) fn server_line(stream: &UnixStream) -> String {
        let mut out = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            (&*stream).read_exact(&mut byte).unwrap();
            out.push(byte[0]);
            if out.ends_with(b"\r\n") {
                out.truncate(out.len() - 2);
                return String::from_utf8(out).unwrap();
            }
        }
    }

    /// The `EXTERNAL` handshake from the bus's side, as the
    /// specification's Figure 7 (or Figure 8 with `agree` false) has it.
    pub(crate) fn server_auth(stream: &UnixStream, agree: bool) {
        let uid = rustix::process::getuid().as_raw();
        assert_eq!(
            server_line(stream),
            format!("\0AUTH EXTERNAL {}", uid_hex(uid))
        );
        (&*stream).write_all(b"OK 1234deadbeef\r\n").unwrap();
        assert_eq!(server_line(stream), "NEGOTIATE_UNIX_FD");
        let reply: &[u8] = if agree {
            b"AGREE_UNIX_FD\r\n"
        } else {
            b"ERROR not on this transport\r\n"
        };
        (&*stream).write_all(reply).unwrap();
        assert_eq!(server_line(stream), "BEGIN");
    }

    /// One whole message from the client, with any descriptors it carried.
    pub(crate) fn server_message(stream: &UnixStream) -> (Vec<u8>, Vec<OwnedFd>) {
        let mut buf: Vec<u8> = Vec::new();
        let mut fds = Vec::new();
        loop {
            if buf.len() >= FIXED_HEADER {
                let (body_at, body_len) = frame(&buf).unwrap();
                if buf.len() >= body_at + body_len {
                    buf.truncate(body_at + body_len);
                    return (buf, fds);
                }
            }
            let mut chunk = [0u8; 4096];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            let got = recvmsg(
                stream.as_fd(),
                &mut [IoSliceMut::new(&mut chunk)],
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            )
            .unwrap();
            for message in ancillary.drain() {
                if let RecvAncillaryMessage::ScmRights(received) = message {
                    fds.extend(received);
                }
            }
            assert!(got.bytes > 0, "the client hung up mid-message");
            buf.extend_from_slice(&chunk[..got.bytes]);
        }
    }

    /// Send one message from the bus's side.
    pub(crate) fn server_send(
        stream: &UnixStream,
        kind: u8,
        serial: u32,
        fields: &[(u8, Value)],
        sig: &str,
        body: &[Value],
    ) {
        let mut fields = fields.to_vec();
        if !sig.is_empty() {
            fields.push((FIELD_SIGNATURE, Value::Signature(sig.to_owned())));
        }
        let body = encode(sig, body).unwrap();
        let message = encode_message(kind, 0, serial, &fields, &body).unwrap();
        (&*stream).write_all(&message).unwrap();
    }

    /// A `METHOD_RETURN` to the call with serial `reply_to`, from
    /// `sender` — the bus fills that field in, so every reply has one.
    pub(crate) fn server_reply(
        stream: &UnixStream,
        serial: u32,
        reply_to: u32,
        sender: &str,
        sig: &str,
        body: &[Value],
    ) {
        server_send(
            stream,
            MSG_METHOD_RETURN,
            serial,
            &[
                (FIELD_REPLY_SERIAL, Value::Uint32(reply_to)),
                (FIELD_SENDER, Value::Str(sender.to_owned())),
            ],
            sig,
            body,
        );
    }

    /// The bytes of a `METHOD_RETURN`, for a test that writes them itself.
    pub(crate) fn reply_bytes(
        serial: u32,
        reply_to: u32,
        sender: &str,
        sig: &str,
        body: &[Value],
    ) -> Vec<u8> {
        let mut fields = vec![
            (FIELD_REPLY_SERIAL, Value::Uint32(reply_to)),
            (FIELD_SENDER, Value::Str(sender.to_owned())),
        ];
        if !sig.is_empty() {
            fields.push((FIELD_SIGNATURE, Value::Signature(sig.to_owned())));
        }
        let body = encode(sig, body).unwrap();
        encode_message(MSG_METHOD_RETURN, 0, serial, &fields, &body).unwrap()
    }

    /// A signal, which a pending call must skip whatever it carries.
    pub(crate) fn signal_bytes(serial: u32, reply_serial: Option<u32>) -> Vec<u8> {
        let mut fields = vec![
            (FIELD_PATH, Value::ObjectPath("/org/a".to_owned())),
            (FIELD_INTERFACE, Value::Str("org.a".to_owned())),
            (FIELD_MEMBER, Value::Str("Changed".to_owned())),
            (FIELD_SENDER, Value::Str(":1.5".to_owned())),
            (FIELD_SIGNATURE, Value::Signature("s".to_owned())),
        ];
        if let Some(reply_serial) = reply_serial {
            fields.push((FIELD_REPLY_SERIAL, Value::Uint32(reply_serial)));
        }
        let body = encode("s", &[Value::Str("ignore me".to_owned())]).unwrap();
        encode_message(4, 0, serial, &fields, &body).unwrap()
    }

    /// Answer the `Hello` every connection opens with, and return the
    /// bytes of the call so a test can look at them.
    pub(crate) fn server_hello(stream: &UnixStream, name: &str) -> Vec<u8> {
        let (bytes, fds) = server_message(stream);
        assert!(fds.is_empty());
        server_reply(
            stream,
            1,
            serial_of(&bytes),
            BUS_NAME,
            "s",
            &[Value::Str(name.to_owned())],
        );
        bytes
    }

    /// The `EXTERNAL` handshake and the `Hello` every connection opens
    /// with, from the bus's side.
    pub(crate) fn server_start(stream: &UnixStream) {
        server_auth(stream, true);
        server_hello(stream, ":1.5");
    }

    /// One whole method call from the client, decoded.
    pub(crate) fn server_call(stream: &UnixStream) -> Call {
        let (bytes, fds) = server_message(stream);
        let fields_len = u32::from_le_bytes(
            bytes[12..16]
                .try_into()
                .expect("a header the framing accepted"),
        ) as usize;
        let header = decode("yyyyuua(yv)", &bytes[..FIXED_HEADER + fields_len]).unwrap();
        let (Value::Uint32(serial), Value::Array(raw)) = (&header[5], &header[6]) else {
            panic!("a header that is not a header: {header:?}");
        };
        let fields: Vec<(u8, Value)> = raw
            .iter()
            .map(|field| match field {
                Value::Struct(pair) => match pair.as_slice() {
                    [Value::Byte(code), Value::Variant(value)] => (*code, (**value).clone()),
                    other => panic!("a header field that is not one: {other:?}"),
                },
                other => panic!("a header field that is not one: {other:?}"),
            })
            .collect();
        let signature = match fields.iter().find(|(code, _)| *code == FIELD_SIGNATURE) {
            Some((_, Value::Signature(sig))) => sig.clone(),
            _ => String::new(),
        };
        let body = decode(&signature, &bytes[align_up(FIXED_HEADER + fields_len, 8)..]).unwrap();
        Call {
            fields,
            signature,
            body,
            serial: *serial,
            fds,
        }
    }

    /// The next call to `member` the client makes. A lookup of who owns
    /// the destination is answered with `owner` on the way, since the
    /// client holds the reply to the unique name the bus names here.
    pub(crate) fn server_awaiting(stream: &UnixStream, member: &str, owner: &str) -> Call {
        loop {
            let call = server_call(stream);
            let asked = call.text(FIELD_MEMBER);
            if asked == member {
                return call;
            }
            assert_eq!(asked, "GetNameOwner", "the client called {asked}");
            server_reply(
                stream,
                1,
                call.serial,
                BUS_NAME,
                "s",
                &[Value::Str(owner.to_owned())],
            );
        }
    }

    /// An `ERROR` reply from `sender` to the call with serial `reply_to`.
    pub(crate) fn server_error(
        stream: &UnixStream,
        reply_to: u32,
        sender: &str,
        name: &str,
        message: &str,
    ) {
        server_send(
            stream,
            MSG_ERROR,
            1,
            &[
                (FIELD_REPLY_SERIAL, Value::Uint32(reply_to)),
                (FIELD_SENDER, Value::Str(sender.to_owned())),
                (FIELD_ERROR_NAME, Value::Str(name.to_owned())),
            ],
            "s",
            &[Value::Str(message.to_owned())],
        );
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    use super::testing::{
        fake_bus, reply_bytes, serial_of, server_auth, server_awaiting, server_call, server_error,
        server_hello, server_line, server_message, server_reply, server_send, server_start,
        signal_bytes,
    };
    use super::*;
    use crate::dbus_wire::*;

    #[test]
    fn a_session_authenticates_says_hello_and_makes_a_call() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            // What goes out first is the frame pinned above, unchanged.
            assert_eq!(server_hello(&stream, ":1.42"), HELLO_FRAME);
            let (bytes, _) = server_message(&stream);
            let call = decode_message(&bytes).unwrap();
            assert_eq!(call.kind, MSG_METHOD_CALL);
            server_reply(
                &stream,
                2,
                serial_of(&bytes),
                BUS_NAME,
                "s",
                &[Value::Str("deadbeef".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        assert_eq!(session.unique_name(), ":1.42");
        assert!(session.passes_fds());
        let reply = session
            .call(BUS_NAME, BUS_PATH, BUS_INTERFACE, "GetId", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("deadbeef".to_owned())]);
        // Nothing is sent for a call that names nobody: a reply to it
        // could not be attributed to an owner.
        let err = session
            .call("", BUS_PATH, BUS_INTERFACE, "GetId", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::NoDestination), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn signals_and_replies_to_other_calls_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.9");
            let (bytes, _) = server_message(&stream);
            // A signal with no reply serial at all, then a reply to a
            // call this connection never made.
            (&stream).write_all(&signal_bytes(7, None)).unwrap();
            server_reply(
                &stream,
                8,
                999,
                BUS_NAME,
                "s",
                &[Value::Str("not yours".to_owned())],
            );
            // A signal that carries the pending serial: "if a signal has
            // a reply serial it must be ignored".
            (&stream)
                .write_all(&signal_bytes(10, Some(serial_of(&bytes))))
                .unwrap();
            server_reply(
                &stream,
                9,
                serial_of(&bytes),
                BUS_NAME,
                "s",
                &[Value::Str("yours".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(BUS_NAME, BUS_PATH, BUS_INTERFACE, "GetId", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("yours".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn an_error_reply_names_the_error_and_leaves_the_session_usable() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.10");
            let (bytes, _) = server_message(&stream);
            server_send(
                &stream,
                MSG_ERROR,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (
                        FIELD_ERROR_NAME,
                        Value::Str("org.freedesktop.portal.Error.NotAllowed".to_owned()),
                    ),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                ],
                "s",
                &[Value::Str("no".to_owned())],
            );
            let (bytes, _) = server_message(&stream);
            server_reply(
                &stream,
                3,
                serial_of(&bytes),
                ":1.5",
                "u",
                &[Value::Uint32(1)],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Denied", "", &[], &[])
            .unwrap_err();
        match err {
            WireError::Remote { name, message } => {
                assert_eq!(name, "org.freedesktop.portal.Error.NotAllowed");
                assert_eq!(message, "no");
            }
            other => panic!("{other:?}"),
        }
        // The connection is still good: an error is an answer.
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Allowed", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Uint32(1)]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_refused_mechanism_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_line(&stream);
            (&stream)
                .write_all(b"REJECTED DBUS_COOKIE_SHA1 ANONYMOUS\r\n")
                .unwrap();
        });
        let err = Session::connect(&path).unwrap_err();
        assert!(
            matches!(&err, WireError::AuthRejected(m) if m == "DBUS_COOKIE_SHA1 ANONYMOUS"),
            "{err:?}"
        );
        server.join().unwrap();
    }

    #[test]
    fn a_bus_that_will_not_pass_descriptors_refuses_a_call_that_carries_one() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, false);
            server_hello(&stream, ":1.11");
        });
        let mut session = Session::connect(&path).unwrap();
        assert!(!session.passes_fds());
        let file = std::fs::File::open(tmp.path()).unwrap();
        let err = session
            .call(
                ":1.5",
                "/org/a",
                "org.a",
                "Take",
                "h",
                &[Value::Fd(0)],
                &[file.as_fd()],
            )
            .unwrap_err();
        assert!(matches!(err, WireError::NoFdPassing), "{err:?}");
        // A call carrying nothing still works on such a connection.
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_descriptor_reaches_the_far_side_of_the_bus() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("doc");
        std::fs::write(&file_path, b"twelve bytes").unwrap();
        let want = rustix::fs::stat(&file_path).unwrap();
        let (path, server) = fake_bus(tmp.path(), move |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.12");
            let (bytes, fds) = server_message(&stream);
            let call = decode_message(&bytes).unwrap();
            assert_eq!(call.signature, "ahs");
            assert_eq!(
                decode(&call.signature, &call.body).unwrap(),
                vec![
                    Value::Array(vec![Value::Fd(0)]),
                    Value::Str("read".to_owned())
                ]
            );
            assert_eq!(fds.len(), 1);
            // The descriptor names the same file, not a copy of a path.
            let got = rustix::fs::fstat(&fds[0]).unwrap();
            assert_eq!(
                (got.st_dev, got.st_ino, got.st_size),
                (want.st_dev, want.st_ino, want.st_size)
            );
            server_reply(
                &stream,
                2,
                serial_of(&bytes),
                ":1.5",
                "as",
                &[Value::Array(vec![Value::Str("1a2b".to_owned())])],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let file = std::fs::File::open(&file_path).unwrap();
        // A body naming a descriptor the call was not given never leaves.
        let err = session
            .call(
                ":1.5",
                "/org/a",
                "org.a",
                "AddFull",
                "ahs",
                &[
                    Value::Array(vec![Value::Fd(3)]),
                    Value::Str("read".to_owned()),
                ],
                &[file.as_fd()],
            )
            .unwrap_err();
        assert!(matches!(err, WireError::FdIndex(3)), "{err:?}");
        let reply = session
            .call(
                ":1.5",
                "/org/a",
                "org.a",
                "AddFull",
                "ahs",
                &[
                    Value::Array(vec![Value::Fd(0)]),
                    Value::Str("read".to_owned()),
                ],
                &[file.as_fd()],
            )
            .unwrap();
        assert_eq!(
            reply,
            vec![Value::Array(vec![Value::Str("1a2b".to_owned())])]
        );
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_bus_that_says_nothing_times_the_call_out() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            // Accept the connection and never answer: the client must
            // give up on its own deadline rather than park forever.
            server_line(&stream);
            std::thread::sleep(CALL_TIMEOUT + Duration::from_secs(1));
        });
        let started = Instant::now();
        let err = Session::connect(&path).unwrap_err();
        assert!(matches!(err, WireError::Timeout), "{err:?}");
        assert!(started.elapsed() >= CALL_TIMEOUT);
        server.join().unwrap();
    }

    /// Send one message with descriptors attached, the way a reply that
    /// carries them would arrive.
    fn server_send_fds(stream: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(fds)));
        let sent = sendmsg(
            stream.as_fd(),
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert_eq!(sent, bytes.len());
    }

    #[test]
    fn a_reply_from_anyone_but_the_owner_of_the_name_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.15");
            // A call to a well-known name asks the bus who owns it first.
            let (bytes, _) = server_message(&stream);
            assert_eq!(
                decode("s", &decode_message(&bytes).unwrap().body).unwrap(),
                vec![Value::Str("org.freedesktop.portal.Documents".to_owned())]
            );
            server_reply(
                &stream,
                2,
                serial_of(&bytes),
                BUS_NAME,
                "s",
                &[Value::Str(":1.77".to_owned())],
            );
            let (bytes, _) = server_message(&stream);
            // Another peer on the bus guesses the serial and answers
            // first, choosing the path bubbler would go on to use.
            server_reply(
                &stream,
                3,
                serial_of(&bytes),
                ":1.99",
                "s",
                &[Value::Str("/forged".to_owned())],
            );
            server_reply(
                &stream,
                4,
                serial_of(&bytes),
                ":1.77",
                "s",
                &[Value::Str("/genuine".to_owned())],
            );
            // The owner is remembered, so the second call asks nothing.
            let (bytes, _) = server_message(&stream);
            server_reply(
                &stream,
                5,
                serial_of(&bytes),
                ":1.77",
                "s",
                &[Value::Str("/again".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        for want in ["/genuine", "/again"] {
            let reply = session
                .call(
                    "org.freedesktop.portal.Documents",
                    "/org/freedesktop/portal/documents",
                    "org.freedesktop.portal.Documents",
                    "GetMountPoint",
                    "",
                    &[],
                    &[],
                )
                .unwrap();
            assert_eq!(reply, vec![Value::Str(want.to_owned())]);
        }
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_reply_with_no_sender_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.16");
            let (bytes, _) = server_message(&stream);
            server_send(
                &stream,
                MSG_METHOD_RETURN,
                2,
                &[(FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes)))],
                "s",
                &[Value::Str("from nobody".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_hello_reply_that_is_not_a_unique_name_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            let (bytes, _) = server_message(&stream);
            server_reply(
                &stream,
                1,
                serial_of(&bytes),
                BUS_NAME,
                "s",
                &[Value::Str("org.not.unique".to_owned())],
            );
        });
        let err = Session::connect(&path).unwrap_err();
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        server.join().unwrap();
    }

    #[test]
    fn an_error_reply_with_no_name_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.17");
            let (bytes, _) = server_message(&stream);
            server_send(
                &stream,
                MSG_ERROR,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                ],
                "s",
                &[Value::Str("nameless".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        // Never an invented name: a refusal bubbler cannot name is a
        // failure, not `org.freedesktop.DBus.Error.Failed`.
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_flood_of_messages_to_skip_does_not_outlast_the_deadline() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.18");
            let (bytes, _) = server_message(&stream);
            // Never the reply: always one more message to skip, so the
            // reader never waits and the deadline is all that ends it.
            let signal = signal_bytes(7, Some(serial_of(&bytes)));
            while (&stream).write_all(&signal).is_ok() {}
        });
        let mut session = Session::connect(&path).unwrap();
        let started = Instant::now();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Wait", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::Timeout), "{err:?}");
        assert!(started.elapsed() >= CALL_TIMEOUT, "{:?}", started.elapsed());
        assert!(
            started.elapsed() < CALL_TIMEOUT * 3,
            "{:?}",
            started.elapsed()
        );
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_reply_delivered_one_byte_at_a_time_is_assembled() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.19");
            let (bytes, _) = server_message(&stream);
            let reply = reply_bytes(
                2,
                serial_of(&bytes),
                ":1.5",
                "s",
                &[Value::Str("assembled".to_owned())],
            );
            for byte in reply {
                (&stream).write_all(&[byte]).unwrap();
            }
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("assembled".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn two_messages_in_one_write_are_read_one_at_a_time() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.20");
            let (bytes, _) = server_message(&stream);
            let mut both = signal_bytes(7, None);
            both.extend_from_slice(&reply_bytes(
                8,
                serial_of(&bytes),
                ":1.5",
                "s",
                &[Value::Str("second".to_owned())],
            ));
            (&stream).write_all(&both).unwrap();
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("second".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn descriptors_a_reply_carries_are_closed() {
        let tmp = tempfile::tempdir().unwrap();
        // Three copies of a pipe's write end: once every copy is closed
        // the read end reports end of file, and nothing else can.
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let (path, server) = fake_bus(tmp.path(), move |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.21");
            let (bytes, _) = server_message(&stream);
            let body = encode("s", &[Value::Str("ok".to_owned())]).unwrap();
            let message = encode_message(
                MSG_METHOD_RETURN,
                0,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                    (FIELD_SIGNATURE, Value::Signature("s".to_owned())),
                    (FIELD_UNIX_FDS, Value::Uint32(3)),
                ],
                &body,
            )
            .unwrap();
            let carried = [write.as_fd(), write.as_fd(), write.as_fd()];
            server_send_fds(&stream, &message, &carried);
            drop(write);
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("ok".to_owned())]);
        server.join().unwrap();
        let mut fds = [PollFd::from_borrowed_fd(read.as_fd(), PollFlags::IN)];
        assert_eq!(
            poll(&mut fds, Some(&timespec(Duration::from_secs(5)))).unwrap(),
            1,
            "the pipe never hung up, so a copy of the descriptor is still open"
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            std::fs::File::from(read).read(&mut byte).unwrap(),
            0,
            "the pipe still has a writer, so a received descriptor was kept"
        );
        drop(session);
    }

    #[test]
    fn a_reply_carrying_one_descriptor_past_the_cap_is_refused() {
        const SENT: usize = MAX_REPLY_FDS + 1;
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.23");
            let (bytes, _) = server_message(&stream);
            let body = encode("s", &[Value::Str("five".to_owned())]).unwrap();
            let message = encode_message(
                MSG_METHOD_RETURN,
                0,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                    (FIELD_SIGNATURE, Value::Signature("s".to_owned())),
                    (FIELD_UNIX_FDS, Value::Uint32(SENT as u32)),
                ],
                &body,
            )
            .unwrap();
            server_send_fds(&stream, &message, &[stream.as_fd(); SENT]);
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_message_that_declares_descriptors_it_did_not_send_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.22");
            let (bytes, _) = server_message(&stream);
            server_send(
                &stream,
                MSG_METHOD_RETURN,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                    (FIELD_UNIX_FDS, Value::Uint32(3)),
                ],
                "s",
                &[Value::Str("three, honest".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    /// A well-known name, which is what a call has to look up.
    const A_NAME: &str = "org.example.Service";

    #[test]
    fn an_error_the_bus_sends_itself_answers_a_call_to_a_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_awaiting(&stream, "Ask", ":1.77");
            // The peer went away between the lookup and the call, so the
            // answer comes from the bus and not from the owner.
            server_error(
                &stream,
                call.serial,
                BUS_NAME,
                "org.freedesktop.DBus.Error.ServiceUnknown",
                "no such service",
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let started = Instant::now();
        let err = session
            .call(A_NAME, "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        match err {
            WireError::Remote { name, .. } => {
                assert_eq!(name, "org.freedesktop.DBus.Error.ServiceUnknown");
            }
            other => panic!("{other:?}"),
        }
        // Answered, not waited out.
        assert!(started.elapsed() < CALL_TIMEOUT, "{:?}", started.elapsed());
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn an_activatable_name_is_started_and_looked_up_again() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            // Nobody holds the name yet, which for an activatable one
            // only means it has not been started.
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_MEMBER), "GetNameOwner");
            assert_eq!(call.body, vec![Value::Str(A_NAME.to_owned())]);
            server_error(&stream, call.serial, BUS_NAME, ERROR_NO_OWNER, "no owner");
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_MEMBER), "StartServiceByName");
            assert_eq!(call.signature, "su");
            assert_eq!(
                call.body,
                vec![Value::Str(A_NAME.to_owned()), Value::Uint32(0)]
            );
            server_reply(&stream, 2, call.serial, BUS_NAME, "u", &[Value::Uint32(1)]);
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_MEMBER), "GetNameOwner");
            server_reply(
                &stream,
                3,
                call.serial,
                BUS_NAME,
                "s",
                &[Value::Str(":1.77".to_owned())],
            );
            let call = server_call(&stream);
            // Addressed to the owner the lookup named, not to the name.
            assert_eq!(call.text(FIELD_DESTINATION), ":1.77");
            assert_eq!(call.text(FIELD_MEMBER), "Ask");
            server_reply(
                &stream,
                4,
                call.serial,
                ":1.77",
                "s",
                &[Value::Str("started".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(A_NAME, "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("started".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_name_the_bus_cannot_start_comes_back_as_the_bus_said() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_call(&stream);
            server_error(&stream, call.serial, BUS_NAME, ERROR_NO_OWNER, "no owner");
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_MEMBER), "StartServiceByName");
            server_error(
                &stream,
                call.serial,
                BUS_NAME,
                "org.freedesktop.DBus.Error.ServiceUnknown",
                "not installed",
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(A_NAME, "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        // Why it could not be started, not merely that nobody holds it.
        match err {
            WireError::Remote { name, .. } => {
                assert_eq!(name, "org.freedesktop.DBus.Error.ServiceUnknown");
            }
            other => panic!("{other:?}"),
        }
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_forged_answer_to_the_owner_lookup_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_MEMBER), "GetNameOwner");
            // A peer answers the lookup first, naming a connection of
            // its choosing; only the bus may say who owns a name.
            server_reply(
                &stream,
                2,
                call.serial,
                ":1.99",
                "s",
                &[Value::Str(":1.13".to_owned())],
            );
            server_reply(
                &stream,
                3,
                call.serial,
                BUS_NAME,
                "s",
                &[Value::Str(":1.77".to_owned())],
            );
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_DESTINATION), ":1.77");
            server_reply(
                &stream,
                4,
                call.serial,
                ":1.77",
                "s",
                &[Value::Str("real".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(A_NAME, "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("real".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_message_of_an_unknown_type_carrying_the_serial_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_awaiting(&stream, "Ask", ":1.77");
            // Type 9 is not a type this specification has: "unknown
            // types must be ignored", serial and sender notwithstanding.
            server_send(
                &stream,
                9,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(call.serial)),
                    (FIELD_SENDER, Value::Str(":1.77".to_owned())),
                ],
                "s",
                &[Value::Str("not a reply".to_owned())],
            );
            server_reply(
                &stream,
                3,
                call.serial,
                ":1.77",
                "s",
                &[Value::Str("the reply".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(A_NAME, "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("the reply".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    fn reply_behind(stray: impl FnOnce(&UnixStream, u32) + Send + 'static) -> Vec<Value> {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), move |stream| {
            server_start(&stream);
            let (bytes, _) = server_message(&stream);
            stray(&stream, serial_of(&bytes));
            server_reply(
                &stream,
                3,
                serial_of(&bytes),
                ":1.5",
                "s",
                &[Value::Str("the reply".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        drop(session);
        server.join().unwrap();
        reply
    }

    #[test]
    fn a_big_endian_message_before_the_reply_is_skipped() {
        let reply = reply_behind(|stream, _| {
            // Eight bytes of header fields, a length that read
            // little-endian would be past every limit.
            let mut message = vec![b'B', 4, 0, PROTOCOL_VERSION];
            message.extend_from_slice(&0u32.to_be_bytes());
            message.extend_from_slice(&7u32.to_be_bytes());
            message.extend_from_slice(&8u32.to_be_bytes());
            message.extend_from_slice(&[0; 8]);
            (&*stream).write_all(&message).unwrap();
        });
        assert_eq!(reply, vec![Value::Str("the reply".to_owned())]);
    }

    #[test]
    fn a_message_over_the_size_limit_before_the_reply_is_skipped() {
        let reply = reply_behind(|stream, serial| {
            let mut message = encode_message(
                MSG_METHOD_RETURN,
                0,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial)),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                    (FIELD_SIGNATURE, Value::Signature("ay".to_owned())),
                ],
                &[],
            )
            .unwrap();
            let body_len = MAX_INCOMING as u32;
            message[4..8].copy_from_slice(&body_len.to_le_bytes());
            message.resize(message.len() + MAX_INCOMING, 0);
            (&*stream).write_all(&message).unwrap();
        });
        assert_eq!(reply, vec![Value::Str("the reply".to_owned())]);
    }

    #[test]
    fn a_header_field_the_decoder_does_not_support_before_the_reply_is_skipped() {
        let reply = reply_behind(|stream, serial| {
            let dict = Value::Dict(vec![("k".to_owned(), Value::Str("v".to_owned()))]);
            let mut message = encode_message(
                MSG_METHOD_RETURN,
                0,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial)),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                    (200, dict),
                ],
                &[],
            )
            .unwrap();
            let at = message
                .windows(6)
                .position(|w| w == b"a{ss}\0")
                .expect("the dict's signature");
            message[at + 2] = b'u';
            assert!(matches!(
                decode_message(&message),
                Err(WireError::Unsupported(_))
            ));
            (&*stream).write_all(&message).unwrap();
        });
        assert_eq!(reply, vec![Value::Str("the reply".to_owned())]);
    }

    #[test]
    fn a_message_with_more_descriptors_than_taken_before_the_reply_is_skipped() {
        // Eight: the control buffer's alignment slack holds up to six
        // (rustix 1.1.5's `cmsg_space!` adds the alignment of `cmsghdr`).
        const SENT: usize = 8;
        let reply = reply_behind(|stream, serial| {
            let mut fields = vec![(FIELD_UNIX_FDS, Value::Uint32(SENT as u32))];
            fields.extend(signal_fields(serial));
            let body = encode("s", &[Value::Str("ignore me".to_owned())]).unwrap();
            let message = encode_message(4, 0, 2, &fields, &body).unwrap();
            let fds = [stream.as_fd(); SENT];
            server_send_fds(stream, &message, &fds);
        });
        assert_eq!(reply, vec![Value::Str("the reply".to_owned())]);
    }

    #[test]
    fn descriptors_of_a_message_right_behind_the_reply_are_not_the_replys() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.31");
            // Written before the call is read, so the client finds both
            // queued: the first call after `Hello` has serial 2.
            server_reply(&stream, 3, 2, ":1.5", "s", &[Value::Str("ok".to_owned())]);
            let mut fields = vec![(FIELD_UNIX_FDS, Value::Uint32(1))];
            fields.extend(signal_fields(2));
            let body = encode("s", &[Value::Str("ignore me".to_owned())]).unwrap();
            let message = encode_message(4, 0, 4, &fields, &body).unwrap();
            server_send_fds(&stream, &message, &[stream.as_fd()]);
            let call = server_call(&stream);
            assert_eq!(call.serial, 2);
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("ok".to_owned())]);
        server.join().unwrap();
        drop(session);
    }

    fn signal_fields(reply_serial: u32) -> Vec<(u8, Value)> {
        vec![
            (FIELD_PATH, Value::ObjectPath("/org/a".to_owned())),
            (FIELD_INTERFACE, Value::Str("org.a".to_owned())),
            (FIELD_MEMBER, Value::Str("Changed".to_owned())),
            (FIELD_SENDER, Value::Str(":1.5".to_owned())),
            (FIELD_SIGNATURE, Value::Signature("s".to_owned())),
            (FIELD_REPLY_SERIAL, Value::Uint32(reply_serial)),
        ]
    }

    #[test]
    fn a_return_the_bus_sends_for_a_peer_is_not_taken_for_a_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_awaiting(&stream, "Ask", ":1.77");
            // The bus may answer for a peer, but only with an error. A
            // `METHOD_RETURN` under its name is not a reply from the
            // owner, and taking it would let the bus — or anything that
            // could ever be mistaken for it — choose the value.
            server_reply(
                &stream,
                2,
                call.serial,
                BUS_NAME,
                "s",
                &[Value::Str("from the bus".to_owned())],
            );
            server_reply(
                &stream,
                3,
                call.serial,
                ":1.77",
                "s",
                &[Value::Str("from the owner".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(A_NAME, "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("from the owner".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn an_owner_that_answers_that_nobody_is_there_is_forgotten() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_MEMBER), "GetNameOwner");
            server_reply(
                &stream,
                2,
                call.serial,
                BUS_NAME,
                "s",
                &[Value::Str(":1.77".to_owned())],
            );
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_DESTINATION), ":1.77");
            server_error(&stream, call.serial, BUS_NAME, ERROR_NO_OWNER, "gone");
            // The second call looks the name up again instead of
            // addressing the connection that is no longer there.
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_MEMBER), "GetNameOwner");
            server_reply(
                &stream,
                3,
                call.serial,
                BUS_NAME,
                "s",
                &[Value::Str(":1.78".to_owned())],
            );
            let call = server_call(&stream);
            assert_eq!(call.text(FIELD_DESTINATION), ":1.78");
            server_reply(
                &stream,
                4,
                call.serial,
                ":1.78",
                "s",
                &[Value::Str("the restarted one".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(A_NAME, "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        assert!(
            matches!(&err, WireError::Remote { name, .. } if name == ERROR_NO_OWNER),
            "{err:?}"
        );
        assert!(session.owners.is_empty(), "{:?}", session.owners);
        let reply = session
            .call(A_NAME, "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("the restarted one".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    /// True (after printing why) when the run did not opt in to tests that
    /// talk to the developer's real session bus.
    fn session_tests_skipped() -> bool {
        if std::env::var_os("BUBBLER_TEST_SESSION").is_some_and(|v| v == "1") {
            return false;
        }
        println!(
            "skipping: set BUBBLER_TEST_SESSION=1 to run tests that reach the session or start audio daemons"
        );
        true
    }

    /// The session bus socket: `DBUS_SESSION_BUS_ADDRESS` when it names a
    /// `unix:path=` one, else `$XDG_RUNTIME_DIR/bus`, and only when what
    /// is there is a socket.
    fn session_bus_socket() -> Option<PathBuf> {
        let from_env = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").and_then(|address| {
            address.as_bytes().split(|b| *b == b';').find_map(|entry| {
                entry
                    .strip_prefix(b"unix:".as_slice())?
                    .split(|b| *b == b',')
                    .find_map(|pair| {
                        Some(PathBuf::from(OsStr::from_bytes(
                            pair.strip_prefix(b"path=".as_slice())?,
                        )))
                    })
            })
        });
        let path = match from_env {
            Some(path) => path,
            None => PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?).join("bus"),
        };
        std::fs::metadata(&path)
            .ok()
            .filter(|m| m.file_type().is_socket())
            .map(|_| path)
    }

    #[test]
    fn the_real_session_bus_answers_get_id() {
        if session_tests_skipped() {
            return;
        }
        let Some(path) = session_bus_socket() else {
            println!("skipping: no session bus socket to talk to");
            return;
        };
        let mut session = Session::connect(&path).unwrap();
        assert!(
            session.unique_name().starts_with(':'),
            "{:?}",
            session.unique_name()
        );
        let reply = session
            .call(BUS_NAME, BUS_PATH, BUS_INTERFACE, "GetId", "", &[], &[])
            .unwrap();
        let [Value::Str(id)] = reply.as_slice() else {
            panic!("GetId answered {reply:?}")
        };
        // "UUIDs": 16 bytes, printed as 32 hex digits.
        assert_eq!(id.len(), 32, "{id:?}");
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{id:?}");
    }

    /// The desktop portal: a well-known name a real session bus has to
    /// resolve, and one that is activatable where it exists at all.
    const PORTAL: &str = "org.freedesktop.portal.Desktop";

    #[test]
    fn the_real_session_bus_carries_a_call_to_a_name_it_resolved() {
        if session_tests_skipped() {
            return;
        }
        let Some(path) = session_bus_socket() else {
            println!("skipping: no session bus socket to talk to");
            return;
        };
        let mut session = Session::connect(&path).unwrap();
        match session.call(
            PORTAL,
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.DBus.Properties",
            "Get",
            "ss",
            &[
                Value::Str("org.freedesktop.portal.FileChooser".to_owned()),
                Value::Str("version".to_owned()),
            ],
            &[],
        ) {
            // `Get` answers with the property inside a variant, and this
            // one is a version number.
            Ok(reply) => {
                let [Value::Variant(version)] = reply.as_slice() else {
                    panic!("Get answered {reply:?}")
                };
                assert!(matches!(**version, Value::Uint32(_)), "{version:?}");
            }
            Err(WireError::Remote { name, .. })
                if name == ERROR_NO_OWNER || name == ERROR_SERVICE_UNKNOWN =>
            {
                println!("skipping: no portal on this bus and none to start ({name})");
                return;
            }
            // The portal is there and answered, just not with that
            // property; the owner path is what this test is about.
            Err(WireError::Remote { name, .. }) => println!("the portal answered {name}"),
            Err(other) => panic!("{other:?}"),
        }
        // The call went to the unique name the bus gave, not to the
        // well-known one the caller passed.
        let (_, owner) = session
            .owners
            .iter()
            .find(|(name, _)| name == PORTAL)
            .expect("the owner was resolved and kept");
        assert!(owner.starts_with(':'), "{owner:?}");
    }

    #[test]
    fn the_real_session_bus_refuses_a_method_that_is_not_there() {
        if session_tests_skipped() {
            return;
        }
        let Some(path) = session_bus_socket() else {
            println!("skipping: no session bus socket to talk to");
            return;
        };
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(
                BUS_NAME,
                BUS_PATH,
                BUS_INTERFACE,
                "NoSuchMethod",
                "",
                &[],
                &[],
            )
            .unwrap_err();
        assert!(
            matches!(&err, WireError::Remote { name, .. } if name.starts_with("org.freedesktop.DBus.Error.")),
            "{err:?}"
        );
    }
}
