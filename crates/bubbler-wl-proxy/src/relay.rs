//! The loop that carries messages between a sandboxed client and the
//! compositor, one message at a time.
//!
//! Everything is non-blocking and single-threaded. Both directions of every
//! connection have a queue of frames waiting to be written, and a direction is
//! polled for writability only while its queue holds something: with blocking
//! writes, a compositor and a client that both stop reading would wedge the
//! proxy between them, and the sandbox is exactly the side that may do so on
//! purpose.
//!
//! A message and the descriptors it carries travel together. The kernel
//! attaches ancillary data to the first byte of the batch it was sent with, so
//! by the time a message is complete its own descriptors have arrived; they
//! are taken from the queue in order, ride out with the message's first
//! written byte, and are closed with the message if the policy drops it.

use std::collections::VecDeque;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::time::Instant;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    accept_with, connect, recvmsg, sendmsg, socket_with,
};

use crate::audit::{Audit, Kind};
use crate::objects::ObjectError;
use crate::policy::{Action, Connection, Incoming, Policy};
use crate::wire::{self, Header, WireError};

/// Bytes to ask for when nothing is half-read. libwayland's own connection
/// buffer is this size, so a larger read rarely finds more.
const CHUNK: usize = 4096;

/// Descriptors one `recvmsg` may collect. Linux caps `SCM_RIGHTS` at 253 per
/// message, so the buffer can never be too small and the kernel never has to
/// truncate — a truncated control message would silently close a client's fd.
const MAX_FDS: usize = 253;

/// Descriptors one message may carry. The protocol's largest is two.
const MAX_MESSAGE_FDS: usize = 4;

/// Bytes one direction may have waiting before the proxy stops reading the
/// side that feeds it. A peer that does not read is not a reason to grow.
const MAX_QUEUE: usize = 4 << 20;

/// Bytes every connection of one sandbox may have waiting between them. The
/// per-direction cap bounds one connection; this bounds a client that opens
/// many, and the connection holding the most is the one that gives way.
const MAX_TOTAL_QUEUE: usize = 64 << 20;

/// Connections one proxy serves at a time. A toolkit opens one per process;
/// past this the listener is left alone and the kernel's backlog holds them.
const MAX_CONNECTIONS: usize = 256;

/// How long the loop waits before accepting again after running out of
/// descriptors. Retrying at once would spin against a table that is full.
const BACKOFF: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 100_000_000,
};

/// One message waiting to be written, with the descriptors it owns.
#[derive(Debug)]
struct Frame {
    data: Vec<u8>,
    off: usize,
    fds: Vec<OwnedFd>,
}

/// One end of a connection: what has been read from it and not yet parsed,
/// and what is waiting to be written to it.
#[derive(Debug)]
struct Side {
    fd: OwnedFd,
    buf: Vec<u8>,
    fds: VecDeque<OwnedFd>,
    out: VecDeque<Frame>,
    out_bytes: usize,
    eof: bool,
}

/// Which connection and which of its two sides one entry of the poll array
/// stands for, since an entry is only there when it has something to wait for.
#[derive(Debug, Clone, Copy)]
enum Slot {
    Listener,
    Client(usize),
    Server(usize),
}

/// Whether an error means the process is out of descriptors, in which case
/// asking again at once would only spin.
fn out_of_descriptors(err: Errno) -> bool {
    err == Errno::MFILE || err == Errno::NFILE
}

/// One client and the upstream connection opened for it.
#[derive(Debug)]
struct Conn {
    client: Side,
    server: Side,
    state: Connection,
    /// The client has been refused: nothing more is read, and the connection
    /// ends once the error has gone out.
    closing: bool,
    /// A descriptor failed; the connection ends without a word, because the
    /// peer going away is not a policy event.
    broken: bool,
}

/// The listener, the socket to forward to, and every live connection.
#[derive(Debug)]
struct Relay {
    listener: OwnedFd,
    upstream: PathBuf,
    policy: Policy,
    audit: Audit,
    conns: Vec<Conn>,
    /// Set when `accept` ran out of descriptors: the next round waits instead
    /// of asking again, and clears it.
    backoff: bool,
}

/// Serve `listener` — an inherited, listening, non-blocking Unix socket —
/// forwarding every connection to `upstream` under `policy`.
///
/// Returns only on an error that is the proxy's own; a client that
/// misbehaves loses its connection, not the whole sandbox's display.
pub fn run(listener: OwnedFd, upstream: PathBuf, policy: Policy, audit: Audit) -> io::Result<()> {
    let mut relay = Relay {
        listener,
        upstream,
        policy,
        audit,
        conns: Vec::new(),
        backoff: false,
    };
    loop {
        if let Err(err) = relay.step() {
            // The log is where the launcher looks, and it may be the only
            // place left: with `--log-fd 2` this process's own stderr is that
            // same descriptor, and it is closed as the relay unwinds.
            relay.audit.line(
                Kind::Close,
                Instant::now(),
                &format!("bubbler-wl-proxy: stopped: {err}"),
            );
            return Err(err);
        }
    }
}

impl Side {
    fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            buf: Vec::new(),
            fds: VecDeque::new(),
            out: VecDeque::new(),
            out_bytes: 0,
            eof: false,
        }
    }
}

/// How many bytes to read next: enough for a fresh batch, and never less than
/// the rest of a message that has already declared its size, so even a maximal
/// one can be completed.
fn want(buf: &[u8]) -> usize {
    match Header::decode(buf) {
        Ok(header) => usize::from(header.size)
            .saturating_sub(buf.len())
            .max(CHUNK),
        Err(_) => CHUNK,
    }
}

/// Write what the socket will take of `side`'s queue. Descriptors ride with
/// the first byte of their own frame, which is why they are cleared as soon as
/// any of it has gone out.
fn flush(side: &mut Side) -> io::Result<()> {
    while let Some(frame) = side.out.front_mut() {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_MESSAGE_FDS))];
        let mut cmsg = SendAncillaryBuffer::new(&mut space);
        let borrowed: Vec<BorrowedFd<'_>> = frame.fds.iter().map(OwnedFd::as_fd).collect();
        if !borrowed.is_empty() && !cmsg.push(SendAncillaryMessage::ScmRights(&borrowed)) {
            return Err(io::Error::other(
                "the message carries more descriptors than fit",
            ));
        }
        let iov = [IoSlice::new(&frame.data[frame.off..])];
        let sent = match sendmsg(&side.fd, &iov, &mut cmsg, SendFlags::NOSIGNAL) {
            // Nothing went out, so neither did the ancillary data: the frame
            // keeps its descriptors and is tried again on the next `POLLOUT`.
            Ok(0) => break,
            Ok(sent) => sent,
            Err(Errno::AGAIN) | Err(Errno::INTR) => break,
            Err(err) => return Err(err.into()),
        };
        frame.fds.clear();
        frame.off += sent;
        side.out_bytes -= sent;
        if frame.off >= frame.data.len() {
            side.out.pop_front();
        }
    }
    Ok(())
}

impl Conn {
    fn new(client: OwnedFd, server: OwnedFd) -> Self {
        Self {
            client: Side::new(client),
            server: Side::new(server),
            state: Connection::new(),
            closing: false,
            broken: false,
        }
    }

    /// What to poll one side for. Reading stops while the other side's queue
    /// is full, so a slow peer slows the sender instead of growing memory.
    fn flags(&self, client: bool) -> PollFlags {
        let (side, other) = match client {
            true => (&self.client, &self.server),
            false => (&self.server, &self.client),
        };
        let mut flags = PollFlags::empty();
        if !self.closing && !side.eof && other.out_bytes < MAX_QUEUE {
            flags |= PollFlags::IN;
        }
        if !side.out.is_empty() {
            flags |= PollFlags::OUT;
        }
        flags
    }

    /// Whether everything this connection still had to say has been said.
    ///
    /// The half-close arms are deliberate: a peer that has gone still leaves
    /// what it already sent to be delivered, so the connection lives until
    /// the queue aimed at the side that is *still there* is empty. It never
    /// waits on a queue aimed at the side that hung up — nobody is left to
    /// read that one — and it never waits on a peer that will not read, since
    /// that peer hanging up is itself what ends the connection.
    fn finished(&self) -> bool {
        self.broken
            // Refused: the client gets its `wl_display.error`, then nothing.
            || (self.closing && self.client.out.is_empty())
            // The client has gone: deliver what it already asked for.
            || (self.client.eof && self.server.out.is_empty())
            // The compositor has gone: deliver what it already said.
            || (self.server.eof && self.client.out.is_empty())
    }

    /// Bytes this connection has waiting in both directions.
    fn queued(&self) -> usize {
        self.client.out_bytes + self.server.out_bytes
    }

    /// One round of work for this connection. An error names a protocol fault
    /// the proxy will not forward past; the connection is closed either way.
    fn service(
        &mut self,
        client: PollFlags,
        server: PollFlags,
        policy: &mut Policy,
        audit: &mut Audit,
        now: Instant,
    ) -> Result<(), String> {
        // A side that has already ended keeps reporting `HUP` for as long as
        // the connection lives, so it is never read again: polling it once
        // more would be a spin, not a wake-up.
        let woke = PollFlags::IN | PollFlags::HUP | PollFlags::ERR;
        if client.intersects(woke) && !self.closing && !self.client.eof {
            self.pump(true, policy, audit, now)?;
        }
        if server.intersects(woke) && !self.closing && !self.server.eof {
            self.pump(false, policy, audit, now)?;
        }
        // Writing straight away costs one syscall and saves a poll round trip
        // on every message; a socket that is full simply says so.
        if !self.server.out.is_empty() && flush(&mut self.server).is_err() {
            self.broken = true;
        }
        if !self.client.out.is_empty() && flush(&mut self.client).is_err() {
            self.broken = true;
        }
        Ok(())
    }

    /// Read from one side, decode every whole message it has sent, and queue
    /// what the policy lets through on the other side.
    fn pump(
        &mut self,
        from_client: bool,
        policy: &mut Policy,
        audit: &mut Audit,
        now: Instant,
    ) -> Result<(), String> {
        let Self {
            client,
            server,
            state,
            closing,
            ..
        } = self;
        let (src, dst) = match from_client {
            true => (&mut *client, &mut *server),
            false => (&mut *server, &mut *client),
        };
        receive(src)?;
        let mut at = 0;
        while !*closing {
            let rest = &src.buf[at..];
            let header = match Header::decode(rest) {
                Ok(header) => header,
                Err(WireError::NeedMore) => break,
                Err(err) => return Err(err.to_string()),
            };
            if rest.len() < usize::from(header.size) {
                break;
            }
            let Some(interface) = state.objects.interface(header.object) else {
                return Err(ObjectError::Unmapped(header.object).to_string());
            };
            let Some(message) = interface.message(from_client, header.opcode) else {
                return Err(ObjectError::NoSuchMessage(interface.name, header.opcode).to_string());
            };
            let (mut args, consumed) =
                wire::decode(rest, message.args).map_err(|err| err.to_string())?;
            let owed = wire::fd_count(message.args);
            if src.fds.len() < owed {
                return Err(format!(
                    "a {}.{} arrived without its {owed} descriptors",
                    interface.name, message.name
                ));
            }
            let mut fds: Vec<OwnedFd> = src.fds.drain(..owed).collect();
            at += consumed;
            let mut incoming = Incoming {
                from_client,
                object: header.object,
                opcode: header.opcode,
                interface,
                message,
                args: &mut args,
                fds: &mut fds,
            };
            let action = policy
                .apply(&mut incoming, state, audit, now)
                .map_err(|err| err.to_string())?;
            match action {
                // Re-encoded rather than copied: what the far side reads is
                // then exactly what the proxy decoded and judged.
                Action::Forward => {
                    let data = wire::encode(header.object, header.opcode, &args)
                        .map_err(|err| err.to_string())?;
                    dst.out_bytes += data.len();
                    dst.out.push_back(Frame { data, off: 0, fds });
                }
                Action::Drop => {}
                Action::Refuse { error } => {
                    if !error.is_empty() {
                        src.out_bytes += error.len();
                        src.out.push_back(Frame {
                            data: error,
                            off: 0,
                            fds: Vec::new(),
                        });
                    }
                    *closing = true;
                }
            }
        }
        src.buf.drain(..at);
        Ok(())
    }
}

/// Take one batch of bytes and descriptors off `side`.
fn receive(side: &mut Side) -> Result<(), String> {
    let start = side.buf.len();
    side.buf.resize(start + want(&side.buf), 0);
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut cmsg = RecvAncillaryBuffer::new(&mut space);
    let received = {
        let mut iov = [IoSliceMut::new(&mut side.buf[start..])];
        recvmsg(&side.fd, &mut iov, &mut cmsg, RecvFlags::CMSG_CLOEXEC)
    };
    match received {
        Ok(msg) => {
            side.buf.truncate(start + msg.bytes);
            if msg.bytes == 0 {
                side.eof = true;
            }
            for message in cmsg.drain() {
                if let RecvAncillaryMessage::ScmRights(fds) = message {
                    side.fds.extend(fds);
                }
            }
            if msg.flags.contains(ReturnFlags::CTRUNC) {
                return Err("the peer sent more descriptors than one message may carry".into());
            }
            // No message owns more than two descriptors, so a queue this deep
            // is a peer sending descriptors nothing will ever claim. Left to
            // grow it would empty this process's table and take some other
            // connection down with a misleading reason.
            if side.fds.len() > MAX_FDS {
                return Err("the peer sent more descriptors than its messages can own".into());
            }
            Ok(())
        }
        Err(Errno::AGAIN) | Err(Errno::INTR) => {
            side.buf.truncate(start);
            Ok(())
        }
        // A peer that has gone is not a protocol fault; the connection ends
        // once whatever it already said has been delivered.
        Err(_) => {
            side.buf.truncate(start);
            side.eof = true;
            Ok(())
        }
    }
}

impl Relay {
    /// Wait for something to happen, then serve every connection that has.
    fn step(&mut self) -> io::Result<()> {
        let backing_off = self.backoff;
        let listening = self.conns.len() < MAX_CONNECTIONS && !backing_off;
        let mut slots = Vec::with_capacity(1 + self.conns.len() * 2);
        let mut polled = Vec::with_capacity(1 + self.conns.len() * 2);
        if listening {
            slots.push(Slot::Listener);
            polled.push(PollFd::from_borrowed_fd(
                self.listener.as_fd(),
                PollFlags::IN,
            ));
        }
        for (index, conn) in self.conns.iter().enumerate() {
            // A descriptor with nothing left to wait for is left out of the
            // array altogether. `POLLHUP` and `POLLERR` are reported whatever
            // the mask asks for, so a side that has hung up would wake `poll`
            // at once, every round, for as long as the other side still had
            // bytes queued — a loop at 100 % of a core, doing nothing.
            for (client, slot) in [(true, Slot::Client(index)), (false, Slot::Server(index))] {
                let flags = conn.flags(client);
                if flags.is_empty() {
                    continue;
                }
                let side = match client {
                    true => &conn.client,
                    false => &conn.server,
                };
                slots.push(slot);
                polled.push(PollFd::from_borrowed_fd(side.fd.as_fd(), flags));
            }
        }
        let timeout = backing_off.then_some(BACKOFF);
        // An empty array with no timeout would be a wait for nothing. It only
        // happens when every connection is already finished, and those are
        // reaped below, which is what puts the listener back in the array.
        if !polled.is_empty() || timeout.is_some() {
            match poll(&mut polled, timeout.as_ref()) {
                Ok(_) => {}
                Err(Errno::INTR) => return Ok(()),
                Err(err) => return Err(err.into()),
            }
        }
        self.backoff = false;

        let mut ready = vec![(PollFlags::empty(), PollFlags::empty()); self.conns.len()];
        let mut waiting = false;
        for (slot, fd) in slots.iter().zip(polled.iter()) {
            match slot {
                Slot::Listener => waiting = fd.revents().intersects(PollFlags::IN),
                Slot::Client(index) => ready[*index].0 = fd.revents(),
                Slot::Server(index) => ready[*index].1 = fd.revents(),
            }
        }
        drop(polled);

        let now = Instant::now();
        let Self {
            policy,
            audit,
            conns,
            ..
        } = self;
        let mut dead = Vec::new();
        for (index, conn) in conns.iter_mut().enumerate() {
            let (client, server) = ready[index];
            match conn.service(client, server, policy, audit, now) {
                Ok(()) if !conn.finished() => {}
                Ok(()) => dead.push(index),
                Err(why) => {
                    audit.line(
                        Kind::Close,
                        now,
                        &format!("bubbler-wl-proxy: connection closed: {why}"),
                    );
                    dead.push(index);
                }
            }
        }
        // One sandbox, many connections: the per-direction cap bounds each of
        // them, this bounds the lot. The connection holding the most is the
        // one that took the total over, and is the one that goes.
        let total: usize = conns.iter().map(Conn::queued).sum();
        if total > MAX_TOTAL_QUEUE {
            let fattest = conns
                .iter()
                .enumerate()
                .filter(|(index, _)| !dead.contains(index))
                .max_by_key(|(_, conn)| conn.queued())
                .map(|(index, _)| index);
            if let Some(index) = fattest {
                audit.line(
                    Kind::Close,
                    now,
                    &format!(
                        "bubbler-wl-proxy: connection closed: the sandbox has queued \
                         {total} bytes across its connections"
                    ),
                );
                dead.push(index);
            }
        }
        // Dropping a connection closes its sockets and everything still queued
        // on it, descriptors included.
        dead.sort_unstable();
        dead.dedup();
        for index in dead.into_iter().rev() {
            conns.remove(index);
        }
        if waiting {
            self.accept(now);
        }
        Ok(())
    }

    /// Take every connection the listener has waiting, opening one upstream
    /// connection for each.
    fn accept(&mut self, now: Instant) {
        while self.conns.len() < MAX_CONNECTIONS {
            let client =
                match accept_with(&self.listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                    Ok(client) => client,
                    Err(Errno::AGAIN) | Err(Errno::INTR) => return,
                    Err(err) if out_of_descriptors(err) => return self.wait_for_descriptors(now),
                    Err(err) => {
                        self.audit.line(
                            Kind::Close,
                            now,
                            &format!("bubbler-wl-proxy: connection closed: accept failed: {err}"),
                        );
                        return;
                    }
                };
            match self.dial() {
                Ok(server) => self.conns.push(Conn::new(client, server)),
                Err(err) if out_of_descriptors(err) => return self.wait_for_descriptors(now),
                Err(err) => self.audit.line(
                    Kind::Close,
                    now,
                    &format!("bubbler-wl-proxy: connection closed: no upstream socket: {err}"),
                ),
            }
        }
    }

    /// Out of descriptors: say so once and leave the listener out of the next
    /// round, so the loop waits rather than asking again immediately. The
    /// connections already open keep being served throughout, and one of them
    /// ending is what frees the descriptors this needs.
    fn wait_for_descriptors(&mut self, now: Instant) {
        self.backoff = true;
        self.audit.line(
            Kind::Close,
            now,
            "bubbler-wl-proxy: connection refused: out of descriptors",
        );
    }

    /// Open one connection to the socket the sandbox is really talking to.
    fn dial(&self) -> Result<OwnedFd, Errno> {
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        let address = SocketAddrUnix::new(&self.upstream)?;
        match connect(&socket, &address) {
            Ok(()) => Ok(socket),
            // A connection the kernel could not finish at once finishes on
            // the first write, which is queued like any other.
            Err(Errno::INPROGRESS) | Err(Errno::AGAIN) => Ok(socket),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;
    use std::time::Duration;

    use rustix::net::socketpair;

    use super::*;
    use crate::policy::Gate;
    use crate::tables;
    use crate::wire::Arg;

    /// A log the test can read back.
    #[derive(Clone, Default)]
    struct Buf(Rc<RefCell<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).expect("the log is UTF-8")
        }
    }

    /// A connection with the proxy in the middle: the two ends the test keeps
    /// are the client's and the compositor's.
    struct Wired {
        client: OwnedFd,
        server: OwnedFd,
        conn: Conn,
        policy: Policy,
        audit: Audit,
        log: Buf,
    }

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("a socket pair")
    }

    fn wired(gate: Gate) -> Wired {
        let (client, to_client) = pair();
        let (to_server, server) = pair();
        let log = Buf::default();
        Wired {
            client,
            server,
            conn: Conn::new(to_client, to_server),
            policy: Policy::new(gate, false),
            audit: Audit::new(Box::new(log.clone())),
            log,
        }
    }

    impl Wired {
        /// One round of the loop, as if both sides had woken it.
        fn step(&mut self) -> Result<(), String> {
            let both = PollFlags::IN | PollFlags::OUT;
            self.conn.service(
                both,
                both,
                &mut self.policy,
                &mut self.audit,
                Instant::now(),
            )
        }

        /// Read from the compositor's end, collecting any descriptors that
        /// came with the bytes.
        fn recv_server(&mut self) -> (Vec<u8>, Vec<OwnedFd>) {
            let mut buf = [0u8; 512];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
            let mut cmsg = RecvAncillaryBuffer::new(&mut space);
            let received = {
                let mut iov = [IoSliceMut::new(&mut buf)];
                recvmsg(&self.server, &mut iov, &mut cmsg, RecvFlags::CMSG_CLOEXEC)
            };
            let bytes = match received {
                Ok(msg) => msg.bytes,
                Err(Errno::AGAIN) => 0,
                Err(err) => panic!("{err}"),
            };
            let mut fds = Vec::new();
            for message in cmsg.drain() {
                if let RecvAncillaryMessage::ScmRights(carried) = message {
                    fds.extend(carried);
                }
            }
            (buf[..bytes].to_vec(), fds)
        }

        fn read_server(&mut self) -> Vec<u8> {
            let mut buf = [0u8; 512];
            match rustix::io::read(&self.server, &mut buf[..]) {
                Ok(n) => buf[..n].to_vec(),
                Err(Errno::AGAIN) => Vec::new(),
                Err(err) => panic!("{err}"),
            }
        }
    }

    fn opcode(interface: &str, from_client: bool, name: &str) -> u16 {
        let iface = tables::lookup(interface).unwrap_or_else(|| panic!("{interface}"));
        let list = match from_client {
            true => iface.requests,
            false => iface.events,
        };
        let at = list
            .iter()
            .position(|m| m.name == name)
            .unwrap_or_else(|| panic!("{interface}.{name}"));
        u16::try_from(at).expect("an opcode fits")
    }

    #[test]
    fn a_hung_up_upstream_with_a_client_that_never_reads_does_not_spin() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let listen = dir.path().join("listen");
        let upstream = dir.path().join("upstream");
        let listener = std::os::unix::net::UnixListener::bind(&listen).expect("a listener");
        listener.set_nonblocking(true).expect("non-blocking");
        let compositor = std::os::unix::net::UnixListener::bind(&upstream).expect("an upstream");

        // A compositor that says a great deal and then hangs up. One mebibyte
        // is under the queue cap, so all of it is read: what the client's own
        // socket cannot hold stays queued in the proxy, which is the state
        // that used to spin.
        let flood = std::thread::spawn(move || {
            let (mut stream, _) = compositor.accept().expect("the proxy dials");
            let delete_id = opcode("wl_display", false, "delete_id");
            let one = wire::encode(1, delete_id, &[Arg::Uint(0xFF00_0001)]).expect("encodes");
            let mut batch = Vec::new();
            while batch.len() < 60 * 1024 {
                batch.extend_from_slice(&one);
            }
            let mut sent = 0;
            while sent < 1 << 20 {
                if stream.write_all(&batch).is_err() {
                    break;
                }
                sent += batch.len();
            }
        });

        let client = UnixStream::connect(&listen).expect("the proxy is listening");
        let tid = rustix::thread::gettid().as_raw_nonzero().get();
        let watcher = std::thread::spawn(move || {
            // Per thread, not per process: `cargo test` runs the rest of the
            // suite in threads beside this one.
            let cpu = |tid: i32| -> f64 {
                let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat"))
                    .expect("the relay thread's stat");
                let tail = stat.rsplit_once(')').expect("a stat line").1;
                let fields: Vec<&str> = tail.split_whitespace().collect();
                let ticks: u64 = fields[11].parse::<u64>().expect("utime")
                    + fields[12].parse::<u64>().expect("stime");
                ticks as f64 / 100.0
            };
            // Let the flood be read and the queue jam, then watch a whole
            // second of a loop that should be asleep in `poll`.
            std::thread::sleep(Duration::from_millis(1200));
            let before = cpu(tid);
            std::thread::sleep(Duration::from_millis(1000));
            let burned = cpu(tid) - before;
            // Dropping the client is what ends the connection: the queue
            // aimed at it can never be delivered.
            drop(client);
            burned
        });

        let mut relay = Relay {
            listener: OwnedFd::from(listener),
            upstream,
            policy: Policy::new(Gate::Paste, false),
            audit: Audit::new(Box::new(std::io::sink())),
            conns: Vec::new(),
            backoff: false,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut served = false;
        while Instant::now() < deadline {
            relay.step().expect("the relay keeps going");
            served |= !relay.conns.is_empty();
            if served && relay.conns.is_empty() {
                break;
            }
        }
        assert!(served, "the proxy never accepted the client");
        assert!(
            relay.conns.is_empty(),
            "the connection outlived both of its peers"
        );
        let burned = watcher.join().expect("the watcher");
        flood.join().expect("the compositor");
        println!("{burned:.2} CPU-seconds over one second of waiting");
        assert!(
            burned < 0.20,
            "the loop burned {burned:.2} CPU-seconds in one second of waiting"
        );
    }

    #[test]
    fn a_flood_of_descriptors_nothing_will_claim_ends_the_connection() {
        let mut wired = wired(Gate::Paste);
        let (read, write) = rustix::pipe::pipe().expect("a pipe");
        let sync = opcode("wl_display", true, "sync");
        // Two batches, each of descriptors riding on a request that owns none.
        // The queue only grows, and the second batch takes it past the cap.
        for (round, id) in [(0u32, 2u32), (1, 3)] {
            let message = wire::encode(1, sync, &[Arg::NewId(id)]).expect("encodes");
            let carried = [write.as_fd(); 130];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(130))];
            let mut cmsg = SendAncillaryBuffer::new(&mut space);
            assert!(cmsg.push(SendAncillaryMessage::ScmRights(&carried)));
            sendmsg(
                &wired.client,
                &[IoSlice::new(&message)],
                &mut cmsg,
                SendFlags::NOSIGNAL,
            )
            .expect("the client sends a batch");
            let outcome = wired.step();
            match round {
                0 => assert_eq!(outcome, Ok(()), "130 descriptors is under the cap"),
                _ => assert_eq!(
                    outcome,
                    Err("the peer sent more descriptors than its messages can own".to_owned())
                ),
            }
        }
        drop((read, write));
    }

    #[test]
    fn an_empty_descriptor_table_is_waited_out_not_spun_on() {
        assert!(out_of_descriptors(Errno::MFILE));
        assert!(out_of_descriptors(Errno::NFILE));
        assert!(!out_of_descriptors(Errno::CONNABORTED));
        assert!(!out_of_descriptors(Errno::AGAIN));

        let dir = tempfile::tempdir().expect("a temporary directory");
        let listener =
            std::os::unix::net::UnixListener::bind(dir.path().join("listen")).expect("a listener");
        listener.set_nonblocking(true).expect("non-blocking");
        let mut relay = Relay {
            listener: OwnedFd::from(listener),
            upstream: dir.path().join("upstream"),
            policy: Policy::new(Gate::Paste, false),
            audit: Audit::new(Box::new(std::io::sink())),
            conns: Vec::new(),
            backoff: false,
        };
        relay.wait_for_descriptors(Instant::now());
        assert!(relay.backoff);
        // The round that honours it waits on its timeout with the listener
        // out of the array, and clears the flag as it goes.
        let waited = Instant::now();
        relay.step().expect("the loop keeps going");
        assert!(!relay.backoff);
        assert!(
            waited.elapsed() >= Duration::from_millis(50),
            "the loop did not wait at all"
        );
    }

    #[test]
    fn a_read_asks_for_the_rest_of_a_message_that_named_its_size() {
        assert_eq!(want(&[]), CHUNK);
        let long = Header {
            object: 1,
            opcode: 0,
            size: 60_000,
        }
        .encode();
        assert_eq!(want(&long), 60_000 - HEADER_LEN);
        let short = Header {
            object: 1,
            opcode: 0,
            size: 12,
        }
        .encode();
        assert_eq!(want(&short), CHUNK);
    }

    /// The header is eight bytes; spelled out here so the test above reads.
    const HEADER_LEN: usize = 8;

    #[test]
    fn a_request_is_re_encoded_and_forwarded() {
        let mut wired = wired(Gate::Paste);
        let get_registry = opcode("wl_display", true, "get_registry");
        let message = wire::encode(1, get_registry, &[Arg::NewId(2)]).expect("encodes");
        rustix::io::write(&wired.client, &message).expect("the client writes");
        wired.step().expect("a get_registry is forwarded");
        assert_eq!(wired.read_server(), message);
        assert_eq!(
            wired.conn.state.objects.interface(2).map(|i| i.name),
            Some("wl_registry")
        );
    }

    #[test]
    fn a_message_split_across_two_writes_waits_for_the_rest() {
        let mut wired = wired(Gate::Paste);
        let sync = opcode("wl_display", true, "sync");
        let message = wire::encode(1, sync, &[Arg::NewId(2)]).expect("encodes");
        rustix::io::write(&wired.client, &message[..5]).expect("the client writes");
        wired.step().expect("half a message is not a fault");
        assert!(wired.read_server().is_empty());
        rustix::io::write(&wired.client, &message[5..]).expect("the client writes");
        wired.step().expect("the whole message is forwarded");
        assert_eq!(wired.read_server(), message);
    }

    #[test]
    fn a_message_for_an_object_that_is_not_mapped_ends_the_connection() {
        let mut wired = wired(Gate::Paste);
        let sync = opcode("wl_display", true, "sync");
        let message = wire::encode(77, sync, &[Arg::NewId(2)]).expect("encodes");
        rustix::io::write(&wired.client, &message).expect("the client writes");
        let why = wired.step().expect_err("object 77 is not mapped");
        assert_eq!(why, "object 77 is not mapped");
        assert!(wired.read_server().is_empty());
    }

    #[test]
    fn a_denied_clipboard_read_never_reaches_the_compositor_and_closes_its_fd() {
        let mut wired = wired(Gate::Paste);
        let offer = 10;
        let index = tables::index_of("wl_data_offer").expect("wl_data_offer");
        wired
            .conn
            .state
            .objects
            .bind(u32::MAX, index, 3, offer)
            .expect("the offer maps");
        let (read, write) = rustix::pipe::pipe().expect("a pipe");
        let receive = opcode("wl_data_offer", true, "receive");
        let mime = std::ffi::CString::new("text/plain").expect("no NUL");
        let message =
            wire::encode(offer, receive, &[Arg::String(Some(mime)), Arg::Fd]).expect("encodes");

        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut cmsg = SendAncillaryBuffer::new(&mut space);
        let carried = [write.as_fd()];
        assert!(cmsg.push(SendAncillaryMessage::ScmRights(&carried)));
        sendmsg(
            &wired.client,
            &[IoSlice::new(&message)],
            &mut cmsg,
            SendFlags::NOSIGNAL,
        )
        .expect("the client sends the write end");
        drop(write);

        wired.step().expect("a denied read is not a fault");
        assert!(wired.read_server().is_empty());
        let mut buf = [0u8; 8];
        assert_eq!(
            std::fs::File::from(read)
                .read(&mut buf)
                .expect("the read end is open"),
            0,
            "the write end outlived the dropped message"
        );
        assert!(
            wired.log.text().contains("clipboard read denied"),
            "{}",
            wired.log.text()
        );
    }

    #[test]
    fn an_open_gate_forwards_the_read_and_the_descriptor_with_it() {
        let mut wired = wired(Gate::Open);
        let offer = 10;
        let index = tables::index_of("wl_data_offer").expect("wl_data_offer");
        wired
            .conn
            .state
            .objects
            .bind(u32::MAX, index, 3, offer)
            .expect("the offer maps");
        let (read, write) = rustix::pipe::pipe().expect("a pipe");
        let receive = opcode("wl_data_offer", true, "receive");
        let mime = std::ffi::CString::new("text/plain").expect("no NUL");
        let message =
            wire::encode(offer, receive, &[Arg::String(Some(mime)), Arg::Fd]).expect("encodes");

        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut cmsg = SendAncillaryBuffer::new(&mut space);
        let carried = [write.as_fd()];
        assert!(cmsg.push(SendAncillaryMessage::ScmRights(&carried)));
        sendmsg(
            &wired.client,
            &[IoSlice::new(&message)],
            &mut cmsg,
            SendFlags::NOSIGNAL,
        )
        .expect("the client sends the write end");
        drop(write);

        wired.step().expect("an open gate forwards");
        let (bytes, mut carried) = wired.recv_server();
        assert_eq!(bytes, message);
        assert_eq!(carried.len(), 1, "the descriptor did not ride along");
        // The very descriptor the client sent: what is written to the end the
        // compositor received comes out of the end the client kept.
        let sent = carried.pop().expect("one descriptor");
        rustix::io::write(&sent, b"pasted").expect("the compositor writes");
        drop(sent);
        let mut buf = [0u8; 16];
        let mut reader = std::fs::File::from(read);
        let n = reader.read(&mut buf).expect("the read end is open");
        assert_eq!(&buf[..n], b"pasted");
    }

    #[test]
    fn a_refused_bind_answers_the_client_and_stops_reading() {
        let mut wired = wired(Gate::Paste);
        let index = tables::index_of("wl_registry").expect("wl_registry");
        wired
            .conn
            .state
            .objects
            .bind(u32::MAX, index, 1, 2)
            .expect("the registry maps");
        let bind = opcode("wl_registry", true, "bind");
        let iface = std::ffi::CString::new("wl_compositor").expect("no NUL");
        let message = wire::encode(
            2,
            bind,
            &[
                Arg::Uint(9),
                Arg::String(Some(iface)),
                Arg::Uint(1),
                Arg::NewId(3),
            ],
        )
        .expect("encodes");
        rustix::io::write(&wired.client, &message).expect("the client writes");
        wired.step().expect("a refusal is not a relay fault");
        assert!(wired.conn.closing);
        assert!(wired.read_server().is_empty());
        let mut buf = [0u8; 256];
        let n = rustix::io::read(&wired.client, &mut buf[..]).expect("the client is answered");
        let sig = &[
            tables::ArgKind::Object,
            tables::ArgKind::Uint,
            tables::ArgKind::String,
        ];
        let (args, _) = wire::decode(&buf[..n], sig).expect("the error decodes");
        assert_eq!(args[0], Arg::Object(2));
        assert_eq!(args[1], Arg::Uint(0));
        assert!(matches!(&args[2], Arg::String(Some(text))
            if text.to_string_lossy().contains("refused by the sandbox proxy")));
        assert!(wired.conn.finished(), "the connection ends once flushed");
    }
}
